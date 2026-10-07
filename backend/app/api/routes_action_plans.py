import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_, and_, literal, case, text
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, require_analyst_or_admin, check_user_group_access, get_user_allowed_group_ids

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/action-plans", tags=["Gerenciador de Planos de Ação"])

def utc_now():
    return datetime.now(timezone.utc)

def format_task_out(t: models.ActionTask, now_utc: datetime) -> schemas.ActionTaskOut:
    out = schemas.ActionTaskOut.model_validate(t)
    out.assigned_user_name = (t.assigned_user.full_name or t.assigned_user.username) if t.assigned_user else None
    
    # Overdue check: past due date and not completed/done
    is_od = False
    if t.due_date and t.status != "DONE":
        due = t.due_date.replace(tzinfo=timezone.utc) if t.due_date.tzinfo is None else t.due_date
        is_od = due < now_utc
    out.is_overdue = is_od

    links_out = []
    for link in t.vulnerability_links:
        v = link.vulnerability
        links_out.append(schemas.ActionTaskVulnerabilityOut(
            id=link.id,
            action_task_id=link.action_task_id,
            vulnerability_id=link.vulnerability_id,
            plugin_id=v.plugin_id if v else None,
            plugin_name=v.plugin_name if v else None,
            severity=v.severity if v else None,
            cve=v.cve if v else None,
            host_ip=v.host.ip_address if (v and v.host) else None,
            host_name=v.host.hostname if (v and v.host) else None
        ))
    out.vulnerability_links = links_out
    out.vulnerabilities_count = len(links_out)
    return out

def format_plan_out(p: models.ActionPlan, now_utc: datetime) -> schemas.ActionPlanOut:
    out = schemas.ActionPlanOut.model_validate(p)
    
    # Resolve asset group name and complete hierarchy path
    group = p.asset_group
    if not group and p.target_host and p.target_host.asset_group:
        group = p.target_host.asset_group

    if group:
        from app.services.asset_group_service import compute_group_hierarchy_info
        level, hierarchy_path = compute_group_hierarchy_info(group)
        out.asset_group_name = hierarchy_path
        if not out.asset_group_id:
            out.asset_group_id = group.id
    else:
        out.asset_group_name = None

    out.target_host_ip = p.target_host.ip_address if p.target_host else None
    out.target_host_name = p.target_host.hostname if p.target_host else None
    out.owner_user_name = (p.owner_user.full_name or p.owner_user.username) if p.owner_user else None

    # Multi-tagging
    out.tags = [link.tag.name for link in (p.tag_links or []) if link.tag]

    # Matrix scope
    out.scope_host_ips = [h.host_ip for h in (p.scope_hosts or [])]
    out.scope_plugin_ids = [pl.plugin_id for pl in (p.scope_plugins or [])]

    # Tasks stats and formatting
    tasks = p.tasks or []
    out.total_tasks = len(tasks)
    out.completed_tasks = sum(1 for t in tasks if t.status == "DONE")
    out.progress_percent = round((out.completed_tasks / out.total_tasks) * 100.0, 1) if out.total_tasks > 0 else 0.0

    # Overdue check
    is_od = False
    if p.due_date and p.status not in ["COMPLETED", "CANCELLED"]:
        due = p.due_date.replace(tzinfo=timezone.utc) if p.due_date.tzinfo is None else p.due_date
        is_od = due < now_utc
    out.is_overdue = is_od

    out.tasks = [format_task_out(t, now_utc) for t in tasks]
    return out


def sync_action_plan_tags(db: Session, plan: models.ActionPlan, tag_names: Optional[List[str]]):
    """
    Sincroniza tags associadas ao plano de ação.
    """
    if tag_names is None:
        return
    db.query(models.ActionPlanTagLink).filter(models.ActionPlanTagLink.action_plan_id == plan.id).delete()
    db.flush()

    seen = set()
    for raw in tag_names:
        clean = raw.strip()
        if not clean:
            continue
        clean_key = clean.lower()
        if clean_key in seen:
            continue
        seen.add(clean_key)

        tag = db.query(models.Tag).filter(models.Tag.name.ilike(clean)).first()
        if not tag:
            tag = models.Tag(name=clean, color_hex="#6366f1")
            db.add(tag)
            db.flush()

        link = models.ActionPlanTagLink(action_plan_id=plan.id, tag_id=tag.id)
        db.add(link)


def sync_action_plan_matrix_scope(
    db: Session,
    plan: models.ActionPlan,
    scope_host_ips: Optional[List[str]],
    scope_plugin_ids: Optional[List[str]]
):
    """
    Sincroniza escopo matricial N:N de múltiplos hosts e plugins.
    """
    if scope_host_ips is not None:
        db.query(models.ActionPlanHost).filter(models.ActionPlanHost.action_plan_id == plan.id).delete()
        seen_ips = set()
        for raw_ip in scope_host_ips:
            ip = raw_ip.strip()
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                h = db.query(models.Host).filter(models.Host.ip_address == ip).order_by(models.Host.id.desc()).first()
                db.add(models.ActionPlanHost(
                    action_plan_id=plan.id,
                    host_id=h.id if h else None,
                    host_ip=ip
                ))

    if scope_plugin_ids is not None:
        db.query(models.ActionPlanPlugin).filter(models.ActionPlanPlugin.action_plan_id == plan.id).delete()
        seen_plugins = set()
        for raw_pid in scope_plugin_ids:
            pid = str(raw_pid).strip()
            if pid and pid not in seen_plugins:
                seen_plugins.add(pid)
                db.add(models.ActionPlanPlugin(
                    action_plan_id=plan.id,
                    plugin_id=pid
                ))


def link_vulns_to_task_with_precedence(
    db: Session,
    task: models.ActionTask,
    vuln_ids: List[int],
    current_username: str,
    is_host_scope: bool = False
):
    """
    Associa vulnerabilidades a uma tarefa de plano de ação, respeitando a regra de
    exclusividade e precedência ISO 27001 (1 ocorrência = 1 plano ativo).
    Planos específicos de Host têm precedência sobre planos genéricos por vulnerabilidade/plugin.
    """
    now = utc_now()
    plan = task.action_plan
    if not vuln_ids:
        return

    vulns = db.query(models.Vulnerability).filter(models.Vulnerability.id.in_(vuln_ids)).all()
    for v in vulns:
        # Vulnerabilidades Remediadas ou com Risco Aceito não são elegíveis para associação a planos de ação
        if v.treatment_status in ["Remediated", "remediated", "Accepted_Risk", "accepted_risk"]:
            continue

        # Verificar vínculos existentes em planos ativos diferentes
        existing_links = db.query(models.ActionTaskVulnerabilityLink).join(
            models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
        ).join(
            models.ActionPlan, models.ActionTask.action_plan_id == models.ActionPlan.id
        ).filter(
            models.ActionTaskVulnerabilityLink.vulnerability_id == v.id,
            models.ActionPlan.id != plan.id,
            models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
        ).all()

        if existing_links:
            if is_host_scope or plan.scope_type in ["HOST", "MATRIX_NN"]:
                for old_link in existing_links:
                    old_task = old_link.task
                    old_p = old_task.action_plan if old_task else None
                    db.delete(old_link)
                    hist_disassoc = models.VulnerabilityTreatmentHistory(
                        vulnerability_id=v.id,
                        treatment_status="In_Action_Plan",
                        treatment_notes=f"Reatribuído do Plano #{old_p.id if old_p else '?'} ({old_p.title if old_p else ''}) para o Plano de Host #{plan.id} ({plan.title}) conforme regra de precedência ISO 27001.",
                        changed_by_username=current_username,
                        changed_at=now
                    )
                    db.add(hist_disassoc)
            else:
                continue

        # Verificar se já está vinculado nesta mesma tarefa (no banco ou na sessão ativa)
        already_in_task = any(
            link.vulnerability_id == v.id for link in (task.vulnerability_links or [])
        ) or db.query(models.ActionTaskVulnerabilityLink).filter(
            models.ActionTaskVulnerabilityLink.action_task_id == task.id,
            models.ActionTaskVulnerabilityLink.vulnerability_id == v.id
        ).first()
        if not already_in_task:
            new_link = models.ActionTaskVulnerabilityLink(
                action_task_id=task.id,
                vulnerability_id=v.id
            )
            db.add(new_link)
            db.flush()

        # Transicionar para In_Action_Plan se ainda estiver em Open
        if v.treatment_status == "Open":
            v.treatment_status = "In_Action_Plan"
            v.treated_by_username = current_username
            v.treated_at = now
            v.treatment_notes = f"Associada ao Plano de Ação #{plan.id} ({plan.title}) - Status: Em Plano de Ação."
            hist_assoc = models.VulnerabilityTreatmentHistory(
                vulnerability_id=v.id,
                treatment_status="In_Action_Plan",
                treatment_notes=f"Associada ao Plano de Ação #{plan.id} ({plan.title}) - Status: Em Plano de Ação.",
                changed_by_username=current_username,
                changed_at=now
            )
            db.add(hist_assoc)


def revert_orphaned_vulns_to_open(
    db: Session,
    vuln_ids: List[int],
    current_username: str,
    reason: Optional[str] = None
):
    """
    Se vulnerabilidades com 'In_Action_Plan' ou 'In_Remediation' não possuem mais nenhum vínculo com planos ativos,
    reverte automaticamente para 'Open' com registro de auditoria.
    """
    now = utc_now()
    actual_reason = reason or "Retornado para status inicial (Open) devido à desvinculação ou cancelamento de Plano de Ação."
    unique_ids = list(set(vuln_ids))

    for vid in unique_ids:
        v = db.query(models.Vulnerability).filter(models.Vulnerability.id == vid).first()
        if not v or v.treatment_status not in ["In_Action_Plan", "In_Remediation"]:
            continue

        active_link = db.query(models.ActionTaskVulnerabilityLink).join(
            models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
        ).join(
            models.ActionPlan, models.ActionTask.action_plan_id == models.ActionPlan.id
        ).filter(
            models.ActionTaskVulnerabilityLink.vulnerability_id == vid,
            models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
        ).first()

        if not active_link:
            v.treatment_status = "Open"
            v.treated_by_username = current_username
            v.treated_at = now
            v.treatment_notes = actual_reason
            hist = models.VulnerabilityTreatmentHistory(
                vulnerability_id=v.id,
                treatment_status="Open",
                treatment_notes=actual_reason,
                changed_by_username=current_username,
                changed_at=now
            )
            db.add(hist)


def format_host_task_title(host: Optional[models.Host], fallback_ip: Optional[str] = None) -> str:
    """
    Formata o nome da tarefa baseado em host: hostname/ip.
    Se possuir hostname e IP distintos: "hostname (ip)" ou "hostname" se não tiver IP.
    Se não possuir hostname: "ip".
    """
    ip = (host.ip_address if host else fallback_ip or "").strip()
    hostname = (host.hostname if host else "").strip() if host and host.hostname else ""
    if hostname and ip and hostname.lower() != ip.lower():
        return f"{hostname} ({ip})"
    return hostname or ip or "Host"


def generate_action_plan_tasks(
    db: Session,
    plan: models.ActionPlan,
    matching_vulns: List[models.Vulnerability],
    current_username: str,
    scope_plugin_ids_explicit: bool = False
) -> List[models.ActionTask]:
    """
    Cria automaticamente as tarefas estruturadas do Plano de Ação:
    - Escopo baseado em Host (HOST ou MATRIX_NN sem lista específica de plugins):
      Cria UMA tarefa para cada host contendo as vulnerabilidades daquele host.
      Nome da tarefa: hostname/ip
      Abaixo (descrição): nome da(s) vulnerabilidade(s).
    - Escopo MATRIX_NN (com plugins específicos) ou VULNERABILITY:
      Cria UMA tarefa para cada grupo (HOST + VULNERABILIDADE).
      Nome da tarefa: hostname/ip
      Abaixo (descrição): nome da vulnerabilidade (plugin_name).
    """
    if not matching_vulns:
        return []

    is_host_scope = plan.scope_type in ["HOST", "MATRIX_NN"]
    created_tasks = []

    # Determinar se o plano é estritamente baseado em Host:
    # 1. scope_type == "HOST"
    # 2. scope_type == "MATRIX_NN" mas não foram informados plugins específicos (todas as vulnerabilidades dos hosts)
    is_host_based = (plan.scope_type == "HOST") or (plan.scope_type == "MATRIX_NN" and not scope_plugin_ids_explicit)

    if is_host_based:
        # Agrupar vulnerabilidades por IP de host mantendo a ordem dos hosts
        host_groups: Dict[str, List[models.Vulnerability]] = {}
        host_order = []
        for v in matching_vulns:
            hip = (v.host.ip_address if v.host else str(v.host_id)).strip()
            if hip not in host_groups:
                host_groups[hip] = []
                host_order.append(hip)
            host_groups[hip].append(v)

        for idx, hip in enumerate(host_order):
            vulns = host_groups[hip]
            host = vulns[0].host
            task_title = format_host_task_title(host, fallback_ip=hip)

            # Abaixo: o nome da vulnerabilidade (ou lista se múltiplas)
            unique_names = list(dict.fromkeys(v.plugin_name.strip() for v in vulns if v.plugin_name))
            if len(unique_names) == 1:
                task_desc = unique_names[0]
            elif len(unique_names) <= 15:
                task_desc = "\n".join(f"• {name}" for name in unique_names)
            else:
                first_15 = [f"• {name}" for name in unique_names[:15]]
                task_desc = "\n".join(first_15) + f"\n• ... e mais {len(unique_names) - 15} vulnerabilidades"

            task = models.ActionTask(
                action_plan_id=plan.id,
                title=task_title,
                description=task_desc,
                order_index=idx,
                status="TODO",
                assigned_user_id=plan.owner_user_id,
                due_date=plan.due_date
            )
            db.add(task)
            db.flush()

            v_ids = [v.id for v in vulns]
            link_vulns_to_task_with_precedence(db, task, v_ids, current_username, is_host_scope=True)
            created_tasks.append(task)

    else:
        # MATRIX_NN com plugins específicos ou VULNERABILITY (ou GROUP):
        # Uma tarefa para cada grupo HOST + VULNERABILIDADE
        pair_groups: Dict[Tuple[str, str], List[models.Vulnerability]] = {}
        pair_order = []
        for v in matching_vulns:
            hip = (v.host.ip_address if v.host else str(v.host_id)).strip()
            key = (hip, str(v.plugin_id).strip())
            if key not in pair_groups:
                pair_groups[key] = []
                pair_order.append(key)
            pair_groups[key].append(v)

        for idx, key in enumerate(pair_order):
            vulns = pair_groups[key]
            host = vulns[0].host
            vuln_sample = vulns[0]
            task_title = format_host_task_title(host, fallback_ip=key[0])
            task_desc = vuln_sample.plugin_name.strip() if vuln_sample.plugin_name else f"Plugin #{vuln_sample.plugin_id}"

            task = models.ActionTask(
                action_plan_id=plan.id,
                title=task_title,
                description=task_desc,
                order_index=idx,
                status="TODO",
                assigned_user_id=plan.owner_user_id,
                due_date=plan.due_date
            )
            db.add(task)
            db.flush()

            v_ids = [v.id for v in vulns]
            link_vulns_to_task_with_precedence(db, task, v_ids, current_username, is_host_scope=is_host_scope)
            created_tasks.append(task)

    return created_tasks


def sync_action_plan_tasks_on_scope_update(
    db: Session,
    plan: models.ActionPlan,
    matching_vulns: List[models.Vulnerability],
    current_username: str,
    scope_plugin_ids_explicit: bool = False
) -> List[models.ActionTask]:
    """
    Sincroniza as tarefas do Plano de Ação quando o escopo (hosts ou plugins) é alterado na edição:
    1. Mantém tarefas existentes que continuam no escopo (preservando status, assignee, etc.).
    2. Atualiza vínculos de vulnerabilidades das tarefas mantidas (remove itens desmarcados e vincula novos).
    3. Cria novas tarefas estruturadas para novos hosts ou novos pares (HOST+VULN) adicionados ao escopo.
    4. Remove tarefas obsoletas que deixaram de fazer parte do escopo, revertendo vulnerabilidades para 'Open' se órfãs.
    """
    if not matching_vulns:
        return plan.tasks or []

    is_host_scope = plan.scope_type in ["HOST", "MATRIX_NN"]
    is_host_based = (plan.scope_type == "HOST") or (plan.scope_type == "MATRIX_NN" and not scope_plugin_ids_explicit)

    existing_tasks = list(plan.tasks or [])

    if is_host_based:
        host_groups: Dict[str, List[models.Vulnerability]] = {}
        host_order: List[str] = []
        for v in matching_vulns:
            hip = (v.host.ip_address if v.host else str(v.host_id)).strip()
            if hip not in host_groups:
                host_groups[hip] = []
                host_order.append(hip)
            host_groups[hip].append(v)

        existing_by_host: Dict[str, models.ActionTask] = {}
        for t in existing_tasks:
            task_hip = None
            for link in (t.vulnerability_links or []):
                if link.vulnerability and link.vulnerability.host and link.vulnerability.host.ip_address:
                    task_hip = link.vulnerability.host.ip_address.strip()
                    break
            if not task_hip:
                for hip in host_order:
                    if hip in t.title:
                        task_hip = hip
                        break
            if task_hip and task_hip not in existing_by_host:
                existing_by_host[task_hip] = t

        retained_task_ids = set()

        for idx, hip in enumerate(host_order):
            vulns = host_groups[hip]
            host = vulns[0].host
            v_ids = [v.id for v in vulns]
            desired_v_ids = set(v_ids)

            unique_names = list(dict.fromkeys(v.plugin_name.strip() for v in vulns if v.plugin_name))
            if len(unique_names) == 1:
                task_desc = unique_names[0]
            elif len(unique_names) <= 15:
                task_desc = "\n".join(f"• {name}" for name in unique_names)
            else:
                first_15 = [f"• {name}" for name in unique_names[:15]]
                task_desc = "\n".join(first_15) + f"\n• ... e mais {len(unique_names) - 15} vulnerabilidades"

            if hip in existing_by_host:
                task = existing_by_host[hip]
                task.description = task_desc
                unlinked_vids = []
                for link in list(task.vulnerability_links or []):
                    if link.vulnerability_id not in desired_v_ids:
                        unlinked_vids.append(link.vulnerability_id)
                        db.delete(link)
                if unlinked_vids:
                    db.flush()
                    revert_orphaned_vulns_to_open(
                        db=db,
                        vuln_ids=unlinked_vids,
                        current_username=current_username,
                        reason=f"Desvinculada da etapa '{task.title}' após alteração de escopo do Plano #{plan.id}."
                    )
                link_vulns_to_task_with_precedence(db, task, v_ids, current_username, is_host_scope=True)
                retained_task_ids.add(task.id)
            else:
                task_title = format_host_task_title(host, fallback_ip=hip)
                new_task = models.ActionTask(
                    action_plan_id=plan.id,
                    title=task_title,
                    description=task_desc,
                    order_index=idx,
                    status="TODO",
                    assigned_user_id=plan.owner_user_id,
                    due_date=plan.due_date
                )
                db.add(new_task)
                db.flush()
                link_vulns_to_task_with_precedence(db, new_task, v_ids, current_username, is_host_scope=True)
                retained_task_ids.add(new_task.id)

        for t in existing_tasks:
            if t.id not in retained_task_ids:
                old_v_ids = [link.vulnerability_id for link in (t.vulnerability_links or []) if link.vulnerability_id]
                for link in list(t.vulnerability_links or []):
                    db.delete(link)
                db.delete(t)
                db.flush()
                if old_v_ids:
                    revert_orphaned_vulns_to_open(
                        db=db,
                        vuln_ids=old_v_ids,
                        current_username=current_username,
                        reason=f"Desvinculada do Plano #{plan.id} ({plan.title}) devido à remoção do host '{t.title}' do escopo."
                    )

    else:
        pair_groups: Dict[Tuple[str, str], List[models.Vulnerability]] = {}
        pair_order: List[Tuple[str, str]] = []
        for v in matching_vulns:
            hip = (v.host.ip_address if v.host else str(v.host_id)).strip()
            key = (hip, str(v.plugin_id).strip())
            if key not in pair_groups:
                pair_groups[key] = []
                pair_order.append(key)
            pair_groups[key].append(v)

        existing_by_pair: Dict[Tuple[str, str], models.ActionTask] = {}
        for t in existing_tasks:
            task_key = None
            for link in (t.vulnerability_links or []):
                v = link.vulnerability
                if v and v.host and v.host.ip_address:
                    task_key = (v.host.ip_address.strip(), str(v.plugin_id).strip())
                    break
            if not task_key:
                for pair in pair_order:
                    hip, pid = pair
                    if hip in t.title and (pid in (t.description or "") or any(v.plugin_name == t.description for v in pair_groups[pair])):
                        task_key = pair
                        break
            if task_key and task_key not in existing_by_pair:
                existing_by_pair[task_key] = t

        retained_task_ids = set()

        for idx, key in enumerate(pair_order):
            vulns = pair_groups[key]
            host = vulns[0].host
            vuln_sample = vulns[0]
            v_ids = [v.id for v in vulns]
            desired_v_ids = set(v_ids)

            if key in existing_by_pair:
                task = existing_by_pair[key]
                unlinked_vids = []
                for link in list(task.vulnerability_links or []):
                    if link.vulnerability_id not in desired_v_ids:
                        unlinked_vids.append(link.vulnerability_id)
                        db.delete(link)
                if unlinked_vids:
                    db.flush()
                    revert_orphaned_vulns_to_open(
                        db=db,
                        vuln_ids=unlinked_vids,
                        current_username=current_username,
                        reason=f"Desvinculada da etapa '{task.title}' após alteração de escopo do Plano #{plan.id}."
                    )
                link_vulns_to_task_with_precedence(db, task, v_ids, current_username, is_host_scope=is_host_scope)
                retained_task_ids.add(task.id)
            else:
                task_title = format_host_task_title(host, fallback_ip=key[0])
                task_desc = vuln_sample.plugin_name.strip() if vuln_sample.plugin_name else f"Plugin #{vuln_sample.plugin_id}"
                new_task = models.ActionTask(
                    action_plan_id=plan.id,
                    title=task_title,
                    description=task_desc,
                    order_index=idx,
                    status="TODO",
                    assigned_user_id=plan.owner_user_id,
                    due_date=plan.due_date
                )
                db.add(new_task)
                db.flush()
                link_vulns_to_task_with_precedence(db, new_task, v_ids, current_username, is_host_scope=is_host_scope)
                retained_task_ids.add(new_task.id)

        for t in existing_tasks:
            if t.id not in retained_task_ids:
                old_v_ids = [link.vulnerability_id for link in (t.vulnerability_links or []) if link.vulnerability_id]
                for link in list(t.vulnerability_links or []):
                    db.delete(link)
                db.delete(t)
                db.flush()
                if old_v_ids:
                    revert_orphaned_vulns_to_open(
                        db=db,
                        vuln_ids=old_v_ids,
                        current_username=current_username,
                        reason=f"Desvinculada do Plano #{plan.id} ({plan.title}) devido à remoção do par ({t.title}) do escopo."
                    )

    db.flush()
    return plan.tasks or []


def sync_action_plans_on_scan_import(
    db: Session,
    scan: models.Scan,
    current_username: str
):
    """
    Sincroniza automaticamente Planos de Ação e suas Etapas após a importação de um novo Scan CSV (ISO 27001 / PDCA):
    1. Recorrência: se o par (Host + Vulnerabilidade) persistir/reaparecer no novo scan, associa
       a nova vulnerabilidade ao mesmo plano e à mesma etapa, marcando-a como 'In_Action_Plan'.
    2. Auto-conclusão: caso na importação a vulnerabilidade não apareça para o host escaneado,
       a respectiva etapa (host+vulnerabilidade) é definida como Concluída ('DONE') e a vulnerabilidade anterior marcada como 'Remediated'.
    3. Reabertura para 'Em Revisão': se o plano estiver 'PLANNED' ou 'IN_PROGRESS' e o cruzamento
       host+vulnerabilidade estiver presente no novo scan, e a tarefa estava 'DONE' (Concluída),
       atualiza a etapa para 'REVIEW' ('Em Revisão') e o status da vulnerabilidade para 'In_Action_Plan'.
    """
    now = utc_now()
    from app.services.asset_group_service import get_descendant_group_ids

    # 0. Prevenção de concorrência: lock consultivo de transação por grupo de ativos no PostgreSQL
    if scan.asset_group_id and db.bind and getattr(db.bind.dialect, "name", "") == "postgresql":
        try:
            db.execute(text("SELECT pg_advisory_xact_lock(:gid)"), {"gid": scan.asset_group_id})
        except Exception as lock_err:
            logger.debug(f"pg_advisory_xact_lock: {lock_err}")

    # 1. Identificar hosts presentes neste novo scan
    scanned_hosts = db.query(models.Host).filter(models.Host.scan_id == scan.id).all()
    scanned_host_ips = {h.ip_address.strip() for h in scanned_hosts if h.ip_address}
    if not scanned_host_ips:
        return

    # 2. Identificar vulnerabilidades encontradas no novo scan (sem excluir severidades para preservar auditoria de escopos específicos)
    new_vulns = db.query(models.Vulnerability).join(
        models.Host, models.Vulnerability.host_id == models.Host.id
    ).filter(
        models.Vulnerability.scan_id == scan.id
    ).all()

    new_vulns_by_pair: Dict[Tuple[str, str], List[models.Vulnerability]] = {}
    for nv in new_vulns:
        if nv.host and nv.host.ip_address:
            key = (nv.host.ip_address.strip(), str(nv.plugin_id).strip())
            if key not in new_vulns_by_pair:
                new_vulns_by_pair[key] = []
            new_vulns_by_pair[key].append(nv)

    # 3. Buscar planos de ação ativos ou completados elegíveis
    active_plans = db.query(models.ActionPlan).filter(
        models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS", "COMPLETED"])
    ).all()

    for plan in active_plans:
        # Verificar abrangência do grupo de ativos (incluindo grupos descendentes)
        plan_gids = set()
        if plan.asset_group_id:
            plan_gids.update(get_descendant_group_ids(db, plan.asset_group_id, include_self=True))
        if plan.target_host and plan.target_host.asset_group_id:
            plan_gids.update(get_descendant_group_ids(db, plan.target_host.asset_group_id, include_self=True))

        if plan_gids and scan.asset_group_id and (scan.asset_group_id not in plan_gids):
            continue

        tasks = plan.tasks or []
        if not tasks:
            continue

        for task in tasks:
            # Coletar pares (host_ip, plugin_id) monitorados por esta etapa
            monitored_pairs: Set[Tuple[str, str]] = set()
            task_host_ips: Set[str] = set()

            for link in (task.vulnerability_links or []):
                v = link.vulnerability
                if v and v.host and v.host.ip_address:
                    monitored_pairs.add((v.host.ip_address.strip(), str(v.plugin_id).strip()))
                    task_host_ips.add(v.host.ip_address.strip())

            # Se a etapa ainda não tiver links associados, tentar deduzir por IP de host da tarefa e escopo do plano
            if not monitored_pairs:
                task_ip_candidate = task.title.split()[0].strip("()[],")
                if task_ip_candidate in scanned_host_ips:
                    task_host_ips.add(task_ip_candidate)
                    if plan.scope_plugins:
                        for sp in plan.scope_plugins:
                            monitored_pairs.add((task_ip_candidate, str(sp.plugin_id).strip()))
                    elif plan.target_plugin_id:
                        monitored_pairs.add((task_ip_candidate, str(plan.target_plugin_id).strip()))

            # Se o escopo for baseado puramente em host (HOST ou MATRIX_NN sem lista de plugins),
            # adicionar quaisquer novas vulnerabilidades dos hosts monitorados pela tarefa
            is_host_scope_task = (plan.scope_type == "HOST") or (plan.scope_type == "MATRIX_NN" and not (plan.scope_plugins and len(plan.scope_plugins) > 0))
            if is_host_scope_task and task_host_ips:
                for nv in new_vulns:
                    if nv.host and nv.host.ip_address and nv.host.ip_address.strip() in task_host_ips:
                        if nv.severity and nv.severity.lower() in ["info", "none"]:
                            continue
                        monitored_pairs.add((nv.host.ip_address.strip(), str(nv.plugin_id).strip()))

            # Considerar apenas pares cujos hosts participaram do novo scan
            relevant_pairs = {pair for pair in monitored_pairs if pair[0] in scanned_host_ips}
            if not relevant_pairs:
                continue

            present_pairs = {p for p in relevant_pairs if p in new_vulns_by_pair}
            absent_pairs = {p for p in relevant_pairs if p not in new_vulns_by_pair}

            # A. Tratamento de pares PRESENTES (Vulnerabilidade Não Remediada / Recorrência)
            for pair in present_pairs:
                host_ip, pid_str = pair
                for nv in new_vulns_by_pair[pair]:
                    # Associar nv à tarefa se ainda não associada
                    already_linked = any(
                        link.vulnerability_id == nv.id for link in (task.vulnerability_links or [])
                    ) or db.query(models.ActionTaskVulnerabilityLink).filter(
                        models.ActionTaskVulnerabilityLink.action_task_id == task.id,
                        models.ActionTaskVulnerabilityLink.vulnerability_id == nv.id
                    ).first()

                    if not already_linked:
                        db.add(models.ActionTaskVulnerabilityLink(
                            action_task_id=task.id,
                            vulnerability_id=nv.id
                        ))
                        db.flush()

                    if nv.treatment_status != "In_Action_Plan":
                        nv.treatment_status = "In_Action_Plan"
                        nv.treated_by_username = current_username
                        nv.treated_at = now
                        nv.treatment_notes = (
                            f"Vulnerabilidade não remediada: persistência confirmada no Scan #{scan.id} "
                            f"para o Host {host_ip}. Mantida no Plano de Ação #{plan.id} ({plan.title}) - Etapa '{task.title}'."
                        )
                        hist_nv = models.VulnerabilityTreatmentHistory(
                            vulnerability_id=nv.id,
                            treatment_status="In_Action_Plan",
                            treatment_notes=(
                                f"Vulnerabilidade não remediada: detectada no Scan #{scan.id} "
                                f"e vinculada à Etapa '{task.title}' do Plano de Ação #{plan.id}."
                            ),
                            changed_by_username=current_username,
                            changed_at=now
                        )
                        db.add(hist_nv)

                # Atualizar vulnerabilidades anteriores da mesma tarefa registrando explicitamente a não remediação
                for link in (task.vulnerability_links or []):
                    old_v = link.vulnerability
                    if old_v and old_v.host and old_v.host.ip_address.strip() == host_ip and str(old_v.plugin_id).strip() == pid_str:
                        old_v.treatment_status = "In_Action_Plan"
                        old_v.treated_by_username = current_username
                        old_v.treated_at = now
                        old_v.treatment_notes = (
                            f"Vulnerabilidade não remediada: persistência confirmada no Scan #{scan.id}."
                        )
                        hist_not_rem = models.VulnerabilityTreatmentHistory(
                            vulnerability_id=old_v.id,
                            treatment_status="In_Action_Plan",
                            treatment_notes=f"Vulnerabilidade não remediada: persistência detectada no Scan #{scan.id}.",
                            changed_by_username=current_username,
                            changed_at=now
                        )
                        db.add(hist_not_rem)

            # B. Tratamento de pares AUSENTES (Remediados)
            for pair in absent_pairs:
                host_ip, pid_str = pair
                for link in (task.vulnerability_links or []):
                    old_v = link.vulnerability
                    if old_v and old_v.host and old_v.host.ip_address.strip() == host_ip and str(old_v.plugin_id).strip() == pid_str:
                        if old_v.treatment_status != "Remediated":
                            old_v.treatment_status = "Remediated"
                            old_v.treated_by_username = current_username
                            old_v.treated_at = now
                            old_v.treatment_notes = (
                                f"Remediada: vulnerabilidade não mais detectada no Host {host_ip} no Scan #{scan.id} "
                                f"(Plano de Ação #{plan.id} - Etapa '{task.title}')."
                            )
                            hist_rem = models.VulnerabilityTreatmentHistory(
                                vulnerability_id=old_v.id,
                                treatment_status="Remediated",
                                treatment_notes=f"Remediada: vulnerabilidade corrigida e ausente no Scan #{scan.id}.",
                                changed_by_username=current_username,
                                changed_at=now
                            )
                            db.add(hist_rem)

                # Também marcar como Remediated instâncias anteriores abertas ou em plano deste par no grupo de ativos
                prior_vulns = db.query(models.Vulnerability).join(
                    models.Host, models.Vulnerability.host_id == models.Host.id
                ).filter(
                    models.Host.ip_address == host_ip,
                    models.Vulnerability.plugin_id == pid_str,
                    models.Vulnerability.treatment_status.in_(["Open", "In_Action_Plan"])
                ).all()
                for pv in prior_vulns:
                    if pv.asset_group_id == scan.asset_group_id or (plan_gids and pv.asset_group_id in plan_gids):
                        pv.treatment_status = "Remediated"
                        pv.treated_by_username = current_username
                        pv.treated_at = now
                        pv.treatment_notes = (
                            f"Remediada: vulnerabilidade confirmada como corrigida (ausente no Scan #{scan.id}) "
                            f"pelo Plano de Ação #{plan.id} ({plan.title})."
                        )
                        db.add(models.VulnerabilityTreatmentHistory(
                            vulnerability_id=pv.id,
                            treatment_status="Remediated",
                            treatment_notes=f"Remediada: ausente no Scan #{scan.id} (Plano #{plan.id}).",
                            changed_by_username=current_username,
                            changed_at=now
                        ))

            # C. Atualização do status da Etapa/Tarefa
            if len(present_pairs) > 0:
                # Regra: se a vulnerabilidade não foi remediada e a tarefa estava como concluída, reabrir para 'REVIEW'
                if task.status == "DONE":
                    task.status = "REVIEW"
                    task.completed_at = None
            elif len(present_pairs) == 0 and len(absent_pairs) > 0:
                # Se todas as vulnerabilidades monitoradas para este host foram remediadas
                if all(p in absent_pairs for p in monitored_pairs):
                    task.status = "DONE"
                    task.completed_at = now

        # D. Atualização do status do Plano
        all_tasks = plan.tasks or []
        if all_tasks:
            all_done = all(t.status == "DONE" for t in all_tasks)
            any_active = any(t.status in ["REVIEW", "TODO", "DOING", "IN_PROGRESS"] for t in all_tasks)
            if all_done and plan.status != "COMPLETED":
                plan.status = "COMPLETED"
                plan.updated_at = now
            elif any_active:
                if plan.status in ["PLANNED", "COMPLETED"]:
                    plan.status = "IN_PROGRESS"
                    plan.updated_at = now

    db.commit()


def build_action_plan_group_filter(db: Session, current_user: models.User, asset_group_id: Optional[int]):
    """
    Constrói a cláusula de filtro para planos de ação respeitando:
    1. Hierarquia multinível completa de Grupos de Ativos (grupos superiores cobrem
       todos os seus subgrupos descendentes de 2º, 3º e demais níveis).
    2. Vínculo de grupo direto (plan.asset_group_id), grupo do host alvo
       (target_host.asset_group_id) ou grupo de vulnerabilidades vinculadas.
    3. Controle de acesso granular RBAC do usuário.
    """
    from app.services.asset_group_service import get_descendant_group_ids

    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")

    def make_group_match_clause(group_ids: List[int]):
        return or_(
            models.ActionPlan.asset_group_id.in_(group_ids),
            models.ActionPlan.target_host.has(models.Host.asset_group_id.in_(group_ids)),
            models.ActionPlan.tasks.any(
                models.ActionTask.vulnerability_links.any(
                    models.ActionTaskVulnerabilityLink.vulnerability.has(
                        models.Vulnerability.asset_group_id.in_(group_ids)
                    )
                )
            )
        )

    if allowed_ids is not None:
        if asset_group_id:
            check_user_group_access(db, current_user, asset_group_id, action="view")
            descendant_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
            target_ids = list(set(descendant_ids).intersection(set(allowed_ids)))
            if not target_ids:
                return literal(False)
            return make_group_match_clause(target_ids)
        else:
            if not allowed_ids:
                return literal(False)
            return or_(
                make_group_match_clause(allowed_ids),
                and_(
                    models.ActionPlan.asset_group_id == None,
                    or_(
                        models.ActionPlan.target_host_id == None,
                        models.ActionPlan.target_host.has(models.Host.asset_group_id.in_(allowed_ids))
                    )
                )
            )
    elif asset_group_id:
        target_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
        return make_group_match_clause(target_ids)

    return None


@router.get("", response_model=List[schemas.ActionPlanOut])
def list_action_plans(
    asset_group_id: Optional[int] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    scope_type: Optional[str] = None,
    owner_user_id: Optional[int] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Lista planos de ação cadastrados com suporte a filtros, tags, hierarquia multinível de grupos e RBAC.
    """
    query = db.query(models.ActionPlan)

    # Hierarchical group filter and RBAC
    group_filter = build_action_plan_group_filter(db, current_user, asset_group_id)
    if group_filter is not None:
        query = query.filter(group_filter)

    if status:
        query = query.filter(models.ActionPlan.status == status.upper())
    if priority:
        query = query.filter(models.ActionPlan.priority == priority.upper())
    if scope_type:
        query = query.filter(models.ActionPlan.scope_type == scope_type.upper())
    if owner_user_id:
        query = query.filter(models.ActionPlan.owner_user_id == owner_user_id)
    if tag:
        clean_tag = tag.strip()
        query = query.filter(
            models.ActionPlan.tag_links.any(
                models.ActionPlanTagLink.tag.has(models.Tag.name.ilike(clean_tag))
            )
        )

    if search:
        st = f"%{search.strip()}%"
        query = query.filter(
            or_(
                models.ActionPlan.title.ilike(st),
                models.ActionPlan.description.ilike(st),
                models.ActionPlan.created_by_username.ilike(st)
            )
        )

    plans = query.order_by(models.ActionPlan.updated_at.desc(), models.ActionPlan.id.desc()).all()
    now_utc = utc_now()
    return [format_plan_out(p, now_utc) for p in plans]


@router.get("/stats", response_model=schemas.ActionPlanStatsOut)
def get_action_plans_stats(
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna métricas executivas consolidadas dos Planos de Ação e suas Etapas respeitando a hierarquia de grupos.
    """
    query = db.query(models.ActionPlan)
    group_filter = build_action_plan_group_filter(db, current_user, asset_group_id)
    if group_filter is not None:
        query = query.filter(group_filter)

    plans = query.all()
    now_utc = utc_now()

    total_plans = len(plans)
    planned = 0
    in_progress = 0
    completed = 0
    blocked = 0
    overdue = 0
    total_tasks = 0
    completed_tasks = 0

    for p in plans:
        st = (p.status or "").upper()
        if st == "PLANNED" or st == "DRAFT":
            planned += 1
        elif st == "IN_PROGRESS":
            in_progress += 1
        elif st == "COMPLETED":
            completed += 1
        elif st == "BLOCKED":
            blocked += 1

        if p.due_date and st not in ["COMPLETED", "CANCELLED"]:
            due = p.due_date.replace(tzinfo=timezone.utc) if p.due_date.tzinfo is None else p.due_date
            if due < now_utc:
                overdue += 1

        tasks = p.tasks or []
        total_tasks += len(tasks)
        completed_tasks += sum(1 for t in tasks if t.status == "DONE")

    overall_pct = round((completed_tasks / total_tasks) * 100.0, 1) if total_tasks > 0 else 0.0

    return schemas.ActionPlanStatsOut(
        total_plans=total_plans,
        planned_count=planned,
        in_progress_count=in_progress,
        completed_count=completed,
        blocked_count=blocked,
        overdue_count=overdue,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        overall_progress_percent=overall_pct
    )


@router.get("/assignees", response_model=List[schemas.ActionPlanAssigneeOut])
def get_action_plan_assignees(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna lista de usuários do GvulStand habilitados para atribuição de tarefas e planos.
    """
    users = db.query(models.User).filter(models.User.is_active == True).order_by(models.User.username).all()
    return [
        schemas.ActionPlanAssigneeOut(
            id=u.id,
            username=u.username,
            full_name=u.full_name or u.username,
            role=u.role
        )
        for u in users
    ]


@router.get("/tags", response_model=List[schemas.TagOut])
def list_action_plan_tags(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna lista de todas as tags de Planos de Ação e suas respectivas contagens de uso.
    """
    tags = db.query(models.Tag).order_by(models.Tag.name).all()
    result = []
    for t in tags:
        cnt = db.query(func.count(models.ActionPlanTagLink.id)).filter(models.ActionPlanTagLink.tag_id == t.id).scalar() or 0
        out = schemas.TagOut(
            id=t.id,
            name=t.name,
            color_hex=t.color_hex or "#6366f1",
            color=t.color_hex or "#6366f1",
            created_at=t.created_at,
            usage_count=cnt
        )
        result.append(out)
    return result


@router.post("/tags", response_model=schemas.TagOut)
def create_action_plan_tag(
    data: schemas.TagCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Cria uma nova tag ou retorna a tag existente com mesmo nome.
    """
    clean_name = data.name.strip()
    if not clean_name:
        raise HTTPException(status_code=422, detail="Nome da tag não pode ser vazio.")

    existing = db.query(models.Tag).filter(models.Tag.name.ilike(clean_name)).first()
    if existing:
        cnt = db.query(func.count(models.ActionPlanTagLink.id)).filter(models.ActionPlanTagLink.tag_id == existing.id).scalar() or 0
        return schemas.TagOut(
            id=existing.id,
            name=existing.name,
            color_hex=existing.color_hex or "#6366f1",
            color=existing.color_hex or "#6366f1",
            created_at=existing.created_at,
            usage_count=cnt
        )

    color_val = data.color or data.color_hex or "#6366f1"
    tag = models.Tag(
        name=clean_name,
        color_hex=color_val
    )
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return schemas.TagOut(
        id=tag.id,
        name=tag.name,
        color_hex=tag.color_hex,
        color=tag.color_hex,
        created_at=tag.created_at,
        usage_count=0
    )


@router.get("/unassigned-vulns", response_model=List[schemas.VulnerabilityOut])
def get_unassigned_vulnerabilities(
    asset_group_id: Optional[int] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna vulnerabilidades órfãs (não atribuídas a nenhum Plano de Ação ativo) dos scans mais recentes.
    Permite identificar apontamentos críticos e altos sem plano de remediação estabelecido (ISO 27001).
    """
    from app.services.scan_service import get_latest_scan_ids
    from app.services.parameter_service import get_ignored_ids_set
    from app.api.routes_vulnerabilities import format_vuln_out

    active_scan_ids = get_latest_scan_ids(db, asset_group_id)
    if not active_scan_ids:
        return []

    # Subquery de IDs de vulnerabilidades já em planos ativos (PLANNED, IN_PROGRESS)
    assigned_vuln_ids_q = db.query(models.ActionTaskVulnerabilityLink.vulnerability_id).join(
        models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
    ).join(
        models.ActionPlan, models.ActionTask.action_plan_id == models.ActionPlan.id
    ).filter(
        models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
    ).distinct()

    query = db.query(models.Vulnerability).join(
        models.Host, models.Vulnerability.host_id == models.Host.id
    ).filter(
        models.Vulnerability.scan_id.in_(active_scan_ids),
        models.Vulnerability.treatment_status.in_(["Open", "open"]),
        ~models.Vulnerability.id.in_(assigned_vuln_ids_q),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"])
    )

    if severity:
        query = query.filter(models.Vulnerability.severity == severity)
    if search:
        st = f"%{search.strip()}%"
        query = query.filter(
            or_(
                models.Vulnerability.plugin_name.ilike(st),
                models.Vulnerability.cve.ilike(st),
                models.Vulnerability.plugin_id.ilike(st),
                models.Host.ip_address.ilike(st),
                models.Host.hostname.ilike(st)
            )
        )

    ignored_ids = get_ignored_ids_set(db)
    vulns = query.order_by(
        case(
            (models.Vulnerability.severity == "Critical", 1),
            (models.Vulnerability.severity == "High", 2),
            (models.Vulnerability.severity == "Medium", 3),
            (models.Vulnerability.severity == "Low", 4),
            else_=5
        ),
        models.Vulnerability.exploit_available.desc(),
        models.Vulnerability.cvss_v3.desc(),
        models.Vulnerability.id.desc()
    ).offset(offset).limit(limit).all()

    return [format_vuln_out(v, ignored_ids, db=db) for v in vulns]


@router.get("/wizard/os-list", response_model=List[str])
def get_wizard_os_list(
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna lista única de sistemas operacionais identificados nos scans mais recentes para o grupo selecionado.
    """
    from app.services.scan_service import get_latest_scan_ids
    latest_scans = get_latest_scan_ids(db, asset_group_id)
    if not latest_scans:
        return []

    os_rows = db.query(models.Host.os).filter(
        models.Host.scan_id.in_(latest_scans),
        models.Host.os.isnot(None),
        models.Host.os != ''
    ).distinct().order_by(models.Host.os.asc()).all()

    return [r[0] for r in os_rows if r[0] and r[0].strip()]


@router.get("/wizard/hosts", response_model=List[schemas.ActionPlanWizardHostOut])
def get_wizard_hosts(
    asset_group_id: Optional[int] = None,
    search: Optional[str] = None,
    os: Optional[str] = None,
    limit: int = 50,
    plan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna lista de hosts com vulnerabilidades ativas da importação mais recente para seleção passo a passo no Wizard de criação.
    Permite busca por IP ou Hostname e filtragem por Grupo de Ativos e Sistema Operacional.
    Exclui vulnerabilidades Remediadas: apenas vulnerabilidades com status 'Open' são elegíveis.
    """
    from app.services.asset_group_service import get_descendant_group_ids
    from app.services.scan_service import get_latest_scan_ids

    target_gids = None
    if asset_group_id:
        target_gids = get_descendant_group_ids(db, asset_group_id, include_self=True)

    latest_scans = get_latest_scan_ids(db, asset_group_id)
    if not latest_scans:
        return []

    if plan_id:
        this_plan_vids = [
            v[0] for v in db.query(models.ActionTaskVulnerabilityLink.vulnerability_id).join(
                models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
            ).filter(models.ActionTask.action_plan_id == plan_id).all()
        ]
        allowed_status_clause = and_(
            ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated", "Accepted_Risk"]),
            or_(
                models.Vulnerability.treatment_status.in_(["Open", "open"]),
                models.Vulnerability.id.in_(this_plan_vids)
            )
        )
    else:
        allowed_status_clause = models.Vulnerability.treatment_status.in_(["Open", "open"])

    query = db.query(
        models.Host.ip_address,
        func.max(models.Host.hostname).label('hostname'),
        func.max(models.Host.os).label('os'),
        func.max(models.Host.id).label('host_id'),
        func.max(models.Host.asset_group_id).label('asset_group_id'),
        func.count(models.Vulnerability.id).label('vuln_count'),
        func.sum(case((models.Vulnerability.severity.in_(["Critical", "critical"]), 1), else_=0)).label('critical_count'),
        func.sum(case((models.Vulnerability.severity.in_(["High", "high"]), 1), else_=0)).label('high_count'),
        func.sum(case((models.Vulnerability.severity.in_(["Medium", "medium"]), 1), else_=0)).label('medium_count'),
        func.sum(case((models.Vulnerability.severity.in_(["Low", "low"]), 1), else_=0)).label('low_count')
    ).join(
        models.Vulnerability, models.Host.id == models.Vulnerability.host_id
    ).filter(
        models.Vulnerability.scan_id.in_(latest_scans),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
        allowed_status_clause
    )

    if target_gids:
        query = query.filter(models.Host.asset_group_id.in_(target_gids))

    if os and os.strip():
        query = query.filter(models.Host.os.ilike(f"%{os.strip()}%"))

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                models.Host.ip_address.ilike(term),
                models.Host.hostname.ilike(term)
            )
        )

    query = query.group_by(models.Host.ip_address).order_by(
        func.count(models.Vulnerability.id).desc()
    ).limit(limit)

    results = query.all()
    gids = set(r.asset_group_id for r in results if r.asset_group_id)
    groups = {g.id: g.name for g in db.query(models.AssetGroup).filter(models.AssetGroup.id.in_(gids)).all()} if gids else {}

    return [
        schemas.ActionPlanWizardHostOut(
            id=r.host_id,
            ip=r.ip_address,
            hostname=r.hostname or "",
            os=r.os or "",
            asset_group_id=r.asset_group_id,
            asset_group_name=groups.get(r.asset_group_id, "Global"),
            vuln_count=int(r.vuln_count or 0),
            critical_count=int(r.critical_count or 0),
            high_count=int(r.high_count or 0),
            medium_count=int(r.medium_count or 0),
            low_count=int(r.low_count or 0)
        )
        for r in results
    ]


@router.get("/wizard/vulnerabilities", response_model=List[schemas.ActionPlanWizardVulnOut])
def get_wizard_vulnerabilities(
    asset_group_id: Optional[int] = None,
    host_ips: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    plan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna lista de vulnerabilidades (plugins) candidatas da importação mais recente para inclusão no Wizard.
    Se host_ips for informado, lista as vulnerabilidades que afetam aqueles hosts no scan mais recente.
    Se não for informado, lista as vulnerabilidades presentes no Grupo de Ativos no scan mais recente.
    Exclui vulnerabilidades Remediadas: apenas vulnerabilidades com status 'Open' são elegíveis.
    """
    from app.services.asset_group_service import get_descendant_group_ids
    from app.services.scan_service import get_latest_scan_ids

    target_gids = None
    if asset_group_id:
        target_gids = get_descendant_group_ids(db, asset_group_id, include_self=True)

    latest_scans = get_latest_scan_ids(db, asset_group_id)
    if not latest_scans:
        return []

    clean_ips = [ip.strip() for ip in (host_ips or "").split(",") if ip.strip()]

    if plan_id:
        this_plan_vids = [
            v[0] for v in db.query(models.ActionTaskVulnerabilityLink.vulnerability_id).join(
                models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
            ).filter(models.ActionTask.action_plan_id == plan_id).all()
        ]
        allowed_status_clause = and_(
            ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated", "Accepted_Risk"]),
            or_(
                models.Vulnerability.treatment_status.in_(["Open", "open"]),
                models.Vulnerability.id.in_(this_plan_vids)
            )
        )
    else:
        allowed_status_clause = models.Vulnerability.treatment_status.in_(["Open", "open"])

    severity_agg = func.max(models.Vulnerability.severity)

    query = db.query(
        models.Vulnerability.plugin_id,
        func.max(models.Vulnerability.plugin_name).label('plugin_name'),
        severity_agg.label('severity'),
        func.max(models.Vulnerability.cve).label('cve'),
        func.count(func.distinct(models.Host.ip_address)).label('affected_hosts_count')
    ).join(
        models.Host, models.Host.id == models.Vulnerability.host_id
    ).filter(
        models.Vulnerability.scan_id.in_(latest_scans),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
        allowed_status_clause
    )

    if clean_ips:
        query = query.filter(models.Host.ip_address.in_(clean_ips))
    elif target_gids:
        query = query.filter(models.Vulnerability.asset_group_id.in_(target_gids))

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                models.Vulnerability.plugin_id.ilike(term),
                models.Vulnerability.plugin_name.ilike(term),
                models.Vulnerability.cve.ilike(term)
            )
        )

    query = query.group_by(models.Vulnerability.plugin_id).order_by(
        case(
            (severity_agg == "Critical", 1),
            (severity_agg == "High", 2),
            (severity_agg == "Medium", 3),
            (severity_agg == "Low", 4),
            else_=5
        ),
        func.count(func.distinct(models.Host.ip_address)).desc()
    ).limit(limit)

    results = query.all()
    return [
        schemas.ActionPlanWizardVulnOut(
            plugin_id=str(r.plugin_id),
            plugin_name=r.plugin_name or f"Plugin #{r.plugin_id}",
            severity=r.severity or "Medium",
            cve=r.cve or "",
            affected_hosts_count=int(r.affected_hosts_count or 0)
        )
        for r in results
    ]


def validate_action_plan_relational_scope(
    db: Session,
    scope_type: str,
    asset_group_id: Optional[int] = None,
    target_host_id: Optional[int] = None,
    target_host_ip: Optional[str] = None,
    target_plugin_id: Optional[str] = None,
    scope_host_ips: Optional[List[str]] = None,
    scope_plugin_ids: Optional[List[str]] = None,
    strict_raise: bool = True,
    plan_id: Optional[int] = None
) -> Tuple[bool, List[str], List[str], Optional[str], List[models.Vulnerability]]:
    """
    Valida rigorosamente a integridade relacional do escopo do Plano de Ação utilizando
    exclusivamente os dados da importação mais recente de cada Grupo de Ativos (ISO 27001):
    1. Escopo HOST:
       - O IP/ID do host deve existir na base de dados.
       - Se especificado asset_group_id, o host deve pertencer ao grupo ou subgrupos hierárquicos.
       - O host deve possuir no mínimo uma vulnerabilidade ativa (não-Info) vinculada a ele no scan mais recente.
    2. Escopo VULNERABILITY:
       - O target_plugin_id deve existir e possuir vulnerabilidades ativas (não-Info) vinculadas no scan mais recente.
    3. Escopo MATRIX_NN (N hosts para M vulnerabilidades):
       - Todos os IPs da lista de hosts devem existir na base de dados.
       - Se especificado asset_group_id, todos os hosts devem pertencer à hierarquia do grupo.
       - O plano deve ser estritamente relacional:
         * Nenhum host da lista pode ficar sem pelo menos uma vulnerabilidade dos plugins indicados no scan mais recente.
         * Nenhum plugin da lista pode ficar sem ao menos um host afetado da lista de hosts no scan mais recente.
    4. Escopo GROUP:
       - O grupo deve possuir vulnerabilidades ativas (Críticas/Altas) no scan mais recente.

    Retorna: (is_valid, unmatched_hosts, unmatched_plugins, validation_message, matching_vulns)
    Se strict_raise=True e is_valid=False, levanta HTTPException(status_code=422).
    """
    from app.services.asset_group_service import get_descendant_group_ids
    from app.services.scan_service import get_latest_scan_ids

    scope = (scope_type or "CUSTOM").upper()
    target_gids = None
    if asset_group_id:
        target_gids = get_descendant_group_ids(db, asset_group_id, include_self=True)

    latest_scan_ids = get_latest_scan_ids(db, asset_group_id)

    if plan_id:
        this_plan_vids = [
            v[0] for v in db.query(models.ActionTaskVulnerabilityLink.vulnerability_id).join(
                models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
            ).filter(models.ActionTask.action_plan_id == plan_id).all()
        ]
        allowed_status_clause = and_(
            ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated", "Accepted_Risk", "accepted_risk"]),
            or_(
                models.Vulnerability.treatment_status.in_(["Open", "open"]),
                models.Vulnerability.id.in_(this_plan_vids)
            )
        )
    else:
        allowed_status_clause = ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated", "Accepted_Risk", "accepted_risk"])

    if scope == "HOST":
        target_host = None
        if target_host_id:
            target_host = db.query(models.Host).filter(models.Host.id == target_host_id).first()
        if not target_host and target_host_ip and str(target_host_ip).strip():
            target_ip_clean = str(target_host_ip).strip()
            candidate_hosts = db.query(models.Host).filter(models.Host.ip_address == target_ip_clean).order_by(models.Host.id.desc()).all()
            for ch in candidate_hosts:
                if latest_scan_ids and ch.scan_id in latest_scan_ids:
                    target_host = ch
                    break
            if not target_host:
                for ch in candidate_hosts:
                    has_act = db.query(models.Vulnerability.id).filter(
                        models.Vulnerability.host_id == ch.id,
                        models.Vulnerability.scan_id.in_(latest_scan_ids) if latest_scan_ids else literal(False),
                        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
                        allowed_status_clause
                    ).first()
                    if has_act:
                        target_host = ch
                        break
            if not target_host and candidate_hosts:
                target_host = candidate_hosts[0]

        ip_disp = str(target_host_ip).strip() if target_host_ip else (str(target_host_id) if target_host_id else "")
        if not target_host:
            msg = f"Plano de Ação inválido / não relacional: O host '{ip_disp or 'desconhecido'}' não foi encontrado no inventário de ativos."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [ip_disp] if ip_disp else [], [], msg, []

        if target_gids and target_host.asset_group_id and target_host.asset_group_id not in target_gids:
            msg = f"Plano de Ação inválido / não relacional: O host '{target_host.ip_address}' não pertence ao Grupo de Ativos selecionado ou aos seus subgrupos."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [target_host.ip_address], [], msg, []

        if not latest_scan_ids:
            msg = f"Plano de Ação inválido / não relacional: O host '{target_host.ip_address}' não possui vulnerabilidades ativas na importação mais recente para compor um Plano de Ação."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [target_host.ip_address], [], msg, []

        # Atualizar para a instância de Host no scan mais recente se disponível
        recent_host = db.query(models.Host).filter(
            models.Host.ip_address == target_host.ip_address,
            models.Host.scan_id.in_(latest_scan_ids)
        ).first()
        if recent_host:
            target_host = recent_host

        vq = db.query(models.Vulnerability).join(
            models.Host, models.Vulnerability.host_id == models.Host.id
        ).filter(
            models.Host.ip_address == target_host.ip_address,
            models.Vulnerability.scan_id.in_(latest_scan_ids),
            ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
            allowed_status_clause
        )
        if target_gids:
            vq = vq.filter(models.Vulnerability.asset_group_id.in_(target_gids))

        matching_vulns = vq.all()
        if not matching_vulns:
            msg = f"Plano de Ação inválido / não relacional: O host '{target_host.ip_address}' não possui vulnerabilidades ativas na importação mais recente para compor um Plano de Ação."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [target_host.ip_address], [], msg, []

        return True, [], [], None, matching_vulns

    elif scope == "VULNERABILITY":
        plugin_id = str(target_plugin_id or "").strip()
        if not plugin_id:
            msg = "Plano de Ação inválido: É obrigatório informar o Plugin ID para planos com escopo por Vulnerabilidade."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [], [], msg, []

        if not latest_scan_ids:
            msg = f"Plano de Ação inválido / não relacional: O Plugin ID '{plugin_id}' não possui vulnerabilidades ativas na importação mais recente no escopo selecionado."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [], [plugin_id], msg, []

        vq = db.query(models.Vulnerability).filter(
            models.Vulnerability.plugin_id == plugin_id,
            models.Vulnerability.scan_id.in_(latest_scan_ids),
            ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
            allowed_status_clause
        )
        if target_gids:
            vq = vq.filter(models.Vulnerability.asset_group_id.in_(target_gids))

        matching_vulns = vq.all()
        if not matching_vulns:
            msg = f"Plano de Ação inválido / não relacional: O Plugin ID '{plugin_id}' não possui vulnerabilidades ativas na importação mais recente no escopo selecionado."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [], [plugin_id], msg, []

        return True, [], [], None, matching_vulns

    elif scope == "MATRIX_NN":
        clean_host_ips = list(dict.fromkeys([str(ip).strip() for ip in (scope_host_ips or []) if str(ip).strip()]))
        clean_plugin_ids = list(dict.fromkeys([str(p).strip() for p in (scope_plugin_ids or []) if str(p).strip()]))

        if not latest_scan_ids:
            msg = "Plano de Ação inválido / não relacional: Informe ao menos um IP de host no escopo matricial ou selecione plugins com ocorrências ativas na importação mais recente do Grupo de Ativos."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, clean_host_ips, clean_plugin_ids, msg, []

        # Auto-resolução: se hosts não foram informados na Etapa 2, mas plugins foram informados no Grupo de Ativos
        if not clean_host_ips and target_gids and clean_plugin_ids:
            auto_hosts = db.query(models.Host.ip_address).join(
                models.Vulnerability, models.Vulnerability.host_id == models.Host.id
            ).filter(
                models.Vulnerability.asset_group_id.in_(target_gids),
                models.Vulnerability.plugin_id.in_(clean_plugin_ids),
                models.Vulnerability.scan_id.in_(latest_scan_ids),
                ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
                allowed_status_clause
            ).distinct().all()
            clean_host_ips = [h[0] for h in auto_hosts]

        if not clean_host_ips:
            msg = "Plano de Ação inválido / não relacional: Informe ao menos um IP de host no escopo matricial ou selecione plugins com ocorrências ativas na importação mais recente do Grupo de Ativos."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [], [], msg, []

        # 1. Verificar se os hosts existem no inventário
        found_hosts = db.query(models.Host).filter(models.Host.ip_address.in_(clean_host_ips)).all()
        found_ips_set = set(h.ip_address for h in found_hosts)
        missing_ips = [ip for ip in clean_host_ips if ip not in found_ips_set]
        if missing_ips:
            msg = f"Plano de Ação inválido / não relacional: Os seguintes hosts não foram encontrados no inventário de ativos: {', '.join(sorted(missing_ips))}."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, missing_ips, [], msg, []

        # 2. Verificar se todos os hosts pertencem ao grupo selecionado (se informado)
        if target_gids:
            ips_in_target_group = set(h.ip_address for h in found_hosts if h.asset_group_id in target_gids)
            out_of_group = [ip for ip in clean_host_ips if ip not in ips_in_target_group]
            if out_of_group:
                msg = f"Plano de Ação inválido / não relacional: Os seguintes hosts não pertencem ao Grupo de Ativos selecionado ou aos seus subgrupos: {', '.join(sorted(out_of_group))}."
                if strict_raise:
                    raise HTTPException(status_code=422, detail=msg)
                return False, out_of_group, [], msg, []

        # Se não foram fornecidos plugins específicos, seleciona todas as vulnerabilidades ativas dos hosts informados NO SCAN MAIS RECENTE
        if not clean_plugin_ids:
            mq_all = db.query(models.Vulnerability).join(
                models.Host, models.Vulnerability.host_id == models.Host.id
            ).filter(
                models.Host.ip_address.in_(clean_host_ips),
                models.Vulnerability.scan_id.in_(latest_scan_ids),
                ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
                allowed_status_clause
            )
            if target_gids:
                mq_all = mq_all.filter(models.Vulnerability.asset_group_id.in_(target_gids))

            matching_vulns = mq_all.all()
            covered_hosts = set(v.host.ip_address for v in matching_vulns if v.host)
            unmatched_hosts = [ip for ip in clean_host_ips if ip not in covered_hosts]

            if not matching_vulns or unmatched_hosts:
                critiques = []
                if unmatched_hosts:
                    critiques.append(f"Hosts sem nenhuma vulnerabilidade ativa na importação mais recente: {', '.join(sorted(unmatched_hosts))}")
                msg = f"Plano de Ação inválido / não relacional: Os hosts selecionados devem possuir ao menos uma vulnerabilidade ativa na importação mais recente. {'; '.join(critiques)}."
                if strict_raise:
                    raise HTTPException(status_code=422, detail=msg)
                return False, unmatched_hosts, [], msg, matching_vulns

            return True, [], [], None, matching_vulns

        # 3. Consultar vulnerabilidades no cruzamento N:M NO SCAN MAIS RECENTE
        mq = db.query(models.Vulnerability).join(
            models.Host, models.Vulnerability.host_id == models.Host.id
        ).filter(
            models.Host.ip_address.in_(clean_host_ips),
            models.Vulnerability.plugin_id.in_(clean_plugin_ids),
            models.Vulnerability.scan_id.in_(latest_scan_ids),
            ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
            allowed_status_clause
        )
        if target_gids:
            mq = mq.filter(models.Vulnerability.asset_group_id.in_(target_gids))

        matching_vulns = mq.all()

        # 4. Avaliar cobertura bipartida estrita
        covered_hosts = set(v.host.ip_address for v in matching_vulns if v.host)
        unmatched_hosts = [ip for ip in clean_host_ips if ip not in covered_hosts]

        covered_plugins = set(str(v.plugin_id) for v in matching_vulns)
        unmatched_plugins = [p for p in clean_plugin_ids if p not in covered_plugins]

        if unmatched_hosts or unmatched_plugins:
            critiques = []
            if unmatched_hosts:
                critiques.append(f"Hosts sem nenhuma das vulnerabilidades selecionadas na importação mais recente: {', '.join(sorted(unmatched_hosts))}")
            if unmatched_plugins:
                critiques.append(f"Plugin IDs não vinculados a nenhum dos hosts na importação mais recente: {', '.join(sorted(unmatched_plugins))}")
            msg = f"Plano de Ação inválido / não relacional: Cada host deve possuir ao menos uma vulnerabilidade associada e cada plugin deve afetar ao menos um host na importação mais recente. {'; '.join(critiques)}."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, unmatched_hosts, unmatched_plugins, msg, matching_vulns

        return True, [], [], None, matching_vulns

    elif scope == "GROUP":
        if not asset_group_id:
            msg = "Plano de Ação inválido: Selecione um Grupo de Ativos para planos com escopo de Grupo."
            if strict_raise:
                raise HTTPException(status_code=422, detail=msg)
            return False, [], [], msg, []

        matching_vulns = []
        if latest_scan_ids:
            g_query = db.query(models.Vulnerability).filter(
                models.Vulnerability.asset_group_id.in_(target_gids),
                models.Vulnerability.scan_id.in_(latest_scan_ids),
                models.Vulnerability.severity.in_(["Critical", "critical", "High", "high"]),
                ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
                allowed_status_clause
            ).limit(200)
            matching_vulns = g_query.all()
        return True, [], [], None, matching_vulns

    # CUSTOM ou outros escopos manuais
    return True, [], [], None, []


@router.post("/preview-impact", response_model=schemas.ActionPlanPreviewImpactOut)
def preview_action_plan_impact(
    data: schemas.ActionPlanPreviewImpactIn,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Calcula em tempo real a abrangência e impacto de um plano de ação antes de sua criação/salvamento:
    Total de vulnerabilidades alcançadas por severidade, total de hosts envolvidos,
    quantas já estão vinculadas a outros planos e validação relacional estrita.
    """
    is_valid, unmatched_h, unmatched_p, val_msg, matching_vulns = validate_action_plan_relational_scope(
        db=db,
        scope_type=data.scope_type,
        asset_group_id=data.asset_group_id,
        target_host_id=data.target_host_id,
        target_host_ip=data.target_host_ip,
        target_plugin_id=data.target_plugin_id,
        scope_host_ips=data.scope_host_ips,
        scope_plugin_ids=data.scope_plugin_ids,
        strict_raise=False,
        plan_id=data.plan_id
    )

    if not matching_vulns:
        return schemas.ActionPlanPreviewImpactOut(
            total_affected_vulns=0,
            total_affected_hosts=0,
            total_vulnerabilities=0,
            unique_hosts_count=0,
            unique_plugins_count=0,
            is_relational_valid=is_valid,
            unmatched_hosts=unmatched_h,
            unmatched_plugins=unmatched_p,
            validation_message=val_msg
        )

    m_vuln_ids = [v.id for v in matching_vulns]
    host_ids = set(v.host_id for v in matching_vulns)

    # Contagem de já em plano
    assigned_count = db.query(func.count(models.ActionTaskVulnerabilityLink.vulnerability_id.distinct())).join(
        models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
    ).join(
        models.ActionPlan, models.ActionTask.action_plan_id == models.ActionPlan.id
    ).filter(
        models.ActionTaskVulnerabilityLink.vulnerability_id.in_(m_vuln_ids),
        models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
    ).scalar() or 0

    crit = sum(1 for v in matching_vulns if (v.severity or "").lower() == "critical")
    high = sum(1 for v in matching_vulns if (v.severity or "").lower() == "high")
    med = sum(1 for v in matching_vulns if (v.severity or "").lower() == "medium")
    low = sum(1 for v in matching_vulns if (v.severity or "").lower() == "low")

    total = len(matching_vulns)
    unassigned = max(0, total - assigned_count)
    plugin_ids = set(v.plugin_id for v in matching_vulns)

    return schemas.ActionPlanPreviewImpactOut(
        total_affected_vulns=total,
        total_affected_hosts=len(host_ids),
        total_vulnerabilities=total,
        unique_hosts_count=len(host_ids),
        unique_plugins_count=len(plugin_ids),
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        severity_distribution={
            "Critical": crit,
            "High": high,
            "Medium": med,
            "Low": low,
        },
        already_in_plan_count=assigned_count,
        unassigned_count=unassigned,
        is_relational_valid=is_valid,
        unmatched_hosts=unmatched_h,
        unmatched_plugins=unmatched_p,
        validation_message=val_msg
    )


@router.get("/{plan_id}", response_model=schemas.ActionPlanOut)
def get_action_plan_details(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Obtém os detalhes completos de um plano de ação, suas etapas e vínculos com vulnerabilidades.
    """
    p = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Plano de Ação não encontrado.")
    check_gid = p.asset_group_id or (p.target_host.asset_group_id if p.target_host else None)
    if check_gid:
        check_user_group_access(db, current_user, check_gid, action="view")
    return format_plan_out(p, utc_now())


@router.post("", response_model=schemas.ActionPlanOut)
def create_action_plan(
    data: schemas.ActionPlanCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Cria um novo Plano de Ação (GvulStand Action Plans).
    Suporta escopos por Host, por Vulnerabilidade (Plugin), por Grupo, Matricial (MATRIX_NN) ou Customizado.
    Valida estritamente a integridade relacional de hosts e vulnerabilidades.
    """
    if data.asset_group_id:
        check_user_group_access(db, current_user, data.asset_group_id, action="treat")

    # Resolver target_host inicial se informado por IP ou ID
    target_host = None
    if data.target_host_id:
        target_host = db.query(models.Host).filter(models.Host.id == data.target_host_id).first()
    if not target_host and data.target_host_ip:
        target_ip_clean = data.target_host_ip.strip()
        candidate_hosts = db.query(models.Host).filter(models.Host.ip_address == target_ip_clean).order_by(models.Host.id.desc()).all()
        for ch in candidate_hosts:
            has_act = db.query(models.Vulnerability.id).filter(
                models.Vulnerability.host_id == ch.id,
                ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
                ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated", "Accepted_Risk", "accepted_risk"])
            ).first()
            if has_act:
                target_host = ch
                break
        if not target_host and candidate_hosts:
            target_host = candidate_hosts[0]

    if target_host:
        data.target_host_id = target_host.id
        if not data.asset_group_id and target_host.asset_group_id:
            data.asset_group_id = target_host.asset_group_id

    # Validação relacional estrita (levanta HTTP 422 se inválido)
    is_valid, _, _, _, matching_vulns = validate_action_plan_relational_scope(
        db=db,
        scope_type=data.scope_type,
        asset_group_id=data.asset_group_id,
        target_host_id=data.target_host_id,
        target_host_ip=data.target_host_ip,
        target_plugin_id=data.target_plugin_id,
        scope_host_ips=data.scope_host_ips,
        scope_plugin_ids=data.scope_plugin_ids,
        strict_raise=True,
        plan_id=None
    )

    plan = models.ActionPlan(
        title=data.title.strip(),
        description=data.description.strip() if data.description else None,
        asset_group_id=data.asset_group_id,
        scope_type=data.scope_type.upper(),
        target_host_id=data.target_host_id,
        target_plugin_id=data.target_plugin_id.strip() if data.target_plugin_id else None,
        priority=data.priority.upper(),
        status=data.status.upper(),
        created_by_username=current_user.username,
        owner_user_id=data.owner_user_id or current_user.id,
        due_date=data.due_date
    )
    db.add(plan)
    db.flush()

    # Sync Tags & Matrix Scope
    sync_action_plan_tags(db, plan, data.tags)
    actual_plugin_ids = data.scope_plugin_ids
    actual_host_ips = data.scope_host_ips
    if plan.scope_type == "MATRIX_NN" and matching_vulns:
        if not actual_plugin_ids:
            actual_plugin_ids = list(dict.fromkeys(str(v.plugin_id) for v in matching_vulns if v.plugin_id))
        if not actual_host_ips:
            actual_host_ips = list(dict.fromkeys(str(v.host.ip_address) for v in matching_vulns if v.host and v.host.ip_address))
    sync_action_plan_matrix_scope(db, plan, actual_host_ips, actual_plugin_ids)

    # Create initial tasks if provided
    is_host_scope = plan.scope_type in ["HOST", "MATRIX_NN"]
    if data.initial_tasks:
        for idx, t_data in enumerate(data.initial_tasks):
            task = models.ActionTask(
                action_plan_id=plan.id,
                title=t_data.title.strip(),
                description=t_data.description.strip() if t_data.description else None,
                order_index=t_data.order_index or idx,
                status=t_data.status.upper(),
                assigned_user_id=t_data.assigned_user_id or plan.owner_user_id,
                start_date=t_data.start_date,
                due_date=t_data.due_date or plan.due_date
            )
            db.add(task)
            db.flush()
            if t_data.vulnerability_ids:
                link_vulns_to_task_with_precedence(db, task, t_data.vulnerability_ids, current_user.username, is_host_scope)

        if data.auto_link_vulnerabilities and matching_vulns and plan.tasks:
            already_linked_ids = set(
                link.vulnerability_id
                for tk in (plan.tasks or [])
                for link in (tk.vulnerability_links or [])
            )
            remaining_vulns = [v for v in matching_vulns if v.id not in already_linked_ids]
            if remaining_vulns:
                link_vulns_to_task_with_precedence(db, plan.tasks[0], [v.id for v in remaining_vulns], current_user.username, is_host_scope)
    else:
        # Geração automática de tarefas conforme especificação:
        # - Escopo baseado em Host: 1 tarefa para cada host.
        # - Escopo MATRIX_NN (com plugins) ou VULNERABILITY: 1 tarefa para cada grupo HOST+VULNERABILIDADE.
        # - Título da tarefa: hostname/ip. Abaixo (descrição): nome da vulnerabilidade.
        if data.auto_link_vulnerabilities and matching_vulns:
            scope_plugin_ids_explicit = bool(data.scope_plugin_ids and any(str(p).strip() for p in data.scope_plugin_ids))
            generate_action_plan_tasks(
                db=db,
                plan=plan,
                matching_vulns=matching_vulns,
                current_username=current_user.username,
                scope_plugin_ids_explicit=scope_plugin_ids_explicit
            )
        else:
            task = models.ActionTask(
                action_plan_id=plan.id,
                title="Planejamento e Execução da Remediação",
                description=f"Iniciativa de remediação estruturada no escopo {plan.scope_type}.",
                order_index=0,
                status="TODO",
                assigned_user_id=plan.owner_user_id,
                due_date=plan.due_date
            )
            db.add(task)
            db.flush()

    db.commit()
    db.refresh(plan)
    return format_plan_out(plan, utc_now())


@router.put("/{plan_id}", response_model=schemas.ActionPlanOut)
def update_action_plan(
    plan_id: int,
    data: schemas.ActionPlanUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Atualiza metadados, prazos, prioridade, tags, escopo ou status de um plano de ação.
    """
    p = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Plano de Ação não encontrado.")
    if p.asset_group_id:
        check_user_group_access(db, current_user, p.asset_group_id, action="treat")

    # Se algum campo de escopo for alterado, validar estritamente a nova combinação
    scope_fields_modified = (
        data.scope_type is not None or
        data.scope_host_ips is not None or
        data.scope_plugin_ids is not None or
        data.target_host_id is not None or
        data.target_host_ip is not None or
        data.target_plugin_id is not None or
        data.asset_group_id is not None
    )
    matching_vulns = []
    if scope_fields_modified:
        new_scope = (data.scope_type or p.scope_type).upper()
        new_asset_group = data.asset_group_id if data.asset_group_id is not None else p.asset_group_id
        new_host_id = data.target_host_id if data.target_host_id is not None else p.target_host_id
        new_host_ip = data.target_host_ip if data.target_host_ip is not None else None
        new_plugin_id = data.target_plugin_id if data.target_plugin_id is not None else p.target_plugin_id
        new_host_ips = data.scope_host_ips if data.scope_host_ips is not None else [h.host_ip for h in p.scope_hosts]
        new_plugin_ids = data.scope_plugin_ids if data.scope_plugin_ids is not None else [pl.plugin_id for pl in p.scope_plugins]

        is_valid, _, _, _, matching_vulns = validate_action_plan_relational_scope(
            db=db,
            scope_type=new_scope,
            asset_group_id=new_asset_group,
            target_host_id=new_host_id,
            target_host_ip=new_host_ip,
            target_plugin_id=new_plugin_id,
            scope_host_ips=new_host_ips,
            scope_plugin_ids=new_plugin_ids,
            strict_raise=True,
            plan_id=p.id
        )

    if data.title is not None:
        p.title = data.title.strip()
    if data.description is not None:
        p.description = data.description.strip() if data.description else None
    if data.asset_group_id is not None:
        p.asset_group_id = data.asset_group_id
    if data.scope_type is not None:
        p.scope_type = data.scope_type.upper()
    if data.target_host_id is not None or data.target_host_ip is not None:
        target_h = None
        if data.target_host_id:
            target_h = db.query(models.Host).filter(models.Host.id == data.target_host_id).first()
        if not target_h and data.target_host_ip:
            target_ip_clean = data.target_host_ip.strip()
            candidate_hosts = db.query(models.Host).filter(models.Host.ip_address == target_ip_clean).order_by(models.Host.id.desc()).all()
            for ch in candidate_hosts:
                has_act = db.query(models.Vulnerability.id).filter(
                    models.Vulnerability.host_id == ch.id,
                    ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
                    ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated", "Accepted_Risk"])
                ).first()
                if has_act:
                    target_h = ch
                    break
            if not target_h and candidate_hosts:
                target_h = candidate_hosts[0]
        p.target_host_id = target_h.id if target_h else None
    if data.target_plugin_id is not None:
        p.target_plugin_id = data.target_plugin_id
    if data.priority is not None:
        p.priority = data.priority.upper()
    if data.owner_user_id is not None:
        p.owner_user_id = data.owner_user_id
    if data.due_date is not None:
        p.due_date = data.due_date

    # Status change handling
    if data.status is not None:
        new_status = data.status.upper()
        if new_status != p.status:
            p.status = new_status
            if new_status == "CANCELLED":
                # Reverter vulnerabilidades vinculadas para Open se órfãs
                linked_v_ids = list(set(
                    link.vulnerability_id
                    for tk in (p.tasks or [])
                    for link in (tk.vulnerability_links or [])
                    if link.vulnerability_id
                ))
                if linked_v_ids:
                    canc_reason = f"Retornado para status inicial (Open) devido ao cancelamento do Plano de Ação '{p.title}' (ID #{p.id})."
                    revert_orphaned_vulns_to_open(db, linked_v_ids, current_user.username, reason=canc_reason)

    # Sync tags and matrix scope if provided
    if data.tags is not None:
        sync_action_plan_tags(db, p, data.tags)

    if scope_fields_modified:
        actual_plugin_ids = data.scope_plugin_ids if data.scope_plugin_ids is not None else [pl.plugin_id for pl in p.scope_plugins]
        actual_host_ips = data.scope_host_ips if data.scope_host_ips is not None else [h.host_ip for h in p.scope_hosts]
        if p.scope_type == "MATRIX_NN" and matching_vulns:
            if not actual_plugin_ids:
                actual_plugin_ids = list(dict.fromkeys(str(v.plugin_id) for v in matching_vulns if v.plugin_id))
            if not actual_host_ips:
                actual_host_ips = list(dict.fromkeys(str(v.host.ip_address) for v in matching_vulns if v.host and v.host.ip_address))
        sync_action_plan_matrix_scope(db, p, actual_host_ips, actual_plugin_ids)

        scope_plugin_ids_explicit = bool(actual_plugin_ids and any(str(pl).strip() for pl in actual_plugin_ids))
        sync_action_plan_tasks_on_scope_update(
            db=db,
            plan=p,
            matching_vulns=matching_vulns,
            current_username=current_user.username,
            scope_plugin_ids_explicit=scope_plugin_ids_explicit
        )

    p.updated_at = utc_now()
    db.commit()
    db.refresh(p)
    return format_plan_out(p, utc_now())


@router.delete("/{plan_id}")
def delete_action_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Exclui um plano de ação e todas as suas etapas associadas.
    Permitido para Administradores ou o Analista criador do plano.
    Reverte vulnerabilidades associadas para 'Open' caso não possuam outro plano ativo,
    registrando no log de auditoria que o plano foi excluído com título e ID.
    """
    p = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Plano de Ação não encontrado.")

    if current_user.role != "admin" and p.created_by_username != current_user.username:
        raise HTTPException(status_code=403, detail="Apenas administradores ou o usuário criador podem excluir este plano de ação.")

    plan_title = p.title
    plan_id_val = p.id

    # Coletar todas as vulnerabilidades vinculadas às tarefas do plano
    linked_v_ids = list(set(
        link.vulnerability_id
        for tk in (p.tasks or [])
        for link in (tk.vulnerability_links or [])
        if link.vulnerability_id
    ))

    # Excluir o plano de ação (cascata para tasks e links)
    db.delete(p)
    db.flush()

    # Reverter vulnerabilidades órfãs para Open com mensagem explícita de exclusão
    if linked_v_ids:
        del_reason = f"Retornado para status inicial (Open) devido à exclusão do Plano de Ação '{plan_title}' (ID #{plan_id_val})."
        revert_orphaned_vulns_to_open(db, linked_v_ids, current_user.username, reason=del_reason)

    db.commit()

    logger.info(
        f"Plano de Ação #{plan_id_val} ('{plan_title}') foi excluído pelo usuário '{current_user.username}'. "
        f"{len(linked_v_ids)} vulnerabilidades verificadas para reversão ao status inicial (Open)."
    )

    return {"message": f"Plano de Ação #{plan_id_val} ('{plan_title}') removido com sucesso."}


@router.post("/{plan_id}/tasks", response_model=schemas.ActionTaskOut)
def add_action_task(
    plan_id: int,
    data: schemas.ActionTaskCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Adiciona uma nova etapa/tarefa a um plano de ação existente.
    """
    p = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Plano de Ação não encontrado.")
    if p.asset_group_id:
        check_user_group_access(db, current_user, p.asset_group_id, action="treat")

    # Order index calculation
    max_order = db.query(func.coalesce(func.max(models.ActionTask.order_index), 0)).filter(
        models.ActionTask.action_plan_id == plan_id
    ).scalar()

    task = models.ActionTask(
        action_plan_id=plan_id,
        title=data.title.strip(),
        description=data.description.strip() if data.description else None,
        order_index=data.order_index if data.order_index != 0 else (max_order + 1),
        status=data.status.upper(),
        assigned_user_id=data.assigned_user_id or p.owner_user_id,
        start_date=data.start_date,
        due_date=data.due_date or p.due_date
    )
    db.add(task)
    db.flush()

    if data.vulnerability_ids:
        is_host_scope = p.scope_type in ["HOST", "MATRIX_NN"]
        link_vulns_to_task_with_precedence(db, task, data.vulnerability_ids, current_user.username, is_host_scope)

    p.updated_at = utc_now()
    db.commit()
    db.refresh(task)
    return format_task_out(task, utc_now())


@router.put("/tasks/{task_id}", response_model=schemas.ActionTaskOut)
def update_action_task(
    task_id: int,
    data: schemas.ActionTaskUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Atualiza uma etapa/tarefa: status (TODO, DOING, REVIEW, DONE, BLOCKED), prazos e responsável.
    Permitido para Administradores, Analistas ou o Responsável direto pela tarefa.
    Sincroniza automaticamente o status de remediação das vulnerabilidades vinculadas (ISO 27001).
    """
    t = db.query(models.ActionTask).filter(models.ActionTask.id == task_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada.")

    # Permissions check: Admin, Analyst with group access, or Task Assignee
    is_admin = current_user.role == "admin"
    is_assignee = t.assigned_user_id == current_user.id
    is_analyst = current_user.role == "analyst"

    if not (is_admin or is_assignee or is_analyst):
        raise HTTPException(status_code=403, detail="Sem permissão para atualizar esta tarefa.")

    now = utc_now()

    if data.title is not None and (is_admin or is_analyst):
        t.title = data.title.strip()
    if data.description is not None and (is_admin or is_analyst):
        t.description = data.description.strip() if data.description else None
    if data.order_index is not None and (is_admin or is_analyst):
        t.order_index = data.order_index
    if data.assigned_user_id is not None and (is_admin or is_analyst):
        t.assigned_user_id = data.assigned_user_id
    if data.start_date is not None and (is_admin or is_analyst):
        t.start_date = data.start_date
    if data.due_date is not None and (is_admin or is_analyst):
        t.due_date = data.due_date

    # Status update and treatment sync
    if data.status is not None:
        new_status = data.status.upper()
        if new_status != t.status:
            t.status = new_status
            if new_status == "DONE":
                t.completed_at = now
            else:
                t.completed_at = None

            # Automatic transition of linked vulnerabilities based on task execution stage
            if new_status == "DOING":
                for link in t.vulnerability_links:
                    v = link.vulnerability
                    if v and v.treatment_status in ["Open", "In_Action_Plan"]:
                        v.treatment_status = "In_Remediation"
                        v.treated_by_username = current_user.username
                        v.treated_at = now
                        hist = models.VulnerabilityTreatmentHistory(
                            vulnerability_id=v.id,
                            treatment_status="In_Remediation",
                            treatment_notes=f"Tratativa iniciada via Plano de Ação #{t.action_plan_id} (Etapa '{t.title}' em execução).",
                            changed_by_username=current_user.username,
                            changed_at=now
                        )
                        db.add(hist)
            elif new_status == "DONE":
                for link in t.vulnerability_links:
                    v = link.vulnerability
                    if v and v.treatment_status != "Remediated":
                        v.treatment_status = "Remediated"
                        v.treated_by_username = current_user.username
                        v.treated_at = now
                        hist = models.VulnerabilityTreatmentHistory(
                            vulnerability_id=v.id,
                            treatment_status="Remediated",
                            treatment_notes=f"Tratativa concluída via Plano de Ação #{t.action_plan_id} (Etapa '{t.title}' finalizada).",
                            changed_by_username=current_user.username,
                            changed_at=now
                        )
                        db.add(hist)

    # Manual sync request
    if data.sync_vuln_treatment and t.status != "DONE" and t.status != "DOING":
        for link in t.vulnerability_links:
            v = link.vulnerability
            if v and v.treatment_status != "Remediated":
                v.treatment_status = "In_Remediation"
                v.treated_by_username = current_user.username
                v.treated_at = now
                hist = models.VulnerabilityTreatmentHistory(
                    vulnerability_id=v.id,
                    treatment_status="In_Remediation",
                    treatment_notes=f"Tratativa sincronizada via Plano de Ação #{t.action_plan_id} (Etapa: {t.title}).",
                    changed_by_username=current_user.username,
                    changed_at=now
                )
                db.add(hist)

    # Vulnerability links update
    if data.vulnerability_ids is not None and (is_admin or is_analyst):
        old_ids = [link.vulnerability_id for link in (t.vulnerability_links or [])]
        new_ids = set(data.vulnerability_ids)
        removed_ids = [vid for vid in old_ids if vid not in new_ids]

        db.query(models.ActionTaskVulnerabilityLink).filter(
            models.ActionTaskVulnerabilityLink.action_task_id == t.id
        ).delete()
        db.flush()

        is_host_scope = t.action_plan.scope_type in ["HOST", "MATRIX_NN"] if t.action_plan else False
        link_vulns_to_task_with_precedence(db, t, list(new_ids), current_user.username, is_host_scope)

        if removed_ids:
            revert_orphaned_vulns_to_open(db, removed_ids, current_user.username)

    t.updated_at = now
    if t.action_plan:
        t.action_plan.updated_at = now

        # Auto-update plan status to COMPLETED if all tasks are DONE
        all_tasks = t.action_plan.tasks or []
        if all_tasks and all(tk.status == "DONE" for tk in all_tasks):
            t.action_plan.status = "COMPLETED"
        elif t.action_plan.status == "PLANNED" and t.status in ["DOING", "REVIEW", "DONE"]:
            t.action_plan.status = "IN_PROGRESS"

    db.commit()
    db.refresh(t)
    return format_task_out(t, now)


@router.delete("/tasks/{task_id}")
def delete_action_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Remove uma etapa/tarefa de um plano de ação e reverte vulnerabilidades órfãs para 'Open'.
    """
    t = db.query(models.ActionTask).filter(models.ActionTask.id == task_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada.")

    linked_v_ids = [link.vulnerability_id for link in (t.vulnerability_links or [])]
    plan = t.action_plan
    db.delete(t)
    if plan:
        plan.updated_at = utc_now()
    db.commit()

    if linked_v_ids:
        revert_orphaned_vulns_to_open(db, linked_v_ids, current_user.username)
        db.commit()

    return {"message": f"Tarefa #{task_id} removida com sucesso."}

