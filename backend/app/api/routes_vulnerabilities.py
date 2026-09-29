import re
import math
from datetime import datetime, timezone
from typing import List, Optional, Union, Set
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, require_analyst_or_admin, check_user_group_access, get_user_allowed_group_ids
from app.services.scan_service import get_latest_scan_ids
from app.services.parameter_service import apply_indicator_exclusion, get_ignored_ids_set

router = APIRouter(prefix="/vulnerabilities", tags=["Gestão e Exploração de Vulnerabilidades"])

def calculate_aging_days(v: models.Vulnerability) -> int:
    ref = v.first_found or v.created_at
    if not ref:
        return 0
    if ref.tzinfo is not None:
        now = datetime.now(timezone.utc)
    else:
        now = datetime.utcnow()
    diff = (now - ref).days
    return max(0, diff)

def format_vuln_out(v: models.Vulnerability, ignored_ids: Optional[Set[str]] = None) -> schemas.VulnerabilityOut:
    out = schemas.VulnerabilityOut.model_validate(v)
    out.host_ip = v.host.ip_address if v.host else ""
    out.host_name = v.host.hostname if v.host else ""
    out.asset_group_name = v.asset_group.name if v.asset_group else ""
    out.aging_days = calculate_aging_days(v)
    out.treated_by_username = v.treated_by_username
    out.treated_at = v.treated_at
    out.first_found = v.first_found
    out.last_found = v.last_found
    cves = [c.strip() for c in re.findall(r"CVE-\d{4}-\d{4,7}", v.cve or "", re.IGNORECASE)] if v.cve else []
    out.cve_list = cves
    out.cve_count = len(cves)
    if ignored_ids is not None:
        out.is_ignored_in_indicators = (v.plugin_id in ignored_ids) or (str(v.id) in ignored_ids)
    return out

def populate_vuln_active_plans(vuln_items: List[schemas.VulnerabilityOut], db: Session):
    if not vuln_items:
        return
    v_ids = [v.id for v in vuln_items]
    links = db.query(
        models.ActionTaskVulnerabilityLink.vulnerability_id,
        models.ActionPlan.id,
        models.ActionPlan.title
    ).join(
        models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
    ).join(
        models.ActionPlan, models.ActionTask.action_plan_id == models.ActionPlan.id
    ).filter(
        models.ActionTaskVulnerabilityLink.vulnerability_id.in_(v_ids),
        models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
    ).all()
    plan_map = {row[0]: (row[1], row[2]) for row in links}
    for item in vuln_items:
        if item.id in plan_map:
            item.active_action_plan_id, item.active_action_plan_title = plan_map[item.id]

def populate_host_active_plans(host_items: List[schemas.HostOut], db: Session):
    if not host_items:
        return
    h_ids = [h.id for h in host_items]
    h_ips = [h.ip_address for h in host_items]
    direct = db.query(
        models.ActionPlan.target_host_id,
        models.ActionPlan.id,
        models.ActionPlan.title
    ).filter(
        models.ActionPlan.target_host_id.in_(h_ids),
        models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
    ).all()
    plan_map = {row[0]: (row[1], row[2]) for row in direct}

    matrix = db.query(
        models.ActionPlanHost.host_ip,
        models.ActionPlan.id,
        models.ActionPlan.title
    ).join(
        models.ActionPlan, models.ActionPlanHost.action_plan_id == models.ActionPlan.id
    ).filter(
        models.ActionPlanHost.host_ip.in_(h_ips),
        models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
    ).all()
    matrix_map = {row[0]: (row[1], row[2]) for row in matrix}

    for item in host_items:
        if item.id in plan_map:
            item.active_action_plan_id, item.active_action_plan_title = plan_map[item.id]
        elif item.ip_address in matrix_map:
            item.active_action_plan_id, item.active_action_plan_title = matrix_map[item.ip_address]

@router.get("", response_model=Union[schemas.PaginatedVulnerabilitiesOut, List[schemas.VulnerabilityOut]])
def list_vulnerabilities(
    asset_group_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    host_id: Optional[int] = None,
    host: Optional[str] = None,
    severity: Optional[str] = None,
    exclude_info: bool = False,
    exploit_only: bool = False,
    has_exploit: Optional[str] = None,
    treatment_status: Optional[str] = None,
    not_in_action_plan: bool = False,
    search: Optional[str] = None,
    exclude_ignored: bool = False,
    page: Optional[int] = None,
    page_size: int = Query(50, le=200),
    limit: Optional[int] = Query(None, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Lista e filtra vulnerabilidades detalhadas na base de dados com suporte a paginação completa,
    filtro por host/IP específico, informações de aging e auditoria.
    """
    query = db.query(models.Vulnerability)\
        .join(models.Host, models.Vulnerability.host_id == models.Host.id)\
        .join(models.AssetGroup, models.Vulnerability.asset_group_id == models.AssetGroup.id)

    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    if allowed_ids is not None:
        if asset_group_id:
            check_user_group_access(db, current_user, asset_group_id, action="view")
        else:
            query = query.filter(models.Vulnerability.asset_group_id.in_(allowed_ids))

    if host_id:
        query = query.filter(models.Vulnerability.host_id == host_id)
    elif scan_id:
        query = query.filter(models.Vulnerability.scan_id == scan_id)
    else:
        active_scan_ids = get_latest_scan_ids(db, asset_group_id)
        if not active_scan_ids:
            if page is not None:
                return schemas.PaginatedVulnerabilitiesOut(
                    items=[],
                    total=0,
                    page=1,
                    page_size=page_size,
                    total_pages=1
                )
            return []
        query = query.filter(models.Vulnerability.scan_id.in_(active_scan_ids))

    # Specific Host/IP filter
    if host:
        host_clean = host.strip()
        if host_clean:
            host_term = f"%{host_clean}%"
            query = query.filter(
                (models.Host.ip_address.ilike(host_term)) |
                (models.Host.hostname.ilike(host_term))
            )

    if severity:
        query = query.filter(models.Vulnerability.severity == severity)
    elif exclude_info:
        query = query.filter(models.Vulnerability.severity.notin_(["Info", "None", "none", "info"]))
    
    # Filter by exploit (SIM / NÃO / Todos)
    if has_exploit is not None and has_exploit != "":
        if str(has_exploit).lower() in ("true", "1", "yes", "sim"):
            query = query.filter(models.Vulnerability.exploit_available == True)
        elif str(has_exploit).lower() in ("false", "0", "no", "nao", "não"):
            query = query.filter(models.Vulnerability.exploit_available == False)
    elif exploit_only:
        query = query.filter(models.Vulnerability.exploit_available == True)
    if treatment_status:
        query = query.filter(models.Vulnerability.treatment_status == treatment_status)
    if not_in_action_plan:
        assigned_subq = db.query(models.ActionTaskVulnerabilityLink.vulnerability_id).join(
            models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
        ).join(
            models.ActionPlan, models.ActionTask.action_plan_id == models.ActionPlan.id
        ).filter(
            models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
        ).distinct()
        query = query.filter(
            models.Vulnerability.treatment_status.in_(["Open", "open"]),
            ~models.Vulnerability.id.in_(assigned_subq)
        )
    if search:
        term = f"%{search}%"
        query = query.filter(
            (models.Vulnerability.plugin_name.ilike(term)) |
            (models.Vulnerability.cve.ilike(term)) |
            (models.Vulnerability.plugin_id.ilike(term)) |
            (models.Host.ip_address.ilike(term)) |
            (models.Host.hostname.ilike(term))
        )

    if exclude_ignored:
        query = apply_indicator_exclusion(query, db)

    ignored_ids = get_ignored_ids_set(db)

    # Order by Critical, then exploit, then CVSS
    ordered_query = query.order_by(
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
    )

    if page is not None:
        total = ordered_query.count()
        p = max(1, page)
        ps = max(1, min(page_size, 200))
        offset_val = (p - 1) * ps
        total_pages = max(1, math.ceil(total / ps))
        items_db = ordered_query.offset(offset_val).limit(ps).all()
        formatted_items = [format_vuln_out(v, ignored_ids) for v in items_db]
        populate_vuln_active_plans(formatted_items, db)
        return schemas.PaginatedVulnerabilitiesOut(
            items=formatted_items,
            total=total,
            page=p,
            page_size=ps,
            total_pages=total_pages
        )

    lim = limit if limit is not None else 100
    vulns = ordered_query.offset(offset).limit(lim).all()
    formatted_vulns = [format_vuln_out(v, ignored_ids) for v in vulns]
    populate_vuln_active_plans(formatted_vulns, db)
    return formatted_vulns

@router.get("/unique-hosts", response_model=List[dict])
def get_unique_hosts(
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Retorna lista de hosts únicos (IP e hostname) para autocomplete nos filtros."""
    active_scan_ids = get_latest_scan_ids(db, asset_group_id)
    if not active_scan_ids:
        return []
    hosts = db.query(models.Host.id, models.Host.ip_address, models.Host.hostname)\
        .filter(models.Host.scan_id.in_(active_scan_ids))\
        .order_by(models.Host.ip_address)\
        .all()
    seen = set()
    result = []
    for h in hosts:
        if h.ip_address not in seen:
            seen.add(h.ip_address)
            result.append({
                "id": h.id,
                "ip": h.ip_address,
                "ip_address": h.ip_address,
                "hostname": h.hostname or ""
            })
    return result

@router.get("/inventory", response_model=schemas.PaginatedInventoryOut)
@router.get("/hosts", response_model=schemas.PaginatedInventoryOut)
def get_hosts_inventory(
    asset_group_id: Optional[int] = None,
    search: Optional[str] = None,
    severity_filter: Optional[str] = None,
    sort_by: str = "risk_score",
    sort_order: str = "desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna o inventário de hosts mapeados nos scans mais recentes por grupo de ativos,
    respeitando os filtros globais, com suporte a paginação, pesquisa e ordenação.
    Retorna IP, hostname, versão do SO, contadores de vulnerabilidades (Críticas, Altas, Médias, Baixas) e Risk Score.
    """
    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    if asset_group_id:
        if allowed_ids is not None:
            check_user_group_access(db, current_user, asset_group_id, action="view")
        active_scan_ids = get_latest_scan_ids(db, asset_group_id)
    else:
        if allowed_ids is not None:
            active_ids = []
            for gid in allowed_ids:
                active_ids.extend(get_latest_scan_ids(db, gid))
            active_scan_ids = active_ids
        else:
            active_scan_ids = get_latest_scan_ids(db, None)

    if not active_scan_ids:
        return schemas.PaginatedInventoryOut(
            items=[],
            total=0,
            page=page,
            page_size=page_size,
            total_pages=1,
            stats=schemas.InventoryStatsOut()
        )

    base_query = db.query(models.Host)\
        .join(models.AssetGroup, models.Host.asset_group_id == models.AssetGroup.id)\
        .filter(models.Host.scan_id.in_(active_scan_ids))

    if search:
        st = f"%{search.strip()}%"
        base_query = base_query.filter(
            (models.Host.ip_address.ilike(st)) |
            (models.Host.hostname.ilike(st)) |
            (models.Host.os.ilike(st)) |
            (models.AssetGroup.name.ilike(st))
        )

    if severity_filter:
        sev_clean = severity_filter.strip().lower()
        if sev_clean == "critical":
            base_query = base_query.filter(models.Host.critical_count > 0)
        elif sev_clean == "high":
            base_query = base_query.filter(models.Host.high_count > 0)
        elif sev_clean == "medium":
            base_query = base_query.filter(models.Host.medium_count > 0)
        elif sev_clean == "low":
            base_query = base_query.filter(models.Host.low_count > 0)
        elif sev_clean == "exploits":
            base_query = base_query.filter(models.Host.exploitable_critical_count > 0)

    # Compute overall stats matching the filters
    stats_query = db.query(
        func.count(models.Host.id).label("total_hosts"),
        func.coalesce(func.sum(models.Host.critical_count), 0).label("total_critical"),
        func.coalesce(func.sum(models.Host.high_count), 0).label("total_high"),
        func.coalesce(func.sum(models.Host.medium_count), 0).label("total_medium"),
        func.coalesce(func.sum(models.Host.low_count), 0).label("total_low"),
        func.coalesce(func.avg(models.Host.risk_score), 0.0).label("avg_risk_score"),
        func.coalesce(func.max(models.Host.risk_score), 0.0).label("max_risk_score"),
        func.coalesce(func.sum(case((models.Host.critical_count > 0, 1), else_=0)), 0).label("hosts_with_critical"),
        func.coalesce(func.sum(case((models.Host.exploitable_critical_count > 0, 1), else_=0)), 0).label("hosts_with_exploits")
    ).select_from(models.Host).join(models.AssetGroup, models.Host.asset_group_id == models.AssetGroup.id).filter(models.Host.scan_id.in_(active_scan_ids))

    if search:
        st = f"%{search.strip()}%"
        stats_query = stats_query.filter(
            (models.Host.ip_address.ilike(st)) |
            (models.Host.hostname.ilike(st)) |
            (models.Host.os.ilike(st)) |
            (models.AssetGroup.name.ilike(st))
        )
    if severity_filter:
        sev_clean = severity_filter.strip().lower()
        if sev_clean == "critical":
            stats_query = stats_query.filter(models.Host.critical_count > 0)
        elif sev_clean == "high":
            stats_query = stats_query.filter(models.Host.high_count > 0)
        elif sev_clean == "medium":
            stats_query = stats_query.filter(models.Host.medium_count > 0)
        elif sev_clean == "low":
            stats_query = stats_query.filter(models.Host.low_count > 0)
        elif sev_clean == "exploits":
            stats_query = stats_query.filter(models.Host.exploitable_critical_count > 0)

    stats_row = stats_query.first()
    total_hosts = stats_row.total_hosts if stats_row else 0
    total_crit = int(stats_row.total_critical) if stats_row else 0
    total_high = int(stats_row.total_high) if stats_row else 0
    total_med = int(stats_row.total_medium) if stats_row else 0
    total_low = int(stats_row.total_low) if stats_row else 0
    avg_risk = round(float(stats_row.avg_risk_score), 1) if stats_row else 0.0
    max_risk = round(float(stats_row.max_risk_score), 1) if stats_row else 0.0
    hosts_crit = int(stats_row.hosts_with_critical) if stats_row else 0
    hosts_exp = int(stats_row.hosts_with_exploits) if stats_row else 0

    stats_out = schemas.InventoryStatsOut(
        total_hosts=total_hosts,
        total_critical=total_crit,
        total_high=total_high,
        total_medium=total_med,
        total_low=total_low,
        total_vulns=total_crit + total_high + total_med + total_low,
        avg_risk_score=avg_risk,
        max_risk_score=max_risk,
        hosts_with_critical=hosts_crit,
        hosts_with_exploits=hosts_exp
    )

    sort_column_map = {
        "risk_score": models.Host.risk_score,
        "ip_address": models.Host.ip_address,
        "hostname": models.Host.hostname,
        "os": models.Host.os,
        "critical_count": models.Host.critical_count,
        "high_count": models.Host.high_count,
        "medium_count": models.Host.medium_count,
        "low_count": models.Host.low_count,
        "asset_group_name": models.AssetGroup.name
    }
    col = sort_column_map.get(sort_by, models.Host.risk_score)
    if sort_order.lower() == "asc":
        ordered_query = base_query.order_by(col.asc(), models.Host.id.asc())
    else:
        ordered_query = base_query.order_by(col.desc(), models.Host.id.desc())

    total = total_hosts
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    hosts = ordered_query.offset(offset).limit(page_size).all()

    items = []
    for h in hosts:
        item = schemas.HostOut.model_validate(h)
        item.asset_group_name = h.asset_group.name if h.asset_group else ""
        items.append(item)

    populate_host_active_plans(items, db)

    return schemas.PaginatedInventoryOut(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        stats=stats_out
    )

@router.get("/{vuln_id}", response_model=schemas.VulnerabilityOut)
def get_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Obtém detalhes completos de uma vulnerabilidade específica com histórico de tratativa."""
    v = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada.")
    out = format_vuln_out(v, get_ignored_ids_set(db))
    populate_vuln_active_plans([out], db)
    return out

@router.patch("/{vuln_id}/treatment", response_model=schemas.VulnerabilityOut)
def update_vulnerability_treatment(
    vuln_id: int,
    data: schemas.VulnerabilityStatusUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Atualiza o status de tratamento de uma vulnerabilidade (ISO 27001),
    registrando auditoria completa de QUEM realizou a tratativa e QUANDO.
    A nota de auditoria é obrigatória. Cada alteração gera um registro no histórico.
    """
    v = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada.")

    check_user_group_access(db, current_user, v.asset_group_id, action="treat")

    # Nota obrigatória
    if not data.treatment_notes or not data.treatment_notes.strip():
        raise HTTPException(
            status_code=422,
            detail="A nota de auditoria é obrigatória. Informe uma justificativa para a alteração do tratamento."
        )

    changed_by = current_user.full_name or current_user.username
    now = datetime.now(timezone.utc)

    # Atualiza a vulnerabilidade
    v.treatment_status = data.treatment_status
    v.treatment_notes = data.treatment_notes.strip()
    v.treated_by_username = changed_by
    v.treated_at = now

    # Registra entrada no histórico de auditoria
    history_entry = models.VulnerabilityTreatmentHistory(
        vulnerability_id=v.id,
        treatment_status=data.treatment_status,
        treatment_notes=data.treatment_notes.strip(),
        changed_by_username=changed_by,
        changed_at=now
    )
    db.add(history_entry)

    db.commit()
    db.refresh(v)
    return format_vuln_out(v, get_ignored_ids_set(db))


@router.get("/{vuln_id}/treatment-history", response_model=List[schemas.TreatmentHistoryOut])
def get_treatment_history(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna o histórico completo de alterações de tratamento de uma vulnerabilidade (ISO 27001).
    Ordenado da alteração mais recente para a mais antiga.
    """
    v = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada.")

    check_user_group_access(db, current_user, v.asset_group_id, action="view")

    history = (
        db.query(models.VulnerabilityTreatmentHistory)
        .filter(models.VulnerabilityTreatmentHistory.vulnerability_id == vuln_id)
        .order_by(models.VulnerabilityTreatmentHistory.changed_at.desc())
        .all()
    )
    return history

@router.post("/bulk-treatment", response_model=schemas.BulkTreatmentResponse)
def bulk_update_vulnerability_treatment(
    data: schemas.BulkVulnerabilityTreatmentUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Atualiza o status de tratamento de múltiplas vulnerabilidades em massa (ISO 27001),
    registrando auditoria de QUEM realizou a tratativa e QUANDO em todos os registros.
    A nota de auditoria é obrigatória. Cada vulnerabilidade recebe um registro no histórico.
    """
    if not data.vulnerability_ids:
        raise HTTPException(status_code=400, detail="Nenhuma vulnerabilidade selecionada para atualização.")

    # Nota obrigatória
    if not data.treatment_notes or not data.treatment_notes.strip():
        raise HTTPException(
            status_code=422,
            detail="A nota de auditoria é obrigatória. Informe uma justificativa para a alteração em lote."
        )

    # Verifica permissão para cada grupo de ativos envolvido
    distinct_group_ids = [
        r[0] for r in db.query(models.Vulnerability.asset_group_id).filter(
            models.Vulnerability.id.in_(data.vulnerability_ids)
        ).distinct().all()
    ]
    for gid in distinct_group_ids:
        check_user_group_access(db, current_user, gid, action="treat")

    changed_by = current_user.full_name or current_user.username
    now = datetime.now(timezone.utc)
    notes_clean = data.treatment_notes.strip()

    # Atualiza em massa os campos da vulnerabilidade
    affected = db.query(models.Vulnerability).filter(
        models.Vulnerability.id.in_(data.vulnerability_ids)
    ).update(
        {
            "treatment_status": data.treatment_status,
            "treatment_notes": notes_clean,
            "treated_by_username": changed_by,
            "treated_at": now
        },
        synchronize_session=False
    )

    # Registra histórico individual para cada vulnerabilidade
    history_entries = [
        models.VulnerabilityTreatmentHistory(
            vulnerability_id=vid,
            treatment_status=data.treatment_status,
            treatment_notes=notes_clean,
            changed_by_username=changed_by,
            changed_at=now
        )
        for vid in data.vulnerability_ids
    ]
    db.bulk_save_objects(history_entries)

    db.commit()

    return schemas.BulkTreatmentResponse(
        updated_count=affected,
        message=f"{affected} vulnerabilidades atualizadas com sucesso para status '{data.treatment_status}'."
    )

@router.get("/hosts/{host_id}", response_model=schemas.HostOut)
def get_host_details(
    host_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Obtém os detalhes de um Host e o resumo de suas vulnerabilidades."""
    h = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not h:
        raise HTTPException(status_code=404, detail="Host não encontrado.")
    check_user_group_access(db, current_user, h.asset_group_id, action="view")
    out = schemas.HostOut.model_validate(h)
    out.asset_group_name = h.asset_group.name if h.asset_group else ""
    populate_host_active_plans([out], db)
    return out
