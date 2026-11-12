import re
import math
from datetime import datetime, timezone
from typing import List, Optional, Union, Set
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, and_, or_
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, require_analyst_or_admin, check_user_group_access, get_user_allowed_group_ids
from app.services.scan_service import get_latest_scan_ids
from app.services.parameter_service import (
    apply_indicator_exclusion,
    get_ignored_ids_set,
    to_system_tz,
    format_datetime_in_system_tz
)

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

def format_vuln_out(
    v: models.Vulnerability,
    ignored_ids: Optional[Set[str]] = None,
    db: Optional[Session] = None
) -> schemas.VulnerabilityOut:
    out = schemas.VulnerabilityOut.model_validate(v)
    out.host_ip = v.host.ip_address if v.host else ""
    out.host_name = v.host.hostname if v.host else ""
    out.asset_group_name = v.asset_group.name if v.asset_group else ""
    out.aging_days = calculate_aging_days(v)
    out.treated_by_username = v.treated_by_username
    out.treated_at = to_system_tz(v.treated_at, db) if v.treated_at else None
    if v.treated_at:
        out.treated_at_formatted = format_datetime_in_system_tz(
            v.treated_at, db, fmt="%d/%m/%Y, %H:%M:%S", include_offset=False
        )
    else:
        out.treated_at_formatted = None
    out.first_found = to_system_tz(v.first_found, db) if v.first_found else None
    out.last_found = to_system_tz(v.last_found, db) if v.last_found else None
    out.created_at = to_system_tz(v.created_at, db) if v.created_at else v.created_at
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
    os: Optional[str] = None,
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
        sev_list = [s.strip() for s in severity.split(",") if s.strip()]
        if len(sev_list) == 1:
            query = query.filter(models.Vulnerability.severity == sev_list[0])
        elif len(sev_list) > 1:
            query = query.filter(models.Vulnerability.severity.in_(sev_list))
    elif exclude_info:
        query = query.filter(models.Vulnerability.severity.notin_(["Info", "None", "none", "info"]))

    if os:
        os_list = [o.strip() for o in os.split(",") if o.strip()]
        if os_list:
            os_clauses = [models.Host.os.ilike(f"%{target_os}%") for target_os in os_list]
            query = query.filter(or_(*os_clauses))
    
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
        formatted_items = [format_vuln_out(v, ignored_ids, db=db) for v in items_db]
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
    formatted_vulns = [format_vuln_out(v, ignored_ids, db=db) for v in vulns]
    populate_vuln_active_plans(formatted_vulns, db)
    return formatted_vulns

@router.get("/unique-hosts", response_model=List[dict])
def get_unique_hosts(
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Retorna lista de hosts únicos (IP, hostname e SO) para preenchimento de filtros."""
    active_scan_ids = get_latest_scan_ids(db, asset_group_id)
    if not active_scan_ids:
        return []
    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    q = db.query(models.Host.id, models.Host.ip_address, models.Host.hostname, models.Host.os)\
        .filter(models.Host.scan_id.in_(active_scan_ids))
    if allowed_ids is not None:
        if asset_group_id:
            check_user_group_access(db, current_user, asset_group_id, action="view")
        else:
            q = q.filter(models.Host.asset_group_id.in_(allowed_ids))
    hosts = q.order_by(models.Host.ip_address).all()
    seen = set()
    result = []
    for h in hosts:
        if h.ip_address not in seen:
            seen.add(h.ip_address)
            result.append({
                "id": h.id,
                "ip": h.ip_address,
                "ip_address": h.ip_address,
                "hostname": h.hostname or "",
                "os": h.os or ""
            })
    return result

@router.get("/unique-os", response_model=List[str])
def get_unique_operating_systems(
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Retorna a lista de Sistemas Operacionais únicos dos hosts no escopo ativo."""
    active_scan_ids = get_latest_scan_ids(db, asset_group_id)
    if not active_scan_ids:
        return []
    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    q = db.query(models.Host.os)\
        .filter(
            models.Host.scan_id.in_(active_scan_ids),
            models.Host.os != None,
            models.Host.os != ""
        )
    if allowed_ids is not None:
        if asset_group_id:
            check_user_group_access(db, current_user, asset_group_id, action="view")
        else:
            q = q.filter(models.Host.asset_group_id.in_(allowed_ids))
    rows = q.distinct().order_by(models.Host.os).all()
    os_set = set()
    result = []
    for r in rows:
        val = (r[0] or "").strip()
        if val and val not in os_set:
            os_set.add(val)
            result.append(val)
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

    # Subconsulta de vulnerabilidades ativas/residuais por host (excluindo Remediadas e Info/None, e aplicando exclusões de falsos-positivos)
    active_vuln_subq = db.query(
        models.Vulnerability.host_id.label("v_host_id"),
        func.coalesce(func.sum(case((models.Vulnerability.severity == "Critical", 1), else_=0)), 0).label("active_critical_count"),
        func.coalesce(func.sum(case((models.Vulnerability.severity == "High", 1), else_=0)), 0).label("active_high_count"),
        func.coalesce(func.sum(case((models.Vulnerability.severity == "Medium", 1), else_=0)), 0).label("active_medium_count"),
        func.coalesce(func.sum(case((models.Vulnerability.severity == "Low", 1), else_=0)), 0).label("active_low_count"),
        func.coalesce(func.sum(case((and_(models.Vulnerability.severity == "Critical", models.Vulnerability.exploit_available == True), 1), else_=0)), 0).label("active_exploitable_critical_count")
    ).filter(
        models.Vulnerability.scan_id.in_(active_scan_ids),
        ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated"]),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"])
    )
    active_vuln_subq = apply_indicator_exclusion(active_vuln_subq, db)
    active_vuln_subq = active_vuln_subq.group_by(models.Vulnerability.host_id).subquery()

    dyn_critical = func.coalesce(active_vuln_subq.c.active_critical_count, 0)
    dyn_high = func.coalesce(active_vuln_subq.c.active_high_count, 0)
    dyn_medium = func.coalesce(active_vuln_subq.c.active_medium_count, 0)
    dyn_low = func.coalesce(active_vuln_subq.c.active_low_count, 0)
    dyn_exploitable = func.coalesce(active_vuln_subq.c.active_exploitable_critical_count, 0)

    # Fórmula ISO 27001 de Risk Score por Host:
    # (Crit * 10.0) + (High * 5.0) + (Med * 2.0) + (Low * 0.5) + (Crit_Exploit * 5.0)
    dyn_risk_score = (
        (dyn_critical * 10.0) +
        (dyn_high * 5.0) +
        (dyn_medium * 2.0) +
        (dyn_low * 0.5) +
        (dyn_exploitable * 5.0)
    )

    base_query = db.query(
        models.Host,
        dyn_critical.label("dyn_critical"),
        dyn_high.label("dyn_high"),
        dyn_medium.label("dyn_medium"),
        dyn_low.label("dyn_low"),
        dyn_exploitable.label("dyn_exploitable"),
        dyn_risk_score.label("dyn_risk_score")
    ).join(
        models.AssetGroup, models.Host.asset_group_id == models.AssetGroup.id
    ).outerjoin(
        active_vuln_subq, models.Host.id == active_vuln_subq.c.v_host_id
    ).filter(
        models.Host.scan_id.in_(active_scan_ids)
    )

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
            base_query = base_query.filter(dyn_critical > 0)
        elif sev_clean == "high":
            base_query = base_query.filter(dyn_high > 0)
        elif sev_clean == "medium":
            base_query = base_query.filter(dyn_medium > 0)
        elif sev_clean == "low":
            base_query = base_query.filter(dyn_low > 0)
        elif sev_clean == "exploits":
            base_query = base_query.filter(dyn_exploitable > 0)

    # Compute overall stats matching the filters
    stats_query = db.query(
        func.count(models.Host.id).label("total_hosts"),
        func.coalesce(func.sum(dyn_critical), 0).label("total_critical"),
        func.coalesce(func.sum(dyn_high), 0).label("total_high"),
        func.coalesce(func.sum(dyn_medium), 0).label("total_medium"),
        func.coalesce(func.sum(dyn_low), 0).label("total_low"),
        func.coalesce(func.avg(dyn_risk_score), 0.0).label("avg_risk_score"),
        func.coalesce(func.max(dyn_risk_score), 0.0).label("max_risk_score"),
        func.coalesce(func.sum(case((dyn_critical > 0, 1), else_=0)), 0).label("hosts_with_critical"),
        func.coalesce(func.sum(case((dyn_exploitable > 0, 1), else_=0)), 0).label("hosts_with_exploits")
    ).select_from(models.Host)\
     .join(models.AssetGroup, models.Host.asset_group_id == models.AssetGroup.id)\
     .outerjoin(active_vuln_subq, models.Host.id == active_vuln_subq.c.v_host_id)\
     .filter(models.Host.scan_id.in_(active_scan_ids))

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
            stats_query = stats_query.filter(dyn_critical > 0)
        elif sev_clean == "high":
            stats_query = stats_query.filter(dyn_high > 0)
        elif sev_clean == "medium":
            stats_query = stats_query.filter(dyn_medium > 0)
        elif sev_clean == "low":
            stats_query = stats_query.filter(dyn_low > 0)
        elif sev_clean == "exploits":
            stats_query = stats_query.filter(dyn_exploitable > 0)

    stats_row = stats_query.first()
    total_hosts = stats_row.total_hosts if stats_row else 0
    total_crit = int(stats_row.total_critical) if stats_row else 0
    total_high = int(stats_row.total_high) if stats_row else 0
    total_med = int(stats_row.total_medium) if stats_row else 0
    total_low = int(stats_row.total_low) if stats_row else 0
    avg_risk = round(float(stats_row.avg_risk_score), 1) if stats_row and stats_row.avg_risk_score is not None else 0.0
    max_risk = round(float(stats_row.max_risk_score), 1) if stats_row and stats_row.max_risk_score is not None else 0.0
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
        "risk_score": dyn_risk_score,
        "ip_address": models.Host.ip_address,
        "hostname": models.Host.hostname,
        "os": models.Host.os,
        "critical_count": dyn_critical,
        "high_count": dyn_high,
        "medium_count": dyn_medium,
        "low_count": dyn_low,
        "asset_group_name": models.AssetGroup.name
    }
    col = sort_column_map.get(sort_by, dyn_risk_score)
    if sort_order.lower() == "asc":
        ordered_query = base_query.order_by(col.asc(), models.Host.id.asc())
    else:
        ordered_query = base_query.order_by(col.desc(), models.Host.id.desc())

    total = total_hosts
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    hosts_rows = ordered_query.offset(offset).limit(page_size).all()

    items = []
    for h, d_crit, d_high, d_med, d_low, d_exp, d_risk in hosts_rows:
        item = schemas.HostOut.model_validate(h)
        item.critical_count = int(d_crit or 0)
        item.high_count = int(d_high or 0)
        item.medium_count = int(d_med or 0)
        item.low_count = int(d_low or 0)
        item.exploitable_critical_count = int(d_exp or 0)
        item.risk_score = round(float(d_risk or 0.0), 1)
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
    out = format_vuln_out(v, get_ignored_ids_set(db), db=db)
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

    # Bloquear seleção manual de 'In_Action_Plan'
    if data.treatment_status == "In_Action_Plan":
        raise HTTPException(
            status_code=400,
            detail="O status 'Em Plano de Ação' não pode ser selecionado manualmente. A vinculação ocorre somente mediante a criação de um plano de ação."
        )

    # Bloquear alteração manual se a vulnerabilidade estiver associada a um plano de ação ativo
    active_plan = db.query(models.ActionPlan).join(
        models.ActionTask, models.ActionTask.action_plan_id == models.ActionPlan.id
    ).join(
        models.ActionTaskVulnerabilityLink, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
    ).filter(
        models.ActionTaskVulnerabilityLink.vulnerability_id == v.id,
        models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
    ).first()

    if active_plan or v.treatment_status == "In_Action_Plan":
        plan_ref = f" #{active_plan.id} ('{active_plan.title}')" if active_plan else ""
        raise HTTPException(
            status_code=400,
            detail=f"Não é possível alterar manualmente o status de tratamento: esta vulnerabilidade está associada a um plano de ação ativo{plan_ref}. O tratamento é gerenciado exclusivamente pelo plano de ação até sua conclusão/remediação."
        )

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
    return format_vuln_out(v, get_ignored_ids_set(db), db=db)


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
    result = []
    for h in history:
        item = schemas.TreatmentHistoryOut.model_validate(h)
        item.changed_at = to_system_tz(h.changed_at, db)
        item.changed_at_formatted = format_datetime_in_system_tz(
            h.changed_at, db, fmt="%d/%m/%Y, %H:%M:%S", include_offset=False
        )
        result.append(item)
    return result

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

    # Bloquear seleção manual de 'In_Action_Plan'
    if data.treatment_status == "In_Action_Plan":
        raise HTTPException(
            status_code=400,
            detail="O status 'Em Plano de Ação' não pode ser selecionado manualmente. A vinculação ocorre somente mediante a criação de um plano de ação."
        )

    # Verificar se alguma vulnerabilidade selecionada está vinculada a plano de ação ativo
    plan_linked = db.query(models.ActionTaskVulnerabilityLink.vulnerability_id).join(
        models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
    ).join(
        models.ActionPlan, models.ActionTask.action_plan_id == models.ActionPlan.id
    ).filter(
        models.ActionTaskVulnerabilityLink.vulnerability_id.in_(data.vulnerability_ids),
        models.ActionPlan.status.in_(["PLANNED", "IN_PROGRESS"])
    ).all()
    in_plan_vulns = db.query(models.Vulnerability.id).filter(
        models.Vulnerability.id.in_(data.vulnerability_ids),
        models.Vulnerability.treatment_status == "In_Action_Plan"
    ).all()
    protected_ids = set([r[0] for r in plan_linked] + [r[0] for r in in_plan_vulns])
    if protected_ids:
        raise HTTPException(
            status_code=400,
            detail=f"{len(protected_ids)} vulnerabilidade(s) selecionada(s) estão associadas a Planos de Ação ativos e seu tratamento é gerenciado exclusivamente pelo plano."
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
    """Obtém os detalhes de um Host e o resumo de suas vulnerabilidades ativas/residuais."""
    h = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not h:
        raise HTTPException(status_code=404, detail="Host não encontrado.")
    check_user_group_access(db, current_user, h.asset_group_id, action="view")
    out = schemas.HostOut.model_validate(h)
    out.asset_group_name = h.asset_group.name if h.asset_group else ""

    # Calcula contadores e risk score dinâmicos sobre as vulnerabilidades ativas (não remediadas)
    active_vulns_q = db.query(
        models.Vulnerability.severity,
        models.Vulnerability.exploit_available
    ).filter(
        models.Vulnerability.host_id == host_id,
        models.Vulnerability.scan_id == h.scan_id,
        ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated"]),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"])
    )
    active_vulns = apply_indicator_exclusion(active_vulns_q, db).all()

    crit = sum(1 for v in active_vulns if v.severity == "Critical")
    high = sum(1 for v in active_vulns if v.severity == "High")
    med = sum(1 for v in active_vulns if v.severity == "Medium")
    low = sum(1 for v in active_vulns if v.severity == "Low")
    exp = sum(1 for v in active_vulns if v.severity == "Critical" and v.exploit_available)

    out.critical_count = crit
    out.high_count = high
    out.medium_count = med
    out.low_count = low
    out.exploitable_critical_count = exp
    out.risk_score = round(
        (crit * 10.0) + (high * 5.0) + (med * 2.0) + (low * 0.5) + (exp * 5.0),
        1
    )

    populate_host_active_plans([out], db)
    return out
