from typing import List, Optional
from sqlalchemy.orm import Session
from app import models

def get_latest_scan_ids(db: Session, asset_group_id: Optional[int] = None) -> List[int]:
    """
    Retorna os IDs do scan mais recente para cada grupo de ativos aplicável.
    - Se asset_group_id for informado:
        - Se for um Grupo Superior (com subgrupos vinculados), retorna o scan mais recente do próprio grupo
          e o scan mais recente de CADA um de seus subgrupos (visão consolidada corporativa).
        - Se for um subgrupo ou grupo específico sem filhos, retorna apenas o scan mais recente dele.
    - Se não for informado, retorna o scan mais recente de CADA grupo de ativos existente.
    """
    if asset_group_id:
        from app.services.asset_group_service import get_descendant_group_ids
        target_group_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
        latest_ids = []
        for gid in target_group_ids:
            latest = db.query(models.Scan).filter(
                models.Scan.asset_group_id == gid
            ).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
            if latest:
                latest_ids.append(latest.id)
        return latest_ids

    groups = db.query(models.AssetGroup).all()
    latest_ids = []
    for g in groups:
        latest = db.query(models.Scan).filter(
            models.Scan.asset_group_id == g.id
        ).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
        if latest:
            latest_ids.append(latest.id)

    # Scans sem grupo vinculado (caso existam)
    unassigned = db.query(models.Scan).filter(
        models.Scan.asset_group_id == None
    ).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
    if unassigned and unassigned.id not in latest_ids:
        latest_ids.append(unassigned.id)

    return latest_ids


from collections import defaultdict
from app.services.parameter_service import apply_indicator_exclusion

MONTH_NAMES_BR = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"]
ACTIONABLE_SEVERITIES = ["Critical", "High", "Medium", "Low"]

def compute_trend_data(
    db: Session,
    asset_group_id: Optional[int] = None,
    allowed_group_ids: Optional[List[int]] = None
) -> dict:
    """
    Calcula a evolução temporal real de vulnerabilidades (Descobertas vs Remediadas)
    para o ciclo PDCA, agrupando até os últimos 7 meses com base na data do último scan.
    """
    if asset_group_id:
        from app.services.asset_group_service import get_descendant_group_ids
        target_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
        if allowed_group_ids is not None:
            target_ids = [gid for gid in target_ids if gid in allowed_group_ids]
    else:
        target_ids = allowed_group_ids

    query = db.query(models.Scan)
    if target_ids is not None:
        query = query.filter(models.Scan.asset_group_id.in_(target_ids))

    all_scans = query.order_by(models.Scan.scan_date.asc(), models.Scan.id.asc()).all()
    if not all_scans:
        return {"labels": [], "discovered": [], "remediated": [], "has_sufficient_data": False}

    scans_by_month_group = defaultdict(dict)
    for s in all_scans:
        dt = s.scan_date or s.created_at
        if not dt:
            continue
        ym = (dt.year, dt.month)
        gid = s.asset_group_id or 0
        scans_by_month_group[ym][gid] = s

    sorted_months = sorted(scans_by_month_group.keys())
    if not sorted_months:
        return {"labels": [], "discovered": [], "remediated": [], "has_sufficient_data": False}

    # No máximo os últimos 7 meses conforme a data das importações
    if len(sorted_months) > 7:
        sorted_months = sorted_months[-7:]

    has_multiple_years = len(set(y for y, m in sorted_months)) > 1

    labels = []
    discovered = []
    remediated = []

    def get_scan_sigs(scan_id: int):
        q = db.query(
            models.Host.ip_address,
            models.Vulnerability.plugin_id,
            models.Vulnerability.port,
            models.Vulnerability.protocol
        ).join(models.Host, models.Vulnerability.host_id == models.Host.id)\
        .filter(
            models.Vulnerability.scan_id == scan_id,
            models.Vulnerability.severity.in_(ACTIONABLE_SEVERITIES)
        )
        return set(apply_indicator_exclusion(q, db).all())

    sig_cache = {}
    prev_group_sigs = {}
    cum_remediated = 0

    for ym in sorted_months:
        y, m = ym
        lbl = f"{MONTH_NAMES_BR[m - 1]}/{str(y)[2:]}" if has_multiple_years else MONTH_NAMES_BR[m - 1]
        labels.append(lbl)

        curr_groups = scans_by_month_group[ym]
        month_disc = 0
        month_res = 0
        curr_group_sigs = {}

        for gid, s in curr_groups.items():
            if s.id not in sig_cache:
                sig_cache[s.id] = get_scan_sigs(s.id)
            sigs = sig_cache[s.id]
            curr_group_sigs[gid] = sigs
            month_disc += len(sigs)

            if gid in prev_group_sigs:
                month_res += len(prev_group_sigs[gid] - sigs)

            manual_count = db.query(models.Vulnerability).filter(
                models.Vulnerability.scan_id == s.id,
                models.Vulnerability.treatment_status == "Remediated",
                models.Vulnerability.severity.in_(ACTIONABLE_SEVERITIES)
            ).count()
            month_res += manual_count

        cum_remediated += month_res
        discovered.append(month_disc)
        remediated.append(cum_remediated)

        for gid, sigs in curr_group_sigs.items():
            prev_group_sigs[gid] = sigs

    return {
        "labels": labels,
        "discovered": discovered,
        "remediated": remediated,
        "has_sufficient_data": len(labels) >= 2
    }
