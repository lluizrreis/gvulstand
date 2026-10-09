import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, check_user_group_access, get_user_allowed_group_ids
from app.services.scan_service import get_latest_scan_ids, compute_trend_data
from app.services.parameter_service import apply_indicator_exclusion, get_effective_slas

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

router = APIRouter(prefix="/dashboard", tags=["Dashboard & Indicadores de Governança"])

def resolve_dashboard_scan_ids(db: Session, current_user: models.User, asset_group_id: Optional[int]) -> List[int]:
    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    if asset_group_id:
        if allowed_ids is not None:
            check_user_group_access(db, current_user, asset_group_id, action="view")
        return get_latest_scan_ids(db, asset_group_id)
    else:
        if allowed_ids is not None:
            active_ids = []
            for gid in allowed_ids:
                active_ids.extend(get_latest_scan_ids(db, gid))
            return active_ids
        else:
            return get_latest_scan_ids(db, None)

@router.get("/stats", response_model=schemas.DashboardStats)
def get_dashboard_stats(
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna métricas executivas consolidadas e indicadores ISO 27001 / ISO 9001
    utilizando estritamente o scan mais recente de cada grupo de ativos.
    """
    active_scan_ids = resolve_dashboard_scan_ids(db, current_user, asset_group_id)

    if not active_scan_ids:
        return schemas.DashboardStats(
            total_findings=0,
            total_scans=0,
            total_asset_groups=db.query(models.AssetGroup).count(),
            total_unique_hosts=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            exploitable_total_count=0,
            iso27001_risk_score=0.0,
            posture_score=100,
            iso9001_remediation_efficiency=None,
            severity_breakdown={"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            aging_breakdown={"0_30": 0, "31_60": 0, "61_90": 0, "above_90": 0},
            vpr_breakdown={"rating_9_10": 0, "rating_7_8_9": 0, "rating_4_6_9": 0, "rating_0_3_9": 0},
            sla_progress={
                "Critical": {"meeting": 0, "not_meeting": 0},
                "High": {"meeting": 0, "not_meeting": 0},
                "Medium": {"meeting": 0, "not_meeting": 0},
                "Low": {"meeting": 0, "not_meeting": 0}
            },
            age_sla_matrix={
                "Critical": {"d0_7": 0, "d8_14": 0, "d15_30": 0, "d31_60": 0, "d61_90": 0, "above_90": 0},
                "High": {"d0_7": 0, "d8_14": 0, "d15_30": 0, "d31_60": 0, "d61_90": 0, "above_90": 0},
                "Medium": {"d0_7": 0, "d8_14": 0, "d15_30": 0, "d31_60": 0, "d61_90": 0, "above_90": 0},
                "Low": {"d0_7": 0, "d8_14": 0, "d15_30": 0, "d31_60": 0, "d61_90": 0, "above_90": 0}
            },
            exploitable_types={"malware": 0, "remote_low": 0, "local_low": 0, "framework_metasploit": 0, "remote_high": 0},
            scan_health={"auth_success": 0, "insufficient_access": 0, "auth_failure": 0, "intermittent": 0, "no_credentials": 0},
            patch_advisory={"missing_patches": 0, "applied_patches": 0},
            cve_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "exploit": 0, "total": 0},
            treatment_breakdown={
                "In_Action_Plan": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "In_Remediation": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "Accepted_Risk": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "Remediated": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "Open": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            },
            action_plans_summary={
                "total_plans": 0,
                "active_plans": 0,
                "total_vulns": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            asset_group_distribution=[],
            recent_scans=[],
            trend_data={"labels": [], "discovered": [], "remediated": [], "has_sufficient_data": False}
        )

    scan_q = db.query(models.Scan).filter(models.Scan.id.in_(active_scan_ids))
    vuln_q = db.query(models.Vulnerability).filter(models.Vulnerability.scan_id.in_(active_scan_ids))
    vuln_q = apply_indicator_exclusion(vuln_q, db)
    host_q = db.query(models.Host).filter(models.Host.scan_id.in_(active_scan_ids))

    total_scans = len(active_scan_ids)
    total_asset_groups = db.query(models.AssetGroup).count()
    total_unique_hosts = host_q.with_entities(models.Host.ip_address).distinct().count()

    # Severity counts
    crit_count = vuln_q.filter(models.Vulnerability.severity == "Critical").count()
    high_count = vuln_q.filter(models.Vulnerability.severity == "High").count()
    med_count = vuln_q.filter(models.Vulnerability.severity == "Medium").count()
    low_count = vuln_q.filter(models.Vulnerability.severity == "Low").count()
    info_count = vuln_q.filter(models.Vulnerability.severity == "Info").count()

    # Total findings counts only actual actionable vulnerabilities (Critical, High, Medium, Low)
    total_findings = crit_count + high_count + med_count + low_count

    # Exploitable count (only actionable vulnerabilities)
    exploit_count = vuln_q.filter(
        models.Vulnerability.exploit_available == True,
        models.Vulnerability.severity != "Info"
    ).count()

    # ISO 27001 Risk Posture Score
    raw_risk = (crit_count * 10.0) + (high_count * 5.0) + (med_count * 2.0) + (low_count * 0.5)
    iso27001_risk_score = round(raw_risk / max(1, total_unique_hosts), 1)
    import math
    posture_score = max(10, min(100, round(100 - (16.0 * math.log(1.0 + iso27001_risk_score)))))

    # ISO 9001 Remediation Efficiency
    remediated_count = vuln_q.filter(
        models.Vulnerability.treatment_status == "Remediated",
        models.Vulnerability.severity != "Info"
    ).count()
    if remediated_count == 0 or total_findings == 0:
        remediation_eff = None
    else:
        remediation_eff = round((remediated_count / max(1, total_findings)) * 100.0, 1)

    # Distribution by asset group (each group reflecting its latest scan)
    group_dist = []
    groups = db.query(models.AssetGroup).all()

    # Precompute group hierarchy in memory to prevent recursive SQL queries
    children_map = defaultdict(list)
    for g in groups:
        if g.parent_id is not None:
            children_map[g.parent_id].append(g.id)

    descendants_map = {}
    for g in groups:
        descendants = [g.id]
        queue = [g.id]
        visited = {g.id}
        while queue:
            curr = queue.pop(0)
            for child_id in children_map.get(curr, []):
                if child_id not in visited:
                    visited.add(child_id)
                    descendants.append(child_id)
                    queue.append(child_id)
        descendants_map[g.id] = descendants

    # Get latest scan ID per asset group in a single query
    latest_scan_by_group = {}
    for scan_id, ag_id in (
        db.query(models.Scan.id, models.Scan.asset_group_id)
        .filter(models.Scan.asset_group_id.isnot(None))
        .order_by(models.Scan.scan_date.desc(), models.Scan.id.desc())
        .all()
    ):
        if ag_id not in latest_scan_by_group:
            latest_scan_by_group[ag_id] = scan_id

    # Collect all relevant latest scan IDs across all groups
    all_scan_ids = set(latest_scan_by_group.values())

    # Aggregate vulnerability severity counts across all latest scans in a single query
    scan_counts = defaultdict(lambda: defaultdict(int))
    if all_scan_ids:
        vuln_counts_q = (
            db.query(
                models.Vulnerability.scan_id,
                models.Vulnerability.severity,
                func.count(models.Vulnerability.id),
            )
            .filter(
                models.Vulnerability.scan_id.in_(all_scan_ids),
                models.Vulnerability.severity.in_(["Critical", "High", "Medium", "Low"]),
            )
        )
        vuln_counts_q = apply_indicator_exclusion(vuln_counts_q, db)
        for scan_id, severity, count in vuln_counts_q.group_by(
            models.Vulnerability.scan_id,
            models.Vulnerability.severity,
        ).all():
            scan_counts[scan_id][severity] = count

    for g in groups:
        g_scan_ids = {latest_scan_by_group[gid] for gid in descendants_map[g.id] if gid in latest_scan_by_group}
        if g_scan_ids:
            g_crit = sum(scan_counts[sid]["Critical"] for sid in g_scan_ids)
            g_high = sum(scan_counts[sid]["High"] for sid in g_scan_ids)
            g_med = sum(scan_counts[sid]["Medium"] for sid in g_scan_ids)
            g_low = sum(scan_counts[sid]["Low"] for sid in g_scan_ids)
            g_total = g_crit + g_high + g_med + g_low
        else:
            g_crit = g_high = g_med = g_low = g_total = 0

        group_dist.append({
            "id": g.id,
            "name": g.name,
            "critical": g_crit,
            "high": g_high,
            "medium": g_med,
            "low": g_low,
            "total": g_total
        })

    # Aging & Tenable Metrics Calculation
    actionable_vulns = vuln_q.filter(models.Vulnerability.severity != "Info").all()
    group_slas = {g.id: g for g in groups}

    aging_0_30 = 0
    aging_31_60 = 0
    aging_61_90 = 0
    aging_above_90 = 0

    vpr_9_10 = 0
    vpr_7_8_9 = 0
    vpr_4_6_9 = 0
    vpr_0_3_9 = 0

    sla_prog = {
        "Critical": {"meeting": 0, "not_meeting": 0},
        "High": {"meeting": 0, "not_meeting": 0},
        "Medium": {"meeting": 0, "not_meeting": 0},
        "Low": {"meeting": 0, "not_meeting": 0}
    }

    age_matrix = {
        "Critical": {"d0_7": 0, "d8_14": 0, "d15_30": 0, "d31_60": 0, "d61_90": 0, "above_90": 0},
        "High": {"d0_7": 0, "d8_14": 0, "d15_30": 0, "d31_60": 0, "d61_90": 0, "above_90": 0},
        "Medium": {"d0_7": 0, "d8_14": 0, "d15_30": 0, "d31_60": 0, "d61_90": 0, "above_90": 0},
        "Low": {"d0_7": 0, "d8_14": 0, "d15_30": 0, "d31_60": 0, "d61_90": 0, "above_90": 0}
    }

    exp_malware = 0
    exp_remote_low = 0
    exp_local_low = 0
    exp_framework = 0
    exp_remote_high = 0

    missing_patches = 0
    applied_patches = 0

    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    cves_critical = set()
    cves_high = set()
    cves_medium = set()
    cves_low = set()
    cves_exploit = set()
    cves_total = set()

    treatment_breakdown = {
        "In_Action_Plan": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "In_Remediation": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "Accepted_Risk": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "Remediated": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "Open": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    }

    now_utc = datetime.now(timezone.utc)
    for v in actionable_vulns:
        # Treatment status breakdown by severity
        st = v.treatment_status if v.treatment_status in treatment_breakdown else "Open"
        treatment_breakdown[st]["total"] += 1
        sev_key = (v.severity or "Low").lower()
        if sev_key in treatment_breakdown[st]:
            treatment_breakdown[st][sev_key] += 1

        # CVE extraction per severity
        if v.cve:
            found_cves = cve_pattern.findall(v.cve)
            for c in found_cves:
                c_upper = c.upper()
                cves_total.add(c_upper)
                if v.severity == "Critical":
                    cves_critical.add(c_upper)
                elif v.severity == "High":
                    cves_high.add(c_upper)
                elif v.severity == "Medium":
                    cves_medium.add(c_upper)
                elif v.severity == "Low":
                    cves_low.add(c_upper)
                if v.exploit_available:
                    cves_exploit.add(c_upper)
        # Aging
        ref_dt = v.first_found or v.created_at
        if ref_dt:
            now_cmp = now_utc if ref_dt.tzinfo is not None else datetime.utcnow()
            days = max(0, (now_cmp - ref_dt).days)
        else:
            days = 0

        if days <= 30:
            aging_0_30 += 1
        elif days <= 60:
            aging_31_60 += 1
        elif days <= 90:
            aging_61_90 += 1
        else:
            aging_above_90 += 1

        # VPR Distribution
        score = v.vpr if v.vpr is not None else (v.cvss_v3 or 0.0)
        if score >= 9.0:
            vpr_9_10 += 1
        elif score >= 7.0:
            vpr_7_8_9 += 1
        elif score >= 4.0:
            vpr_4_6_9 += 1
        else:
            vpr_0_3_9 += 1

        # SLA Progress
        sev = v.severity if v.severity in sla_prog else "Low"
        g = group_slas.get(v.asset_group_id)
        effective_slas = get_effective_slas(db, g)
        sla_limit = effective_slas.get(sev, 60)

        if days <= sla_limit:
            sla_prog[sev]["meeting"] += 1
        else:
            sla_prog[sev]["not_meeting"] += 1

        # Age Matrix (6 buckets)
        if days <= 7:
            age_matrix[sev]["d0_7"] += 1
        elif days <= 14:
            age_matrix[sev]["d8_14"] += 1
        elif days <= 30:
            age_matrix[sev]["d15_30"] += 1
        elif days <= 60:
            age_matrix[sev]["d31_60"] += 1
        elif days <= 90:
            age_matrix[sev]["d61_90"] += 1
        else:
            age_matrix[sev]["above_90"] += 1

        # Exploitable Types Breakdown
        if v.exploit_available:
            frameworks_str = (v.exploit_frameworks or "").lower()
            if v.exploited_by_malware or "malware" in frameworks_str:
                exp_malware += 1
            if "metasploit" in frameworks_str or "canvas" in frameworks_str or "core" in frameworks_str or "elliot" in frameworks_str:
                exp_framework += 1
            if v.plugin_type == "local" or v.port == 0:
                exp_local_low += 1
            elif (v.cvss_v3 or 0) >= 8.0:
                exp_remote_low += 1
            else:
                exp_remote_high += 1

        # Patch Advisory
        if v.treatment_status == "Remediated":
            applied_patches += 1
        elif v.patch_available or v.solution:
            missing_patches += 1

    # Scan Health & Credential Quality (Deduplicado por IP único de host)
    error_vulns = vuln_q.filter(models.Vulnerability.plugin_id.in_(list(SCAN_ERROR_PLUGINS.keys()))).all()
    error_hosts_by_plugin = {}
    for ev in error_vulns:
        if ev.host_id not in error_hosts_by_plugin:
            error_hosts_by_plugin[ev.host_id] = set()
        error_hosts_by_plugin[ev.host_id].add(str(ev.plugin_id))

    # Agrupar instâncias de hosts por IP único
    unique_hosts_map = {}
    for h in host_q.all():
        if h.ip_address not in unique_hosts_map:
            unique_hosts_map[h.ip_address] = {
                "host_ids": [],
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        unique_hosts_map[h.ip_address]["host_ids"].append(h.id)
        unique_hosts_map[h.ip_address]["critical"] += (h.critical_count or 0)
        unique_hosts_map[h.ip_address]["high"] += (h.high_count or 0)
        unique_hosts_map[h.ip_address]["medium"] += (h.medium_count or 0)
        unique_hosts_map[h.ip_address]["low"] += (h.low_count or 0)
        unique_hosts_map[h.ip_address]["info"] += (h.info_count or 0)

    sh_auth_success = 0
    sh_insufficient_access = 0
    sh_auth_failure = 0
    sh_intermittent = 0
    sh_no_credentials = 0

    for ip, data in unique_hosts_map.items():
        all_pids = set()
        for hid in data["host_ids"]:
            all_pids.update(error_hosts_by_plugin.get(hid, set()))

        if all_pids.intersection({"21745", "1102", "26917", "24786", "12650"}):
            sh_auth_failure += 1
        elif all_pids.intersection({"102094", "102095", "104410"}):
            sh_insufficient_access += 1
        elif all_pids.intersection({"10180"}):
            sh_intermittent += 1
        elif data["critical"] == 0 and data["high"] == 0 and data["medium"] == 0 and data["low"] == 0 and data["info"] <= 2:
            sh_no_credentials += 1
        else:
            sh_auth_success += 1

    # Recent scans
    recent_scans_raw = scan_q.order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).limit(5).all()
    recent_scans = []
    for s in recent_scans_raw:
        out = schemas.ScanOut.model_validate(s)
        out.asset_group_name = s.asset_group.name if s.asset_group else ""
        recent_scans.append(out)

    # Action Plans Summary
    from app.api.routes_action_plans import build_action_plan_group_filter

    # Statuses excluídos do card de planos de ação: Concluídos (COMPLETED, DONE), Rascunho (DRAFT) e Cancelados (CANCELLED, CANCELED)
    excluded_plan_statuses = [
        "COMPLETED", "DONE", "DRAFT", "CANCELLED", "CANCELED",
        "completed", "done", "draft", "cancelled", "canceled"
    ]

    ap_query = db.query(models.ActionPlan)
    ap_filter = build_action_plan_group_filter(db, current_user, asset_group_id)
    if ap_filter is not None:
        ap_query = ap_query.filter(ap_filter)

    # Filtrar estritamente planos ativos (não concluídos, não rascunho, não cancelados)
    active_plans_filter = ~models.ActionPlan.status.in_(excluded_plan_statuses)
    active_action_plans = ap_query.filter(active_plans_filter).count()

    plan_vuln_ids_q = db.query(models.ActionTaskVulnerabilityLink.vulnerability_id).join(
        models.ActionTask, models.ActionTaskVulnerabilityLink.action_task_id == models.ActionTask.id
    ).join(
        models.ActionPlan, models.ActionTask.action_plan_id == models.ActionPlan.id
    )
    if ap_filter is not None:
        plan_vuln_ids_q = plan_vuln_ids_q.filter(ap_filter)

    # Excluir planos com status excluído e tarefas já concluídas (DONE)
    plan_vuln_ids_q = plan_vuln_ids_q.filter(
        active_plans_filter,
        ~models.ActionTask.status.in_(["DONE", "done"])
    ).distinct()

    if active_action_plans > 0:
        plan_vulns = vuln_q.filter(
            models.Vulnerability.id.in_(plan_vuln_ids_q),
            models.Vulnerability.severity != "Info",
            ~models.Vulnerability.treatment_status.in_(["Remediated", "remediated"])
        ).all()

        plan_crit = sum(1 for v in plan_vulns if v.severity == "Critical")
        plan_high = sum(1 for v in plan_vulns if v.severity == "High")
        plan_med = sum(1 for v in plan_vulns if v.severity == "Medium")
        plan_low = sum(1 for v in plan_vulns if v.severity == "Low")
        plan_total_vulns = len(plan_vulns)
    else:
        plan_crit = 0
        plan_high = 0
        plan_med = 0
        plan_low = 0
        plan_total_vulns = 0

    action_plans_summary = {
        "total_plans": active_action_plans,
        "active_plans": active_action_plans,
        "total_vulns": plan_total_vulns,
        "critical": plan_crit,
        "high": plan_high,
        "medium": plan_med,
        "low": plan_low
    }

    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    trend_data = compute_trend_data(db, asset_group_id, allowed_ids)

    return schemas.DashboardStats(
        total_scans=total_scans,
        total_asset_groups=total_asset_groups,
        total_unique_hosts=total_unique_hosts,
        total_findings=total_findings,
        critical_count=crit_count,
        high_count=high_count,
        medium_count=med_count,
        low_count=low_count,
        info_count=info_count,
        exploitable_total_count=exploit_count,
        iso27001_risk_score=iso27001_risk_score,
        posture_score=posture_score,
        iso9001_remediation_efficiency=remediation_eff,
        severity_breakdown={
            "Critical": crit_count,
            "High": high_count,
            "Medium": med_count,
            "Low": low_count
        },
        aging_breakdown={
            "0_30": aging_0_30,
            "31_60": aging_31_60,
            "61_90": aging_61_90,
            "above_90": aging_above_90
        },
        vpr_breakdown={
            "rating_9_10": vpr_9_10,
            "rating_7_8_9": vpr_7_8_9,
            "rating_4_6_9": vpr_4_6_9,
            "rating_0_3_9": vpr_0_3_9
        },
        sla_progress=sla_prog,
        age_sla_matrix=age_matrix,
        exploitable_types={
            "malware": exp_malware,
            "remote_low": exp_remote_low,
            "local_low": exp_local_low,
            "framework_metasploit": exp_framework,
            "remote_high": exp_remote_high
        },
        scan_health={
            "auth_success": sh_auth_success,
            "insufficient_access": sh_insufficient_access,
            "auth_failure": sh_auth_failure,
            "intermittent": sh_intermittent,
            "no_credentials": sh_no_credentials
        },
        patch_advisory={
            "missing_patches": missing_patches,
            "applied_patches": applied_patches
        },
        cve_counts={
            "critical": len(cves_critical),
            "high": len(cves_high),
            "medium": len(cves_medium),
            "low": len(cves_low),
            "exploit": len(cves_exploit),
            "total": len(cves_total)
        },
        treatment_breakdown=treatment_breakdown,
        action_plans_summary=action_plans_summary,
        asset_group_distribution=group_dist,
        recent_scans=recent_scans,
        trend_data=trend_data
    )

@router.get("/top-critical", response_model=List[schemas.TopCriticalVuln])
def get_top_100_critical_vulnerabilities(
    asset_group_id: Optional[int] = None,
    limit: int = Query(100, le=100),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Indicador Top 100 Vulnerabilidades Críticas no ambiente, agrupadas por plugin/CVE com contagem de ativos afetados,
    utilizando o scan mais recente de cada grupo de ativos.
    """
    active_scan_ids = resolve_dashboard_scan_ids(db, current_user, asset_group_id)
    if not active_scan_ids:
        return []

    vuln_q = db.query(
        models.Vulnerability.plugin_id,
        models.Vulnerability.plugin_name,
        models.Vulnerability.cve,
        models.Vulnerability.cvss_v3,
        models.Vulnerability.severity,
        models.Vulnerability.exploit_available,
        models.Vulnerability.exploit_frameworks,
        models.Vulnerability.solution,
        models.Vulnerability.synopsis,
        func.count(models.Vulnerability.id).label("affected_hosts_count")
    ).filter(
        models.Vulnerability.severity == "Critical",
        models.Vulnerability.scan_id.in_(active_scan_ids)
    )
    vuln_q = apply_indicator_exclusion(vuln_q, db)

    grouped = vuln_q.group_by(
        models.Vulnerability.plugin_id,
        models.Vulnerability.plugin_name,
        models.Vulnerability.cve,
        models.Vulnerability.cvss_v3,
        models.Vulnerability.severity,
        models.Vulnerability.exploit_available,
        models.Vulnerability.exploit_frameworks,
        models.Vulnerability.solution,
        models.Vulnerability.synopsis
    ).order_by(
        models.Vulnerability.exploit_available.desc(),
        models.Vulnerability.cvss_v3.desc(),
        desc("affected_hosts_count")
    ).limit(limit).all()

    result = []
    for item in grouped:
        # Sample affected hosts from active scans
        sample_q = db.query(models.Host.ip_address)\
            .join(models.Vulnerability, models.Host.id == models.Vulnerability.host_id)\
            .filter(
                models.Vulnerability.plugin_id == item.plugin_id,
                models.Vulnerability.scan_id.in_(active_scan_ids)
            )
        sample_hosts = [h[0] for h in sample_q.distinct().limit(5).all()]

        cves = [c.strip() for c in CVE_PATTERN.findall(item.cve or "")] if item.cve else []
        result.append(schemas.TopCriticalVuln(
            plugin_id=item.plugin_id,
            plugin_name=item.plugin_name,
            cve=item.cve,
            cve_list=cves,
            cve_count=len(cves),
            cvss_v3=item.cvss_v3,
            severity=item.severity,
            affected_hosts_count=item.affected_hosts_count,
            exploit_available=item.exploit_available,
            exploit_frameworks=item.exploit_frameworks,
            solution=item.solution,
            synopsis=item.synopsis,
            sample_hosts=sample_hosts
        ))

    return result

@router.get("/plugin-solution/{plugin_id}", response_model=schemas.PluginSolutionOut)
def get_plugin_solution_details(
    plugin_id: str,
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna os detalhes completos do plugin, solução técnica recomendada consolidada,
    e a lista completa de todos os hosts e grupos de ativos afetados,
    sem o formulário de tratamento ISO 27001.
    """
    active_scan_ids = get_latest_scan_ids(db, asset_group_id)
    vuln_query = db.query(models.Vulnerability)\
        .join(models.Host, models.Vulnerability.host_id == models.Host.id)\
        .join(models.AssetGroup, models.Vulnerability.asset_group_id == models.AssetGroup.id)\
        .filter(models.Vulnerability.plugin_id == plugin_id)

    if active_scan_ids:
        vulns = vuln_query.filter(models.Vulnerability.scan_id.in_(active_scan_ids)).all()
    else:
        vulns = []

    # Fallback: se não houver no scan ativo (ou nenhum scan ativo), busca qualquer ocorrência para exibir metadados
    if not vulns:
        vulns = vuln_query.order_by(models.Vulnerability.id.desc()).all()

    if not vulns:
        raise HTTPException(status_code=404, detail="Plugin não encontrado na base de dados.")

    first_v = vulns[0]

    # Consolidar CVEs encontradas em todas as instâncias do plugin
    all_cves = set()
    for v in vulns:
        if v.cve:
            for c in CVE_PATTERN.findall(v.cve):
                all_cves.add(c.strip().upper())
    cve_list = sorted(list(all_cves))

    # Maior score CVSS
    cvss_v3_scores = [v.cvss_v3 for v in vulns if v.cvss_v3 is not None]
    cvss_v3_val = max(cvss_v3_scores) if cvss_v3_scores else first_v.cvss_v3
    cvss_v2_scores = [v.cvss_v2 for v in vulns if v.cvss_v2 is not None]
    cvss_v2_val = max(cvss_v2_scores) if cvss_v2_scores else first_v.cvss_v2

    has_exploit = any(v.exploit_available for v in vulns)
    exploit_fw = next((v.exploit_frameworks for v in vulns if v.exploit_frameworks), first_v.exploit_frameworks)
    synopsis = next((v.synopsis for v in vulns if v.synopsis), first_v.synopsis)
    description = next((v.description for v in vulns if v.description), first_v.description)
    solution = next((v.solution for v in vulns if v.solution), first_v.solution)
    see_also = next((v.see_also for v in vulns if v.see_also), first_v.see_also)
    plugin_output = next((v.plugin_output for v in vulns if v.plugin_output), first_v.plugin_output)

    now_utc = datetime.now(timezone.utc)
    affected_hosts = []
    for v in vulns:
        ref_dt = v.first_found or v.created_at
        if ref_dt:
            now_cmp = now_utc if ref_dt.tzinfo is not None else datetime.utcnow()
            days = max(0, (now_cmp - ref_dt).days)
        else:
            days = 0

        affected_hosts.append(schemas.AffectedHostItem(
            vuln_id=v.id,
            host_id=v.host.id,
            ip_address=v.host.ip_address,
            hostname=v.host.hostname or v.host.netbios_name or None,
            asset_group_id=v.asset_group.id,
            asset_group_name=v.asset_group.name,
            port=v.port,
            protocol=v.protocol,
            aging_days=days,
            first_found=v.first_found,
            treatment_status=v.treatment_status or "Open"
        ))

    # Ordenar por Grupo de Ativos, depois IP e Porta
    affected_hosts.sort(key=lambda h: (h.asset_group_name or "", h.ip_address or "", h.port or 0))

    return schemas.PluginSolutionOut(
        plugin_id=first_v.plugin_id,
        plugin_name=first_v.plugin_name,
        severity=first_v.severity,
        cvss_v3=cvss_v3_val,
        cvss_v2=cvss_v2_val,
        cve=first_v.cve,
        cve_list=cve_list,
        cve_count=len(cve_list),
        exploit_available=has_exploit,
        exploit_frameworks=exploit_fw,
        synopsis=synopsis,
        description=description,
        solution=solution,
        see_also=see_also,
        plugin_output=plugin_output,
        total_affected_hosts=len(affected_hosts),
        affected_hosts=affected_hosts
    )

@router.get("/top-hosts-exploits", response_model=List[schemas.TopExploitableHost])
def get_top_20_hosts_with_exploits(
    asset_group_id: Optional[int] = None,
    limit: int = Query(20, le=50),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Indicador Top 20 Hosts com Vulnerabilidades Críticas que possuem Exploits conhecidos (Metasploit, etc.),
    utilizando o scan mais recente de cada grupo de ativos.
    """
    active_scan_ids = resolve_dashboard_scan_ids(db, current_user, asset_group_id)
    if not active_scan_ids:
        return []

    host_q = db.query(models.Host)\
        .join(models.AssetGroup, models.Host.asset_group_id == models.AssetGroup.id)\
        .filter(models.Host.scan_id.in_(active_scan_ids))

    # Order by highest exploitable critical count, then risk score
    hosts = host_q.order_by(
        models.Host.exploitable_critical_count.desc(),
        models.Host.critical_count.desc(),
        models.Host.risk_score.desc()
    ).limit(limit).all()

    result = []
    for h in hosts:
        # Retrieve exploit frameworks identified on this host
        frameworks_q = db.query(models.Vulnerability.exploit_frameworks)\
            .filter(
                models.Vulnerability.host_id == h.id,
                models.Vulnerability.scan_id.in_(active_scan_ids),
                models.Vulnerability.exploit_available == True,
                models.Vulnerability.exploit_frameworks != None
            )
        frameworks_q = apply_indicator_exclusion(frameworks_q, db).distinct().all()
        
        frameworks_set = set()
        for f in frameworks_q:
            if f[0]:
                for part in f[0].split(","):
                    clean = part.strip()
                    if clean:
                        frameworks_set.add(clean)

        result.append(schemas.TopExploitableHost(
            host_id=h.id,
            ip_address=h.ip_address,
            hostname=h.hostname,
            asset_group_name=h.asset_group.name if h.asset_group else "",
            os=h.os,
            exploitable_critical_count=h.exploitable_critical_count,
            critical_count=h.critical_count,
            high_count=h.high_count,
            medium_count=h.medium_count,
            risk_score=h.risk_score,
            exploits_list=sorted(list(frameworks_set))
        ))

    return result

# Troubleshooting & Scan Error Plugin Dictionary (10107 removido)
SCAN_ERROR_PLUGINS = {
    "1102": {
        "category": "Rede / ICMP",
        "title": "Falha de Ping ICMP / Host Inacessível",
        "description": "O Nessus não obteve resposta a pacotes ICMP echo para este host.",
        "action": "Verificar se o host está ligado e se regras de firewall/antivírus bloqueiam requisições ICMP Echo."
    },
    "10180": {
        "category": "Rede / ICMP",
        "title": "Falha no Teste de Ping do Host Remoto",
        "description": "O scanner não conseguiu determinar se o host está ativo via ping.",
        "action": "Liberar tráfego ICMP entre o Nessus e o ativo, ou habilitar opção 'Do not ping the host' nas configurações do scan."
    },
    "26917": {
        "category": "Scan Incompleto",
        "title": "Informações do Scan Nessus / Scan Incompleto ou Interrompido",
        "description": "O scan foi abortado ou executado com restrições e sem checagens locais completas.",
        "action": "Verificar se a janela de scan expirou ou se o scanner foi bloqueado durante a varredura."
    },
    "24786": {
        "category": "Autenticação Windows",
        "title": "Falha nas Checagens de Credenciais Windows (SMB)",
        "description": "O Nessus não conseguiu autenticar via SMB/RPC para checagens locais no Windows.",
        "action": "Validar credenciais de domínio ou conta local de Administrador e garantir serviço 'Remote Registry' e SMB (porta 445) habilitados."
    },
    "12650": {
        "category": "Autenticação SSH",
        "title": "Nenhuma Credencial SSH Fornecida / Falha no Login",
        "description": "O acesso SSH falhou ou nenhuma credencial válida foi aceita pelo servidor Linux/Unix.",
        "action": "Cadastrar usuário e senha SSH ou chave privada SSH com permissão de login no Nessus."
    },
    "102095": {
        "category": "Permissão / Escalação",
        "title": "Comandos SSH Requerem Elevação de Privilégio (Sudo / Superusuário)",
        "description": "O usuário conectou com sucesso via SSH, mas determinados comandos de auditoria exigem elevação de privilégios (sudo/root).",
        "action": "Conceder privilégios no arquivo sudoers ou habilitar o método de escalação 'sudo' nas credenciais do scanner."
    },
    "102094": {
        "category": "Permissão / Escalação",
        "title": "Comandos SSH Requerem Escalação de Privilégio (Sudo)",
        "description": "O usuário autenticou via SSH, mas não possui permissão de root/sudo para executar comandos de auditoria.",
        "action": "Adicionar o usuário ao grupo sudoers com permissão de execução de comandos ou configurar o método de sudo no Nessus."
    },
    "104410": {
        "category": "Autenticação Windows",
        "title": "Acesso WMI Negado (Permissão Administrativa Windows)",
        "description": "A autenticação Windows teve sucesso, mas o acesso WMI/DCOM foi negado.",
        "action": "Conceder permissão ao usuário no namespace WMI (Root\\CIMV2) e liberar portas DCOM/WMI no firewall do Windows."
    },
    "21745": {
        "category": "Autenticação Geral",
        "title": "Falha Geral de Autenticação (Checagens Locais Não Executadas)",
        "description": "O scan foi executado apenas em nível de rede externa porque as checagens autenticadas falharam.",
        "action": "Cadastrar credenciais válidas com permissão de leitura de patches e configurações locais para o ativo."
    }
}

@router.get("/scan-diagnostics", response_model=schemas.ScanDiagnosticsResponse)
def get_scan_diagnostics(
    asset_group_id: Optional[int] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Verificador de Erros de Scan & Troubleshoot:
    Identifica hosts com falhas de conexão, ICMP, autenticação de login (Windows/SSH/WMI) e permissão (sudo),
    orientando a equipe para liberação de acessos antes de um novo scan (usando o scan mais recente de cada grupo).
    """
    active_scan_ids = resolve_dashboard_scan_ids(db, current_user, asset_group_id)
    if not active_scan_ids:
        return schemas.ScanDiagnosticsResponse(
            total_error_items=0,
            total_affected_hosts=0,
            auth_errors_count=0,
            connection_errors_count=0,
            permission_errors_count=0,
            incomplete_scan_count=0,
            items=[]
        )

    error_plugin_ids = list(SCAN_ERROR_PLUGINS.keys())
    
    query = db.query(models.Vulnerability)\
        .join(models.Scan, models.Vulnerability.scan_id == models.Scan.id)\
        .join(models.Host, models.Vulnerability.host_id == models.Host.id)\
        .join(models.AssetGroup, models.Vulnerability.asset_group_id == models.AssetGroup.id)\
        .filter(
            models.Vulnerability.plugin_id.in_(error_plugin_ids),
            models.Vulnerability.scan_id.in_(active_scan_ids)
        )

    if asset_group_id:
        from app.services.asset_group_service import get_descendant_group_ids
        group_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
        query = query.filter(models.Vulnerability.asset_group_id.in_(group_ids))

    raw_items = query.order_by(models.Vulnerability.created_at.desc()).all()

    auth_count = 0
    conn_count = 0
    perm_count = 0
    incomp_count = 0
    affected_hosts_set = set()

    items = []
    for v in raw_items:
        meta = SCAN_ERROR_PLUGINS.get(str(v.plugin_id), {
            "category": "Diagnóstico",
            "title": v.plugin_name,
            "description": v.synopsis or v.description or "Erro detectado no scan",
            "action": "Verificar conectividade e credenciais do ativo."
        })

        cat = meta["category"]
        if "Permissão" in cat or "Escalação" in cat:
            perm_count += 1
        elif "Autenticação" in cat:
            auth_count += 1
        elif "Rede" in cat or "Conexão" in cat or "ICMP" in cat or "Timeout" in cat:
            conn_count += 1
        elif "Incompleto" in cat or "Scan" in cat:
            incomp_count += 1

        if category and category.lower() not in cat.lower():
            continue

        host_ip_val = v.host.ip_address if v.host else "Unknown"
        host_name_val = v.host.hostname if v.host else None

        affected_hosts_set.add(host_ip_val)

        items.append(schemas.ScanDiagnosticItem(
            id=v.id,
            scan_id=v.scan_id,
            scan_name=v.scan.scan_name if v.scan else "",
            host_id=v.host_id,
            host_ip=host_ip_val,
            host_name=host_name_val,
            asset_group_id=v.asset_group_id,
            asset_group_name=v.asset_group.name if v.asset_group else "",
            plugin_id=v.plugin_id,
            plugin_name=v.plugin_name,
            category=cat,
            error_title=meta["title"],
            error_description=meta["description"],
            recommended_action=meta["action"],
            plugin_output=v.plugin_output,
            port=v.port,
            protocol=v.protocol,
            created_at=v.created_at
        ))

    return schemas.ScanDiagnosticsResponse(
        total_error_items=len(raw_items),
        total_affected_hosts=len(affected_hosts_set),
        auth_errors_count=auth_count,
        connection_errors_count=conn_count,
        permission_errors_count=perm_count,
        incomplete_scan_count=incomp_count,
        items=items
    )

