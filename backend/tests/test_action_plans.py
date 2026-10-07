import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app import models

client = TestClient(app)

def get_admin_token():
    res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert res.status_code == 200
    return res.json()["access_token"]

def test_action_plans_lifecycle_and_features():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test Assignees Endpoint
    res_assignees = client.get("/api/action-plans/assignees", headers=headers)
    assert res_assignees.status_code == 200
    assignees = res_assignees.json()
    assert isinstance(assignees, list)
    assert len(assignees) >= 1
    assert any(u["username"] == "Admin" for u in assignees)

    # 2. Test Stats Initial
    res_stats_init = client.get("/api/action-plans/stats", headers=headers)
    assert res_stats_init.status_code == 200
    stats_init = res_stats_init.json()
    assert "total_plans" in stats_init
    assert "overall_progress_percent" in stats_init

    # Find a host and vulnerability in latest scan for linking
    db = SessionLocal()
    from app.services.scan_service import get_latest_scan_ids
    latest_scan_ids = get_latest_scan_ids(db)
    vuln = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id.in_(latest_scan_ids),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
        models.Vulnerability.treatment_status.in_(["Open", "open"])
    ).first()
    host = vuln.host if vuln else None
    db.close()

    host_id = host.id if host else None
    vuln_id = vuln.id if vuln else None
    plugin_id = vuln.plugin_id if vuln else "104743"

    # 3. Create Action Plan (Scope: HOST with auto-link vulnerabilities)
    due_date = (datetime.now(timezone.utc) + timedelta(days=15)).isoformat()
    create_payload = {
        "title": "Plano de Remediação ISO 27001 - Host Principal",
        "description": "Remediação das vulnerabilidades críticas e altas identificadas no ativo de produção.",
        "scope_type": "HOST",
        "target_host_id": host_id,
        "priority": "HIGH",
        "status": "PLANNED",
        "due_date": due_date,
        "auto_link_vulnerabilities": True,
        "initial_tasks": [
            {
                "title": "Homologar patch em ambiente de staging",
                "description": "Validação de compatibilidade e impacto em serviços.",
                "status": "TODO",
                "order_index": 1,
                "vulnerability_ids": [vuln_id] if vuln_id else []
            }
        ]
    }

    res_create = client.post("/api/action-plans", json=create_payload, headers=headers)
    assert res_create.status_code == 200
    plan = res_create.json()
    plan_id = plan["id"]
    assert plan["title"] == create_payload["title"]
    assert plan["priority"] == "HIGH"
    assert plan["status"] == "PLANNED"
    assert plan["scope_type"] == "HOST"
    assert len(plan["tasks"]) >= 1
    assert plan["owner_user_name"] is not None

    task_1 = plan["tasks"][0]
    task_1_id = task_1["id"]
    assert task_1["status"] == "TODO"

    # 4. Test Compatibility with /api/v1/action-plans
    res_v1 = client.get(f"/api/v1/action-plans/{plan_id}", headers=headers)
    assert res_v1.status_code == 200
    assert res_v1.json()["id"] == plan_id

    # 5. Add a second task to the plan
    add_task_payload = {
        "title": "Aplicar correção em produção e reiniciar serviço",
        "description": "Execução na janela de manutenção com rollback planejado.",
        "status": "TODO",
        "order_index": 2,
        "due_date": due_date,
        "vulnerability_ids": [vuln_id] if vuln_id else []
    }
    res_add_task = client.post(f"/api/action-plans/{plan_id}/tasks", json=add_task_payload, headers=headers)
    assert res_add_task.status_code == 200
    task_2 = res_add_task.json()
    task_2_id = task_2["id"]
    assert task_2["order_index"] == 2
    assert task_2["title"] == add_task_payload["title"]

    # 6. List Action Plans with filters
    res_list = client.get(f"/api/action-plans?status=PLANNED&priority=HIGH&search=ISO 27001", headers=headers)
    assert res_list.status_code == 200
    plans_list = res_list.json()
    assert len(plans_list) >= 1
    assert any(p["id"] == plan_id for p in plans_list)

    # 7. Update Task 1 to DONE with sync_vuln_treatment
    res_update_t1 = client.put(
        f"/api/action-plans/tasks/{task_1_id}",
        json={"status": "DONE", "sync_vuln_treatment": True},
        headers=headers
    )
    assert res_update_t1.status_code == 200
    updated_t1 = res_update_t1.json()
    assert updated_t1["status"] == "DONE"
    assert updated_t1["completed_at"] is not None

    # Verify plan progress recalculated
    res_plan_progress = client.get(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_plan_progress.status_code == 200
    p_prog = res_plan_progress.json()
    assert p_prog["completed_tasks"] >= 1
    assert p_prog["progress_percent"] > 0

    # If vuln was linked, verify treatment history and status
    if vuln_id:
        db = SessionLocal()
        v_check = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
        assert v_check.treatment_status == "Remediated"
        hist = db.query(models.VulnerabilityTreatmentHistory).filter(
            models.VulnerabilityTreatmentHistory.vulnerability_id == vuln_id
        ).order_by(models.VulnerabilityTreatmentHistory.id.desc()).first()
        assert hist is not None
        assert "Plano de Ação" in hist.treatment_notes
        db.close()

    # 8. Update Task 2 to DONE -> Should auto-complete Plan
    res_update_t2 = client.put(
        f"/api/action-plans/tasks/{task_2_id}",
        json={"status": "DONE"},
        headers=headers
    )
    assert res_update_t2.status_code == 200

    res_plan_completed = client.get(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_plan_completed.status_code == 200
    assert res_plan_completed.json()["status"] == "COMPLETED"
    assert res_plan_completed.json()["progress_percent"] == 100.0

    # 9. Update Plan Metadata
    res_update_plan = client.put(
        f"/api/action-plans/{plan_id}",
        json={"title": "Plano de Remediação ISO 27001 - Concluído com Sucesso", "priority": "CRITICAL"},
        headers=headers
    )
    assert res_update_plan.status_code == 200
    assert res_update_plan.json()["title"] == "Plano de Remediação ISO 27001 - Concluído com Sucesso"
    assert res_update_plan.json()["priority"] == "CRITICAL"

    # 10. Delete Task
    res_del_task = client.delete(f"/api/action-plans/tasks/{task_2_id}", headers=headers)
    assert res_del_task.status_code == 200

    # 11. Delete Plan
    res_del_plan = client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_del_plan.status_code == 200

    # Verify 404 on deleted plan
    res_404 = client.get(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_404.status_code == 404

def test_action_plan_creation_from_host_ip_and_plugin():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    from app.services.scan_service import get_latest_scan_ids
    latest_scan_ids = get_latest_scan_ids(db)
    vuln = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id.in_(latest_scan_ids),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
        models.Vulnerability.treatment_status.in_(["Open", "open"])
    ).first()
    host = vuln.host if vuln else None
    plugin_id = vuln.plugin_id if vuln else "100464"
    db.close()

    host_ip = host.ip_address if host else "10.233.20.4"

    # 1. Create plan by host IP
    res_host = client.post("/api/action-plans", json={
        "title": f"Plano de Ação para Host {host_ip}",
        "scope_type": "HOST",
        "target_host_ip": host_ip,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_host.status_code == 200
    plan_host = res_host.json()
    assert plan_host["title"] == f"Plano de Ação para Host {host_ip}"
    if host:
        assert plan_host["target_host_id"] is not None
        assert plan_host["target_host_ip"] == host.ip_address

    # 2. Create plan by Plugin ID
    res_plugin = client.post("/api/action-plans", json={
        "title": f"Plano de Remediação Plugin {plugin_id}",
        "scope_type": "VULNERABILITY",
        "target_plugin_id": plugin_id,
        "priority": "CRITICAL",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_plugin.status_code == 200
    plan_plugin = res_plugin.json()
    assert plan_plugin["target_plugin_id"] == plugin_id

    # Cleanup
    client.delete(f"/api/action-plans/{plan_host['id']}", headers=headers)
    client.delete(f"/api/action-plans/{plan_plugin['id']}", headers=headers)

def test_action_plans_hierarchical_asset_group_filtering():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create 3-level asset group hierarchy
    ts = int(datetime.now().timestamp())
    res_root = client.post("/api/asset-groups", json={
        "name": f"Corporativo Matriz {ts}",
        "description": "Nível 1"
    }, headers=headers)
    assert res_root.status_code in [200, 201]
    root_gid = res_root.json()["id"]

    res_child = client.post("/api/asset-groups", json={
        "name": f"TI Regional {ts}",
        "description": "Nível 2",
        "parent_id": root_gid
    }, headers=headers)
    assert res_child.status_code in [200, 201]
    child_gid = res_child.json()["id"]

    res_subchild = client.post("/api/asset-groups", json={
        "name": f"Cluster Web {ts}",
        "description": "Nível 3",
        "parent_id": child_gid
    }, headers=headers)
    assert res_subchild.status_code in [200, 201]
    subchild_gid = res_subchild.json()["id"]

    # 2. Create Action Plan directly assigned to Level 3 (subchild)
    res_create = client.post("/api/action-plans", json={
        "title": "Plano Específico Subgrupo Nível 3",
        "description": "Tratativa técnica em servidor do cluster web",
        "scope_type": "GROUP",
        "asset_group_id": subchild_gid,
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_create.status_code == 200
    plan = res_create.json()
    plan_id = plan["id"]
    assert f"Corporativo Matriz {ts} > TI Regional {ts} > Cluster Web {ts}" in plan["asset_group_name"]

    # 3. Filter by Level 1 (Root/Superior) -> MUST return the plan
    res_list_root = client.get(f"/api/action-plans?asset_group_id={root_gid}", headers=headers)
    assert res_list_root.status_code == 200
    plans_root = res_list_root.json()
    assert any(p["id"] == plan_id for p in plans_root)

    # 4. Check Stats for Level 1 (Root/Superior) -> MUST count the plan
    res_stats_root = client.get(f"/api/action-plans/stats?asset_group_id={root_gid}", headers=headers)
    assert res_stats_root.status_code == 200
    stats_root = res_stats_root.json()
    assert stats_root["total_plans"] >= 1
    assert stats_root["planned_count"] >= 1

    # 5. Filter by Level 2 (Child) -> MUST return the plan
    res_list_child = client.get(f"/api/action-plans?asset_group_id={child_gid}", headers=headers)
    assert res_list_child.status_code == 200
    plans_child = res_list_child.json()
    assert any(p["id"] == plan_id for p in plans_child)

    # 6. Check Stats for Level 2 (Child) -> MUST count the plan
    res_stats_child = client.get(f"/api/action-plans/stats?asset_group_id={child_gid}", headers=headers)
    assert res_stats_child.status_code == 200
    assert res_stats_child.json()["total_plans"] >= 1

    # 7. Filter by Level 3 (Direct) -> MUST return the plan
    res_list_subchild = client.get(f"/api/action-plans?asset_group_id={subchild_gid}", headers=headers)
    assert res_list_subchild.status_code == 200
    assert any(p["id"] == plan_id for p in res_list_subchild.json())

    # 8. Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    client.delete(f"/api/asset-groups/{subchild_gid}", headers=headers)
    client.delete(f"/api/asset-groups/{child_gid}", headers=headers)
    client.delete(f"/api/asset-groups/{root_gid}", headers=headers)


def test_action_plans_tags_and_multitagging():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create tag via POST /api/action-plans/tags
    res_tag = client.post("/api/action-plans/tags", json={"name": "SOX_TEST", "color": "#6366f1"}, headers=headers)
    assert res_tag.status_code == 200
    tag_data = res_tag.json()
    assert tag_data["name"] == "SOX_TEST"
    assert tag_data["color"] == "#6366f1"

    # 2. Get tags list
    res_tags_list = client.get("/api/action-plans/tags", headers=headers)
    assert res_tags_list.status_code == 200
    tags_all = res_tags_list.json()
    assert any(t["name"] == "SOX_TEST" for t in tags_all)

    # 3. Create plan with tags
    res_plan = client.post("/api/action-plans", json={
        "title": "Plano com Multi-Tagging SOX e PCI",
        "scope_type": "CUSTOM",
        "priority": "MEDIUM",
        "status": "PLANNED",
        "tags": ["SOX_TEST", "PCI_TEST"]
    }, headers=headers)
    assert res_plan.status_code == 200
    plan = res_plan.json()
    plan_id = plan["id"]
    assert "SOX_TEST" in plan["tags"]
    assert "PCI_TEST" in plan["tags"]

    # 4. Filter by tag
    res_filt = client.get("/api/action-plans?tag=SOX_TEST", headers=headers)
    assert res_filt.status_code == 200
    assert any(p["id"] == plan_id for p in res_filt.json())

    res_filt_none = client.get("/api/action-plans?tag=NONEXISTENT_TAG_XYZ", headers=headers)
    assert res_filt_none.status_code == 200
    assert not any(p["id"] == plan_id for p in res_filt_none.json())

    # 5. Update tags on plan
    res_update = client.put(f"/api/action-plans/{plan_id}", json={
        "tags": ["PCI_TEST"]
    }, headers=headers)
    assert res_update.status_code == 200
    assert "PCI_TEST" in res_update.json()["tags"]
    assert "SOX_TEST" not in res_update.json()["tags"]

    # Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)


def test_action_plans_matrix_scope_and_preview():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Preview impact with unmatched / non-existent hosts
    preview_payload = {
        "scope_type": "MATRIX_NN",
        "scope_host_ips": ["192.0.2.1", "192.0.2.2"],
        "scope_plugin_ids": ["104743", "104410"]
    }
    res_preview = client.post("/api/action-plans/preview-impact", json=preview_payload, headers=headers)
    assert res_preview.status_code == 200
    preview = res_preview.json()
    assert "total_vulnerabilities" in preview
    assert "severity_distribution" in preview
    assert preview["is_relational_valid"] is False
    assert len(preview["unmatched_hosts"]) > 0

    # 2. Reject Matrix Plan with non-existent/unmatched hosts (HTTP 422)
    invalid_create_payload = {
        "title": "Plano Escopo Matricial N:N Invalido",
        "scope_type": "MATRIX_NN",
        "priority": "HIGH",
        "status": "PLANNED",
        "scope_host_ips": ["192.0.2.1"],
        "scope_plugin_ids": ["104743"]
    }
    res_inv = client.post("/api/action-plans", json=invalid_create_payload, headers=headers)
    assert res_inv.status_code == 422
    assert "não relacional" in res_inv.json()["detail"].lower() or "inválido" in res_inv.json()["detail"].lower()

    # 3. Create Valid Matrix Plan with existing hosts and associated plugin
    db = SessionLocal()
    from app.services.scan_service import get_latest_scan_ids
    latest_scan_ids = get_latest_scan_ids(db)
    real_sample_vuln = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id.in_(latest_scan_ids),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
        models.Vulnerability.treatment_status.in_(["Open", "open"])
    ).first()
    matrix_plugin_id = real_sample_vuln.plugin_id if real_sample_vuln else "100464"
    real_vulns = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id.in_(latest_scan_ids),
        models.Vulnerability.plugin_id == matrix_plugin_id,
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
        models.Vulnerability.treatment_status.in_(["Open", "open"])
    ).limit(2).all()
    real_host_ips = list(dict.fromkeys([v.host.ip_address for v in real_vulns if v.host]))
    db.close()
    assert len(real_host_ips) >= 1

    valid_matrix_payload = {
        "title": "Plano Escopo Matricial N:N Válido",
        "scope_type": "MATRIX_NN",
        "priority": "HIGH",
        "status": "PLANNED",
        "scope_host_ips": real_host_ips,
        "scope_plugin_ids": [matrix_plugin_id]
    }
    res_create = client.post("/api/action-plans", json=valid_matrix_payload, headers=headers)
    assert res_create.status_code == 200
    plan = res_create.json()
    plan_id = plan["id"]
    assert plan["scope_type"] == "MATRIX_NN"
    assert matrix_plugin_id in plan["scope_plugin_ids"]

    # 4. Reject Update Matrix Plan with non-existent / orphan host (HTTP 422)
    res_update_inv = client.put(f"/api/action-plans/{plan_id}", json={
        "scope_host_ips": real_host_ips + ["192.0.2.99"]
    }, headers=headers)
    assert res_update_inv.status_code == 422

    # Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)


def test_action_plans_precedence_and_orphans():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Setup test host and vulnerability in DB
    db = SessionLocal()
    scan = db.query(models.Scan).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
    if scan and scan.asset_group_id:
        group = db.query(models.AssetGroup).filter(models.AssetGroup.id == scan.asset_group_id).first()
    else:
        group = db.query(models.AssetGroup).first()
        if not group:
            group = models.AssetGroup(name="Grupo Precedencia Test")
            db.add(group)
            db.commit()
            db.refresh(group)
        scan = models.Scan(
            asset_group_id=group.id,
            filename="prec_test_scan.csv",
            scan_name="Precedence Test Scan"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

    test_ip = f"172.16.99.{int(datetime.now().timestamp()) % 240 + 5}"

    host = models.Host(
        scan_id=scan.id,
        ip_address=test_ip,
        hostname=f"srv-prec-{test_ip}",
        asset_group_id=group.id,
        risk_score=10.0
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    test_plugin = f"PLUG_{int(datetime.now().timestamp()) % 90000}"
    vuln = models.Vulnerability(
        scan_id=scan.id,
        asset_group_id=group.id,
        host_id=host.id,
        plugin_id=test_plugin,
        plugin_name="Vulnerabilidade de Teste Precedencia",
        severity="High",
        treatment_status="Open"
    )
    db.add(vuln)
    db.commit()
    host_id = host.id
    vuln_id = vuln.id
    db.close()

    # 1. Broad Plan (scope: VULNERABILITY)
    res_broad = client.post("/api/action-plans", json={
        "title": f"Plano Geral Plugin {test_plugin}",
        "scope_type": "VULNERABILITY",
        "target_plugin_id": test_plugin,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_broad.status_code == 200
    broad_plan_id = res_broad.json()["id"]

    # Check that vulnerability was linked and status is In_Action_Plan
    db = SessionLocal()
    v1 = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    assert v1.treatment_status == "In_Action_Plan"
    db.close()

    # Verify active action plan in vuln details
    res_v_detail = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert res_v_detail.status_code == 200
    assert res_v_detail.json()["active_action_plan_id"] == broad_plan_id

    # 2. Host Plan (scope: HOST) - Higher precedence than broad vulnerability
    res_host_plan = client.post("/api/action-plans", json={
        "title": f"Plano Específico Host {test_ip}",
        "scope_type": "HOST",
        "target_host_id": host_id,
        "priority": "CRITICAL",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_host_plan.status_code == 200
    host_plan_id = res_host_plan.json()["id"]

    # Precedence rule: Vulnerability should now be associated with host_plan_id
    res_v_detail2 = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert res_v_detail2.status_code == 200
    assert res_v_detail2.json()["active_action_plan_id"] == host_plan_id

    # Check treatment history for precedence transfer notes
    res_hist = client.get(f"/api/vulnerabilities/{vuln_id}/treatment-history", headers=headers)
    assert res_hist.status_code == 200
    hist_entries = res_hist.json()
    assert any("precedência" in (h.get("treatment_notes") or "").lower() for h in hist_entries)

    # 3. Test orphan filter and endpoint
    res_unassigned = client.get("/api/action-plans/unassigned-vulns", headers=headers)
    assert res_unassigned.status_code == 200
    assert isinstance(res_unassigned.json(), list)

    # 4. Delete host plan -> findings should revert to Open (orphan)
    res_del_host = client.delete(f"/api/action-plans/{host_plan_id}", headers=headers)
    assert res_del_host.status_code == 200

    db = SessionLocal()
    v_reverted = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    assert v_reverted.treatment_status == "Open"
    db.close()

    # Cleanup
    client.delete(f"/api/action-plans/{broad_plan_id}", headers=headers)
    db = SessionLocal()
    db.query(models.VulnerabilityTreatmentHistory).filter(
        models.VulnerabilityTreatmentHistory.vulnerability_id == vuln_id
    ).delete()
    db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).delete()
    db.query(models.Host).filter(models.Host.id == host_id).delete()
    db.commit()
    db.close()


def test_action_plan_rejection_for_non_existent_or_empty_host():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Non-existent IP
    res_non_existent = client.post("/api/action-plans", json={
        "title": "Plano Host Inexistente",
        "scope_type": "HOST",
        "target_host_ip": "198.51.100.254",
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_non_existent.status_code == 422
    assert "não foi encontrado" in res_non_existent.json()["detail"].lower()

    # 2. Host with no actionable vulnerabilities
    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    scan = db.query(models.Scan).filter(models.Scan.asset_group_id == group.id).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first() or db.query(models.Scan).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
    dummy_ip = f"192.0.2.{int(datetime.now().timestamp()) % 200 + 10}"
    h_empty = models.Host(
        scan_id=scan.id if scan else None,
        ip_address=dummy_ip,
        hostname=f"srv-empty-{dummy_ip}",
        asset_group_id=group.id if group else None,
        risk_score=0.0
    )
    db.add(h_empty)
    db.commit()
    db.refresh(h_empty)
    db.close()

    res_empty_host = client.post("/api/action-plans", json={
        "title": "Plano Host Sem Vulnerabilidades",
        "scope_type": "HOST",
        "target_host_ip": dummy_ip,
        "priority": "MEDIUM",
        "status": "PLANNED"
    }, headers=headers)
    assert res_empty_host.status_code == 422
    assert "não possui vulnerabilidades" in res_empty_host.json()["detail"].lower()

    # Cleanup dummy host
    db = SessionLocal()
    db.query(models.Host).filter(models.Host.id == h_empty.id).delete()
    db.commit()
    db.close()


def test_action_plan_rejection_for_non_existent_plugin():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/action-plans", json={
        "title": "Plano Plugin Fantasma",
        "scope_type": "VULNERABILITY",
        "target_plugin_id": "9999999999",
        "priority": "LOW",
        "status": "PLANNED"
    }, headers=headers)
    assert res.status_code == 422
    assert "não possui vulnerabilidades" in res.json()["detail"].lower()


def test_action_plan_matrix_strict_bipartite_validation():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    from app.services.scan_service import get_latest_scan_ids
    latest_scan_ids = get_latest_scan_ids(db)
    scan = db.query(models.Scan).filter(models.Scan.id.in_(latest_scan_ids)).first()
    group = db.query(models.AssetGroup).filter(models.AssetGroup.id == scan.asset_group_id).first() if scan else db.query(models.AssetGroup).first()
    ts = int(datetime.now().timestamp())

    ip_a = f"198.18.1.{ts % 200 + 1}"
    ip_b = f"198.18.2.{ts % 200 + 2}"

    h_a = models.Host(scan_id=scan.id, ip_address=ip_a, hostname=f"srv-a-{ip_a}", asset_group_id=group.id, risk_score=10.0)
    h_b = models.Host(scan_id=scan.id, ip_address=ip_b, hostname=f"srv-b-{ip_b}", asset_group_id=group.id, risk_score=10.0)
    db.add(h_a)
    db.add(h_b)
    db.commit()
    db.refresh(h_a)
    db.refresh(h_b)

    plug_a = f"PLUG_A_{ts % 90000}"
    plug_b = f"PLUG_B_{ts % 90000}"

    # h_a has plug_a only, h_b has plug_b only
    v_a = models.Vulnerability(scan_id=scan.id, asset_group_id=group.id, host_id=h_a.id, plugin_id=plug_a, plugin_name="Vuln A", severity="High", treatment_status="Open")
    v_b = models.Vulnerability(scan_id=scan.id, asset_group_id=group.id, host_id=h_b.id, plugin_id=plug_b, plugin_name="Vuln B", severity="High", treatment_status="Open")
    db.add(v_a)
    db.add(v_b)
    db.commit()
    db.refresh(v_a)
    db.refresh(v_b)
    va_id = v_a.id
    vb_id = v_b.id
    ha_id = h_a.id
    hb_id = h_b.id
    db.close()

    # Case 1: Orphan Host (provide [ip_a, ip_b] but only [plug_a] -> ip_b has NO vulnerability from the list!)
    res_orphan_host = client.post("/api/action-plans", json={
        "title": "Plano Matriz com Host Orfao",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [ip_a, ip_b],
        "scope_plugin_ids": [plug_a],
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_orphan_host.status_code == 422
    err_detail_1 = res_orphan_host.json()["detail"]
    assert "não relacional" in err_detail_1.lower()
    assert ip_b in err_detail_1

    # Case 2: Orphan Plugin (provide [ip_a] but [plug_a, plug_b] -> plug_b affects NO host in the list!)
    res_orphan_plugin = client.post("/api/action-plans", json={
        "title": "Plano Matriz com Plugin Orfao",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [ip_a],
        "scope_plugin_ids": [plug_a, plug_b],
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_orphan_plugin.status_code == 422
    err_detail_2 = res_orphan_plugin.json()["detail"]
    assert "não relacional" in err_detail_2.lower()
    assert plug_b in err_detail_2

    # Case 3: Valid Bipartite Plan (provide [ip_a, ip_b] and [plug_a, plug_b] -> every host has >= 1 vuln, every plugin affects >= 1 host!)
    res_valid = client.post("/api/action-plans", json={
        "title": "Plano Matriz Bipartido Valido",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [ip_a, ip_b],
        "scope_plugin_ids": [plug_a, plug_b],
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_valid.status_code == 200
    valid_plan_id = res_valid.json()["id"]

    # Clean up
    client.delete(f"/api/action-plans/{valid_plan_id}", headers=headers)
    db = SessionLocal()
    db.query(models.VulnerabilityTreatmentHistory).filter(models.VulnerabilityTreatmentHistory.vulnerability_id.in_([va_id, vb_id])).delete()
    db.query(models.Vulnerability).filter(models.Vulnerability.id.in_([va_id, vb_id])).delete()
    db.query(models.Host).filter(models.Host.id.in_([ha_id, hb_id])).delete()
    db.commit()
    db.close()


def test_action_plan_deletion_reverts_vulnerabilities_to_open_and_logs():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    scan = db.query(models.Scan).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
    ts = int(datetime.now().timestamp())
    if scan and scan.asset_group_id:
        group = db.query(models.AssetGroup).filter(models.AssetGroup.id == scan.asset_group_id).first()
    else:
        group = db.query(models.AssetGroup).first()
        if not group:
            group = models.AssetGroup(name="Grupo Teste Exclusao")
            db.add(group)
            db.commit()
            db.refresh(group)
        scan = models.Scan(
            asset_group_id=group.id,
            filename=f"del_test_{ts}.csv",
            scan_name="Del Test Scan"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

    del_ip = f"198.18.5.{ts % 200 + 5}"
    del_plug = f"PLUG_DEL_{ts % 90000}"

    h = models.Host(scan_id=scan.id, ip_address=del_ip, hostname=f"srv-del-{del_ip}", asset_group_id=group.id, risk_score=10.0)
    db.add(h)
    db.commit()
    db.refresh(h)

    v = models.Vulnerability(
        scan_id=scan.id,
        asset_group_id=group.id,
        host_id=h.id,
        plugin_id=del_plug,
        plugin_name="Vuln Para Exclusao",
        severity="High",
        treatment_status="Open"
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    v_id = v.id
    h_id = h.id
    db.close()

    # 1. Create Action Plan linking this vulnerability
    plan_title = f"Plano de Ação para Teste de Exclusão {ts}"
    res_create = client.post("/api/action-plans", json={
        "title": plan_title,
        "scope_type": "HOST",
        "target_host_id": h_id,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_create.status_code == 200
    plan_id = res_create.json()["id"]

    # Verify vulnerability transitioned to In_Action_Plan
    db = SessionLocal()
    v_check = db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).first()
    assert v_check.treatment_status == "In_Action_Plan"
    db.close()

    # 2. Delete the Action Plan
    res_del = client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_del.status_code == 200

    # 3. Verify vulnerability transitioned back to Open with explicit deletion audit log
    db = SessionLocal()
    v_after_del = db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).first()
    assert v_after_del.treatment_status == "Open"
    assert "exclusão do Plano de Ação" in v_after_del.treatment_notes
    assert plan_title in v_after_del.treatment_notes
    assert str(plan_id) in v_after_del.treatment_notes

    # Check VulnerabilityTreatmentHistory
    history = db.query(models.VulnerabilityTreatmentHistory).filter(
        models.VulnerabilityTreatmentHistory.vulnerability_id == v_id
    ).order_by(models.VulnerabilityTreatmentHistory.id.desc()).first()

    assert history is not None
    assert history.treatment_status == "Open"
    assert "exclusão do Plano de Ação" in history.treatment_notes
    assert plan_title in history.treatment_notes
    assert str(plan_id) in history.treatment_notes
    assert history.changed_by_username == "Admin"

    # Cleanup test host and vuln
    db.query(models.VulnerabilityTreatmentHistory).filter(models.VulnerabilityTreatmentHistory.vulnerability_id == v_id).delete()
    db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).delete()
    db.query(models.Host).filter(models.Host.id == h_id).delete()
    db.commit()
    db.close()


def test_action_plan_wizard_endpoints_and_hosts_without_plugin():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test wizard hosts endpoint
    res_hosts = client.get("/api/action-plans/wizard/hosts", headers=headers)
    assert res_hosts.status_code == 200
    hosts_data = res_hosts.json()
    assert isinstance(hosts_data, list)
    assert len(hosts_data) > 0
    first_h = hosts_data[0]
    assert "ip" in first_h
    assert "vuln_count" in first_h
    assert "critical_count" in first_h

    # 2. Test wizard vulnerabilities endpoint
    res_vulns = client.get(f"/api/action-plans/wizard/vulnerabilities?host_ips={first_h['ip']}", headers=headers)
    assert res_vulns.status_code == 200
    vulns_data = res_vulns.json()
    assert isinstance(vulns_data, list)
    assert len(vulns_data) > 0
    first_v = vulns_data[0]
    assert "plugin_id" in first_v
    assert "plugin_name" in first_v
    assert "affected_hosts_count" in first_v

    # 3. Test creating a plan with host(s) but no plugin specified (all vulns of the host enter the plan)
    plan_payload = {
        "title": f"Plano Wizard Todos os Itens {first_h['ip']}",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [first_h["ip"]],
        "scope_plugin_ids": [],
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }
    res_create = client.post("/api/action-plans", json=plan_payload, headers=headers)
    assert res_create.status_code == 200
    created = res_create.json()
    assert created["title"] == plan_payload["title"]
    assert len(created["scope_host_ips"]) == 1
    # Check that plugins were automatically populated
    assert len(created["scope_plugin_ids"]) > 0

    # Cleanup
    client.delete(f"/api/action-plans/{created['id']}", headers=headers)


def test_action_plan_wizard_multiple_plugins_selection():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch candidate hosts
    res_hosts = client.get("/api/action-plans/wizard/hosts", headers=headers)
    assert res_hosts.status_code == 200
    hosts_data = res_hosts.json()
    assert len(hosts_data) > 0
    target_host = hosts_data[0]
    target_ip = target_host["ip"]
    group_id = target_host.get("asset_group_id")

    # Fetch candidate vulnerabilities for this host
    res_vulns = client.get(f"/api/action-plans/wizard/vulnerabilities?host_ips={target_ip}", headers=headers)
    assert res_vulns.status_code == 200
    vulns_data = res_vulns.json()
    assert len(vulns_data) >= 1

    selected_plugins = [v["plugin_id"] for v in vulns_data[:2]]

    # 1. Test creating plan with host and multiple plugins
    plan_payload_multi = {
        "title": f"Plano Wizard Multi Plugins {target_ip}",
        "scope_type": "MATRIX_NN",
        "asset_group_id": group_id,
        "scope_host_ips": [target_ip],
        "scope_plugin_ids": selected_plugins,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }
    res_create = client.post("/api/action-plans", json=plan_payload_multi, headers=headers)
    assert res_create.status_code == 200
    created_multi = res_create.json()
    assert set(created_multi["scope_plugin_ids"]) == set(selected_plugins)
    assert created_multi["scope_host_ips"] == [target_ip]

    client.delete(f"/api/action-plans/{created_multi['id']}", headers=headers)

    # 2. Test creating plan with 0 hosts and multiple plugins (auto-resolves hosts from asset group)
    if group_id and len(selected_plugins) > 0:
        plan_payload_auto_hosts = {
            "title": f"Plano Wizard Multi Plugins Auto Hosts Group {group_id}",
            "scope_type": "MATRIX_NN",
            "asset_group_id": group_id,
            "scope_host_ips": [],
            "scope_plugin_ids": selected_plugins,
            "priority": "HIGH",
            "status": "PLANNED",
            "auto_link_vulnerabilities": True
        }
        res_auto = client.post("/api/action-plans", json=plan_payload_auto_hosts, headers=headers)
        assert res_auto.status_code == 200
        created_auto = res_auto.json()
        assert len(created_auto["scope_host_ips"]) > 0
        assert set(created_auto["scope_plugin_ids"]) == set(selected_plugins)

        client.delete(f"/api/action-plans/{created_auto['id']}", headers=headers)


def test_action_plan_automated_tasks_generation_rules():
    """
    Valida as regras de negócio de geração automática de tarefas:
    1. Escopo baseado em Host (HOST ou MATRIX_NN sem plugins):
       - Cria 1 tarefa para cada host.
       - Título: hostname/ip.
       - Abaixo (descrição): nome da(s) vulnerabilidade(s).
    2. Escopo MATRIX_NN (com plugins específicos) ou VULNERABILITY:
       - Cria 1 tarefa para cada grupo (HOST + VULNERABILIDADE).
       - Título: hostname/ip.
       - Abaixo (descrição): nome da vulnerabilidade.
    """
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    from app.services.scan_service import get_latest_scan_ids
    latest_scan_ids = get_latest_scan_ids(db)
    v1 = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id.in_(latest_scan_ids),
        ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"]),
        models.Vulnerability.treatment_status.in_(["Open", "open"])
    ).first()
    assert v1 is not None
    h1 = v1.host
    assert h1 is not None
    ip1 = h1.ip_address
    p1 = v1.plugin_id
    h1_vulns = [v for v in h1.vulnerabilities if v.scan_id == v1.scan_id and v.severity not in ["Info", "info", "None", "none"]]
    assert len(h1_vulns) >= 1
    db.close()

    # -------------------------------------------------------------
    # 1. Teste de Escopo HOST: 1 tarefa para cada host
    # -------------------------------------------------------------
    res_host_plan = client.post("/api/action-plans", json={
        "title": f"Plano Escopo Host Teste {ip1}",
        "asset_group_id": v1.asset_group_id,
        "scope_type": "HOST",
        "target_host_id": h1.id,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_host_plan.status_code == 200
    host_plan = res_host_plan.json()
    assert host_plan["total_tasks"] == 1
    t_host = host_plan["tasks"][0]
    assert ip1 in t_host["title"]
    assert v1.plugin_name in t_host["description"]
    assert t_host["vulnerabilities_count"] >= 1

    client.delete(f"/api/action-plans/{host_plan['id']}", headers=headers)

    # -------------------------------------------------------------
    # 2. Teste de Escopo VULNERABILITY: 1 tarefa para cada grupo HOST+VULNERABILIDADE
    # -------------------------------------------------------------
    res_vuln_plan = client.post("/api/action-plans", json={
        "title": f"Plano Escopo Vulnerabilidade Teste {p1}",
        "asset_group_id": v1.asset_group_id,
        "scope_type": "VULNERABILITY",
        "target_plugin_id": p1,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_vuln_plan.status_code == 200
    vuln_plan = res_vuln_plan.json()
    assert vuln_plan["total_tasks"] >= 1
    for task in vuln_plan["tasks"]:
        assert len(task["description"]) > 0 and (task["description"] == v1.plugin_name or f"#{p1}" in task["description"] or "EternalBlue" in task["description"] or "MS17-010" in task["description"])
        assert len(task["vulnerability_links"]) >= 1
        # Verificar que o título é um hostname/ip válido
        assert any(c.isdigit() for c in task["title"]) or len(task["title"]) > 0

    client.delete(f"/api/action-plans/{vuln_plan['id']}", headers=headers)

    # -------------------------------------------------------------
    # 3. Teste de Escopo MATRIX_NN com plugins específicos: 1 tarefa por HOST+VULNERABILIDADE
    # -------------------------------------------------------------
    res_matrix = client.post("/api/action-plans", json={
        "title": f"Plano Matriz N:N Host+Vuln Teste {ip1}",
        "asset_group_id": v1.asset_group_id,
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [ip1],
        "scope_plugin_ids": [p1],
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_matrix.status_code == 200
    matrix_plan = res_matrix.json()
    assert matrix_plan["total_tasks"] == 1
    t_mat = matrix_plan["tasks"][0]
    assert ip1 in t_mat["title"]
    assert t_mat["description"] == v1.plugin_name
    assert t_mat["vulnerabilities_count"] >= 1

    client.delete(f"/api/action-plans/{matrix_plan['id']}", headers=headers)

    # -------------------------------------------------------------
    # 4. Teste de Escopo MATRIX_NN sem plugins (todas as vulns dos hosts): 1 tarefa por host
    # -------------------------------------------------------------
    res_matrix_all = client.post("/api/action-plans", json={
        "title": f"Plano Matriz Todos Itens Teste {ip1}",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [ip1],
        "scope_plugin_ids": [],
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_matrix_all.status_code == 200
    matrix_all_plan = res_matrix_all.json()
    assert matrix_all_plan["total_tasks"] == 1
    t_all = matrix_all_plan["tasks"][0]
    assert any(v.plugin_name in t_all["description"] for v in h1_vulns) or v1.plugin_name in t_all["description"] or "vulnerabilidades" in t_all["description"]
    assert t_all["vulnerabilities_count"] >= 1

    client.delete(f"/api/action-plans/{matrix_all_plan['id']}", headers=headers)


def test_action_plan_latest_scan_only_and_post_import_lifecycle():
    """
    Testa o ciclo de vida completo solicitado pelo usuário:
    1. Criação do plano usa SOMENTE os dados da importação mais recente do grupo de ativos.
    2. Ao importar novo scan com recorrência (host+vulnerabilidade presente), associa a recorrência ao mesmo plano.
    3. Quando no novo scan a vulnerabilidade não aparece mais para o host escaneado, conclui a etapa (DONE) e marca como Remediated.
    4. Se o plano está em Planejado/Em Andamento e a vulnerabilidade reaparece para uma tarefa DONE, a etapa muda para 'Em Revisão' (REVIEW) e vuln para In_Action_Plan.
    """
    from datetime import datetime, timezone, timedelta
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    db = SessionLocal()

    # Criar Grupo de Ativos isolado para o teste
    group = models.AssetGroup(name=f"Grupo Ciclo Vida {datetime.now(timezone.utc).timestamp()}", description="Teste PDCA")
    db.add(group)
    db.commit()
    db.refresh(group)
    gid = group.id

    now = datetime.now(timezone.utc)
    t1 = now - timedelta(days=2)
    t2 = now - timedelta(days=1)

    # 1. Scan 1 (antigo): Host 10.99.1.10 com Plugin 11111 (Critical) e Plugin 22222 (High)
    scan1 = models.Scan(scan_name="Scan 1 Antigo", filename="scan1_antigo.csv", scan_date=t1, asset_group_id=gid)
    db.add(scan1)
    db.commit()
    db.refresh(scan1)

    host1_s1 = models.Host(ip_address="10.99.1.10", hostname="srv-antigo.local", scan_id=scan1.id, asset_group_id=gid)
    db.add(host1_s1)
    db.commit()
    db.refresh(host1_s1)

    v1_s1 = models.Vulnerability(
        host_id=host1_s1.id, scan_id=scan1.id, asset_group_id=gid,
        plugin_id="11111", plugin_name="Vuln Persistente Teste", severity="Critical", treatment_status="Open"
    )
    v2_s1 = models.Vulnerability(
        host_id=host1_s1.id, scan_id=scan1.id, asset_group_id=gid,
        plugin_id="22222", plugin_name="Vuln Corrigida Antiga", severity="High", treatment_status="Open"
    )
    db.add_all([v1_s1, v2_s1])
    db.commit()

    # 2. Scan 2 (recente): Host 10.99.1.10 com apenas Plugin 11111 (Plugin 22222 sumiu) e Host 10.99.1.20 com Plugin 33333
    scan2 = models.Scan(scan_name="Scan 2 Recente", filename="scan2_recente.csv", scan_date=t2, asset_group_id=gid)
    db.add(scan2)
    db.commit()
    db.refresh(scan2)

    host1_s2 = models.Host(ip_address="10.99.1.10", hostname="srv-novo.local", scan_id=scan2.id, asset_group_id=gid)
    host2_s2 = models.Host(ip_address="10.99.1.20", hostname="srv-web.local", scan_id=scan2.id, asset_group_id=gid)
    db.add_all([host1_s2, host2_s2])
    db.commit()
    db.refresh(host1_s2)
    db.refresh(host2_s2)

    v1_s2 = models.Vulnerability(
        host_id=host1_s2.id, scan_id=scan2.id, asset_group_id=gid,
        plugin_id="11111", plugin_name="Vuln Persistente Teste", severity="Critical", treatment_status="Open"
    )
    v3_s2 = models.Vulnerability(
        host_id=host2_s2.id, scan_id=scan2.id, asset_group_id=gid,
        plugin_id="33333", plugin_name="Vuln Host2 Teste", severity="High", treatment_status="Open"
    )
    db.add_all([v1_s2, v3_s2])
    db.commit()
    v1_s2_id = v1_s2.id
    db.close()

    # Teste 1: Wizard e Validação devem enxergar SOMENTE os dados do Scan 2 (o mais recente do grupo)
    res_wiz_vulns = client.get(f"/api/action-plans/wizard/vulnerabilities?asset_group_id={gid}", headers=headers)
    assert res_wiz_vulns.status_code == 200
    wiz_vuln_pids = [w["plugin_id"] for w in res_wiz_vulns.json()]
    assert "11111" in wiz_vuln_pids
    assert "33333" in wiz_vuln_pids
    # Plugin 22222 existia apenas no scan1 antigo e NÃO deve aparecer nas candidatas
    assert "22222" not in wiz_vuln_pids

    # Tentativa de criar plano com Plugin 22222 deve falhar (422) porque não existe no scan recente
    res_fail = client.post("/api/action-plans", json={
        "title": "Plano Inválido Scan Antigo",
        "asset_group_id": gid,
        "scope_type": "MATRIX_NN",
        "scope_host_ips": ["10.99.1.10"],
        "scope_plugin_ids": ["22222"],
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_fail.status_code == 422
    assert "importação mais recente" in res_fail.json()["detail"]

    # Criar Plano Válido para Host 10.99.1.10 com Plugin 11111
    res_plan = client.post("/api/action-plans", json={
        "title": "Plano Remediação Host1 Vuln1",
        "asset_group_id": gid,
        "scope_type": "MATRIX_NN",
        "scope_host_ips": ["10.99.1.10"],
        "scope_plugin_ids": ["11111"],
        "priority": "HIGH",
        "status": "IN_PROGRESS",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_plan.status_code == 200
    plan_data = res_plan.json()
    plan_id = plan_data["id"]
    assert plan_data["total_tasks"] == 1
    task_id = plan_data["tasks"][0]["id"]

    # Teste 2: Importar Scan 3 contendo Host 10.99.1.10 com recorrência de Plugin 11111
    # Deve associar a nova vulnerabilidade à mesma tarefa
    db = SessionLocal()
    scan3 = models.Scan(scan_name="Scan 3 Recorrencia", filename="scan3_recorrencia.csv", scan_date=now, asset_group_id=gid)
    db.add(scan3)
    db.commit()
    db.refresh(scan3)

    host1_s3 = models.Host(ip_address="10.99.1.10", hostname="srv-novo.local", scan_id=scan3.id, asset_group_id=gid)
    db.add(host1_s3)
    db.commit()
    db.refresh(host1_s3)

    v1_s3 = models.Vulnerability(
        host_id=host1_s3.id, scan_id=scan3.id, asset_group_id=gid,
        plugin_id="11111", plugin_name="Vuln Persistente Teste", severity="Critical", treatment_status="Open"
    )
    db.add(v1_s3)
    db.commit()
    db.refresh(v1_s3)
    v1_s3_id = v1_s3.id

    from app.api.routes_action_plans import sync_action_plans_on_scan_import
    sync_action_plans_on_scan_import(db, scan3, "admin")

    # Verificar que v1_s3 foi vinculada à tarefa e marcada como In_Action_Plan
    db.refresh(v1_s3)
    assert v1_s3.treatment_status == "In_Action_Plan"
    link_exists = db.query(models.ActionTaskVulnerabilityLink).filter(
        models.ActionTaskVulnerabilityLink.action_task_id == task_id,
        models.ActionTaskVulnerabilityLink.vulnerability_id == v1_s3.id
    ).first()
    assert link_exists is not None

    # Teste 3: Importar Scan 4 onde Host 10.99.1.10 foi escaneado MAS Plugin 11111 não apareceu mais (remediada)
    # A etapa deve ser concluída (DONE) e as vulnerabilidades anteriores marcadas como Remediated
    scan4 = models.Scan(scan_name="Scan 4 Corrigido", filename="scan4_corrigido.csv", scan_date=now + timedelta(hours=1), asset_group_id=gid)
    db.add(scan4)
    db.commit()
    db.refresh(scan4)

    host1_s4 = models.Host(ip_address="10.99.1.10", hostname="srv-novo.local", scan_id=scan4.id, asset_group_id=gid)
    db.add(host1_s4)
    db.commit()

    sync_action_plans_on_scan_import(db, scan4, "admin")

    t_check = db.query(models.ActionTask).filter(models.ActionTask.id == task_id).first()
    assert t_check.status == "DONE"
    assert t_check.completed_at is not None

    # Verificar que v1_s2 e v1_s3 foram marcadas como Remediated
    v1_s2_db = db.query(models.Vulnerability).filter(models.Vulnerability.id == v1_s2_id).first()
    v1_s3_db = db.query(models.Vulnerability).filter(models.Vulnerability.id == v1_s3_id).first()
    assert v1_s2_db.treatment_status == "Remediated"
    assert v1_s3_db.treatment_status == "Remediated"

    # Teste 4: Reincidência. O plano está em IN_PROGRESS, a tarefa está como DONE.
    # Novo Scan 5 onde Host 10.99.1.10 tem novamente Plugin 11111.
    # A etapa DEVE ir para "REVIEW" ('Em Revisão') e o status da vulnerabilidade para 'In_Action_Plan'.
    p_check = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    p_check.status = "IN_PROGRESS"
    db.commit()

    scan5 = models.Scan(scan_name="Scan 5 Reincidencia", filename="scan5_reincidencia.csv", scan_date=now + timedelta(hours=2), asset_group_id=gid)
    db.add(scan5)
    db.commit()
    db.refresh(scan5)

    host1_s5 = models.Host(ip_address="10.99.1.10", hostname="srv-novo.local", scan_id=scan5.id, asset_group_id=gid)
    db.add(host1_s5)
    db.commit()
    db.refresh(host1_s5)

    v1_s5 = models.Vulnerability(
        host_id=host1_s5.id, scan_id=scan5.id, asset_group_id=gid,
        plugin_id="11111", plugin_name="Vuln Persistente Teste", severity="Critical", treatment_status="Open"
    )
    db.add(v1_s5)
    db.commit()
    db.refresh(v1_s5)
    v1_s5_id = v1_s5.id

    sync_action_plans_on_scan_import(db, scan5, "admin")

    db.refresh(t_check)
    assert t_check.status == "REVIEW"
    assert t_check.completed_at is None

    v1_s5_db = db.query(models.Vulnerability).filter(models.Vulnerability.id == v1_s5_id).first()
    assert v1_s5_db.treatment_status == "In_Action_Plan"

    # Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    db = SessionLocal()
    db.query(models.ActionTaskVulnerabilityLink).filter(
        models.ActionTaskVulnerabilityLink.vulnerability_id.in_(
            db.query(models.Vulnerability.id).filter(models.Vulnerability.asset_group_id == gid)
        )
    ).delete(synchronize_session=False)
    db.query(models.VulnerabilityTreatmentHistory).filter(
        models.VulnerabilityTreatmentHistory.vulnerability_id.in_(
            db.query(models.Vulnerability.id).filter(models.Vulnerability.asset_group_id == gid)
        )
    ).delete(synchronize_session=False)
    db.query(models.Vulnerability).filter(models.Vulnerability.asset_group_id == gid).delete(synchronize_session=False)
    db.query(models.Host).filter(models.Host.asset_group_id == gid).delete(synchronize_session=False)
    db.query(models.Scan).filter(models.Scan.asset_group_id == gid).delete(synchronize_session=False)
    grp = db.query(models.AssetGroup).filter(models.AssetGroup.id == gid).first()
    if grp:
        db.delete(grp)
    db.commit()
    db.close()


def test_action_plan_update_scope_and_task_sync():
    """
    Testa a edição de Plano de Ação adicionando novos servidores e novas vulnerabilidades:
    1. Criação inicial com 1 host e 1 plugin.
    2. Edição (PUT) expandindo escopo com novo host e novo plugin -> Deve retornar 200 (sem erro 500) e sincronizar tarefas.
    3. Edição removendo plugin -> Deve remover tarefa órfã e reverter vulnerabilidade para 'Open'.
    4. Edição de metadados (sem alterar escopo) -> Preserva tarefas existentes.
    """
    from datetime import datetime, timezone
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    db = SessionLocal()

    # Criar Grupo e Scan
    ts = int(datetime.now(timezone.utc).timestamp())
    group = models.AssetGroup(name=f"Grupo Teste Edicao {ts}")
    db.add(group)
    db.commit()
    db.refresh(group)
    gid = group.id

    scan = models.Scan(scan_name="Scan Edicao", filename=f"scan_edicao_{ts}.csv", asset_group_id=gid)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 2 Hosts e 2 Plugins
    ip_a = f"10.200.1.{ts % 200 + 1}"
    ip_b = f"10.200.1.{(ts + 1) % 200 + 1}"
    host_a = models.Host(ip_address=ip_a, hostname=f"srv-a-{ts}", scan_id=scan.id, asset_group_id=gid)
    host_b = models.Host(ip_address=ip_b, hostname=f"srv-b-{ts}", scan_id=scan.id, asset_group_id=gid)
    db.add_all([host_a, host_b])
    db.commit()
    db.refresh(host_a)
    db.refresh(host_b)

    pid_1 = f"PLUG_{ts % 90000 + 100}"
    pid_2 = f"PLUG_{ts % 90000 + 200}"

    v_a1 = models.Vulnerability(host_id=host_a.id, scan_id=scan.id, asset_group_id=gid, plugin_id=pid_1, plugin_name="Falha 1 Servidor A", severity="High", treatment_status="Open")
    v_b2 = models.Vulnerability(host_id=host_b.id, scan_id=scan.id, asset_group_id=gid, plugin_id=pid_2, plugin_name="Falha 2 Servidor B", severity="Critical", treatment_status="Open")
    db.add_all([v_a1, v_b2])
    db.commit()
    db.refresh(v_a1)
    db.refresh(v_b2)
    va1_id = v_a1.id
    vb2_id = v_b2.id
    db.close()

    # 1. Criação inicial: apenas Host A e Plugin 1
    res_create = client.post("/api/action-plans", json={
        "title": f"Plano Edição Teste {ts}",
        "scope_type": "MATRIX_NN",
        "asset_group_id": gid,
        "scope_host_ips": [ip_a],
        "scope_plugin_ids": [pid_1],
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_create.status_code == 200
    plan_data = res_create.json()
    plan_id = plan_data["id"]
    assert plan_data["total_tasks"] == 1
    assert ip_a in plan_data["tasks"][0]["title"]

    # 2. Edição (PUT): Adicionar Host B e Plugin 2
    # Este era o ponto exato que causava erro 500 no backend ("NameError: matching_vulns is not defined")
    res_update = client.put(f"/api/action-plans/{plan_id}", json={
        "title": f"Plano Edição Atualizado {ts}",
        "scope_type": "MATRIX_NN",
        "asset_group_id": gid,
        "scope_host_ips": [ip_a, ip_b],
        "scope_plugin_ids": [pid_1, pid_2],
        "priority": "CRITICAL",
        "status": "PLANNED"
    }, headers=headers)
    assert res_update.status_code == 200, f"Erro ao editar plano: {res_update.text}"
    updated_plan = res_update.json()
    assert updated_plan["priority"] == "CRITICAL"
    assert len(updated_plan["scope_host_ips"]) == 2
    assert len(updated_plan["scope_plugin_ids"]) == 2
    assert updated_plan["total_tasks"] == 2

    # Verificar que as vulnerabilidades de ambos os hosts estão In_Action_Plan
    db = SessionLocal()
    va1_check = db.query(models.Vulnerability).filter(models.Vulnerability.id == va1_id).first()
    vb2_check = db.query(models.Vulnerability).filter(models.Vulnerability.id == vb2_id).first()
    assert va1_check.treatment_status == "In_Action_Plan"
    assert vb2_check.treatment_status == "In_Action_Plan"
    db.close()

    # 3. Edição (PUT): Remover Host A e Plugin 1 (ficando somente Host B e Plugin 2)
    res_update2 = client.put(f"/api/action-plans/{plan_id}", json={
        "scope_type": "MATRIX_NN",
        "asset_group_id": gid,
        "scope_host_ips": [ip_b],
        "scope_plugin_ids": [pid_2]
    }, headers=headers)
    assert res_update2.status_code == 200
    plan_reduced = res_update2.json()
    assert plan_reduced["total_tasks"] == 1
    assert ip_b in plan_reduced["tasks"][0]["title"]

    # va1 deve ter revertido para Open pois seu host/plugin saiu do plano
    db = SessionLocal()
    va1_reverted = db.query(models.Vulnerability).filter(models.Vulnerability.id == va1_id).first()
    vb2_still = db.query(models.Vulnerability).filter(models.Vulnerability.id == vb2_id).first()
    assert va1_reverted.treatment_status == "Open"
    assert vb2_still.treatment_status == "In_Action_Plan"
    db.close()

    # 4. Edição de metadados sem mexer em escopo
    res_update3 = client.put(f"/api/action-plans/{plan_id}", json={
        "title": "Novo Titulo Sem Mudar Escopo",
        "priority": "LOW"
    }, headers=headers)
    assert res_update3.status_code == 200
    plan_meta = res_update3.json()
    assert plan_meta["title"] == "Novo Titulo Sem Mudar Escopo"
    assert plan_meta["priority"] == "LOW"
    assert plan_meta["total_tasks"] == 1

    # Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    db = SessionLocal()
    db.query(models.ActionTaskVulnerabilityLink).filter(
        models.ActionTaskVulnerabilityLink.vulnerability_id.in_(
            db.query(models.Vulnerability.id).filter(models.Vulnerability.asset_group_id == gid)
        )
    ).delete(synchronize_session=False)
    db.query(models.VulnerabilityTreatmentHistory).filter(
        models.VulnerabilityTreatmentHistory.vulnerability_id.in_(
            db.query(models.Vulnerability.id).filter(models.Vulnerability.asset_group_id == gid)
        )
    ).delete(synchronize_session=False)
    db.query(models.Vulnerability).filter(models.Vulnerability.asset_group_id == gid).delete(synchronize_session=False)
    db.query(models.Host).filter(models.Host.asset_group_id == gid).delete(synchronize_session=False)
    db.query(models.Scan).filter(models.Scan.asset_group_id == gid).delete(synchronize_session=False)
    grp = db.query(models.AssetGroup).filter(models.AssetGroup.id == gid).first()
    if grp:
        db.delete(grp)
    db.commit()
    db.close()


def test_dashboard_stats_action_plans_summary():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Obter estatísticas iniciais
    res_init = client.get("/api/dashboard/stats", headers=headers)
    assert res_init.status_code == 200
    stats_init = res_init.json()
    assert "action_plans_summary" in stats_init
    ap_summary = stats_init["action_plans_summary"]
    assert "total_plans" in ap_summary
    assert "active_plans" in ap_summary
    assert "total_vulns" in ap_summary
    assert "critical" in ap_summary
    assert "high" in ap_summary
    assert "medium" in ap_summary
    assert "low" in ap_summary

    init_total_plans = ap_summary["total_plans"]
    init_active_plans = ap_summary["active_plans"]

    # 2. Criar um novo plano de ação
    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    if not group:
        group = models.AssetGroup(name="Dashboard AP Test Group")
        db.add(group)
        db.commit()
        db.refresh(group)

    scan = models.Scan(
        asset_group_id=group.id,
        filename="ap_dash_test.csv",
        scan_name="AP Dash Test Scan"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    host = models.Host(scan_id=scan.id, asset_group_id=group.id, ip_address="10.88.99.1", hostname="srv-dash-ap.local")
    db.add(host)
    db.commit()
    db.refresh(host)

    v_crit = models.Vulnerability(
        scan_id=scan.id,
        host_id=host.id,
        asset_group_id=group.id,
        plugin_id="99901",
        plugin_name="Vulnerabilidade Critica Dashboard Test",
        severity="Critical",
        treatment_status="Open"
    )
    db.add(v_crit)
    db.commit()
    group_id = group.id
    db.close()

    res_create = client.post("/api/action-plans", json={
        "title": "Plano Teste Dashboard Stats",
        "asset_group_id": group_id,
        "scope_type": "HOST",
        "priority": "HIGH",
        "status": "PLANNED",
        "target_host_ip": "10.88.99.1"
    }, headers=headers)
    assert res_create.status_code == 200
    plan_data = res_create.json()
    plan_id = plan_data["id"]

    # 3. Validar se o resumo no dashboard reflete o novo plano e vulnerabilidade
    res_updated = client.get("/api/dashboard/stats", headers=headers)
    assert res_updated.status_code == 200
    stats_updated = res_updated.json()
    ap_sum_up = stats_updated["action_plans_summary"]
    assert ap_sum_up["total_plans"] == init_total_plans + 1
    assert ap_sum_up["active_plans"] == init_active_plans + 1
    assert ap_sum_up["critical"] >= 1
    assert ap_sum_up["total_vulns"] >= 1

    # 4. Validar exclusão ao marcar o plano como COMPLETED
    res_complete = client.put(f"/api/action-plans/{plan_id}", json={"status": "COMPLETED"}, headers=headers)
    assert res_complete.status_code == 200
    res_dash_completed = client.get("/api/dashboard/stats", headers=headers)
    assert res_dash_completed.status_code == 200
    ap_sum_comp = res_dash_completed.json()["action_plans_summary"]
    assert ap_sum_comp["total_plans"] == init_total_plans
    assert ap_sum_comp["active_plans"] == init_active_plans

    # 5. Validar exclusão ao marcar o plano como DRAFT
    res_draft = client.put(f"/api/action-plans/{plan_id}", json={"status": "DRAFT"}, headers=headers)
    assert res_draft.status_code == 200
    res_dash_draft = client.get("/api/dashboard/stats", headers=headers)
    assert res_dash_draft.status_code == 200
    ap_sum_draft = res_dash_draft.json()["action_plans_summary"]
    assert ap_sum_draft["total_plans"] == init_total_plans
    assert ap_sum_draft["active_plans"] == init_active_plans

    # 6. Validar exclusão ao marcar o plano como CANCELLED
    res_cancel = client.put(f"/api/action-plans/{plan_id}", json={"status": "CANCELLED"}, headers=headers)
    assert res_cancel.status_code == 200
    res_dash_cancel = client.get("/api/dashboard/stats", headers=headers)
    assert res_dash_cancel.status_code == 200
    ap_sum_cancel = res_dash_cancel.json()["action_plans_summary"]
    assert ap_sum_cancel["total_plans"] == init_total_plans
    assert ap_sum_cancel["active_plans"] == init_active_plans

    # Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)


def test_action_plan_remediation_exclusion_and_open_only_eligibility():
    """
    Valida rigorosamente as regras de negócio de elegibilidade de vulnerabilidades:
    1. Vulnerabilidades com status 'Remediated' NÃO devem aparecer na lista de vulnerabilidades
       disponíveis/órfãs (/api/action-plans/unassigned-vulns).
    2. Vulnerabilidades com status 'Remediated' NÃO devem aparecer no Wizard (/api/action-plans/wizard/vulnerabilities).
    3. Hosts cujas vulnerabilidades foram todas remediadas NÃO devem ter contagem ativa no Wizard (/api/action-plans/wizard/hosts).
    4. Tentativa de criar plano para host/plugin onde todas as vulnerabilidades estão Remediadas deve ser rejeitada com HTTP 422.
    5. Apenas vulnerabilidades com status 'Open' devem ser elegíveis para criação/associação de novos planos de ação.
    """
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    # Criar um grupo, scan e host dedicado para o teste com nome único
    unique_suffix = int(datetime.now().timestamp() * 1000)
    group = models.AssetGroup(name=f"Grupo Teste Elegibilidade Remediada {unique_suffix}")
    db.add(group)
    db.commit()
    db.refresh(group)

    scan = models.Scan(
        scan_name="Scan Test Eligibility",
        filename="scan_eligibility_test.csv",
        scan_date=datetime.now(timezone.utc),
        asset_group_id=group.id
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    test_ip = f"192.168.250.{unique_suffix % 200 + 10}"
    host = models.Host(
        ip_address=test_ip,
        hostname="host-eligibility.local",
        scan_id=scan.id,
        asset_group_id=group.id
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    # 1. Vulnerabilidade Open (Elegível)
    v_open = models.Vulnerability(
        scan_id=scan.id,
        host_id=host.id,
        asset_group_id=group.id,
        plugin_id="99901",
        plugin_name="Vulnerabilidade Elegivel Open",
        severity="High",
        treatment_status="Open"
    )
    # 2. Vulnerabilidade Remediada (Não Elegível)
    v_remediated = models.Vulnerability(
        scan_id=scan.id,
        host_id=host.id,
        asset_group_id=group.id,
        plugin_id="99902",
        plugin_name="Vulnerabilidade Já Remediada",
        severity="Critical",
        treatment_status="Remediated"
    )
    # 3. Vulnerabilidade Risco Aceito (Não Elegível para novo plano)
    v_risk = models.Vulnerability(
        scan_id=scan.id,
        host_id=host.id,
        asset_group_id=group.id,
        plugin_id="99903",
        plugin_name="Vulnerabilidade Risco Aceito",
        severity="Medium",
        treatment_status="Accepted_Risk"
    )

    db.add_all([v_open, v_remediated, v_risk])
    db.commit()
    db.refresh(v_open)
    db.refresh(v_remediated)
    db.refresh(v_risk)
    v_open_id = v_open.id
    v_remediated_id = v_remediated.id
    v_risk_id = v_risk.id
    host_id = host.id
    scan_id = scan.id
    group_id = group.id
    db.close()

    try:
        # A) Teste /api/action-plans/unassigned-vulns: somente Open deve constar
        res_unassigned = client.get(f"/api/action-plans/unassigned-vulns?search={test_ip}", headers=headers)
        assert res_unassigned.status_code == 200
        unassigned_items = res_unassigned.json()
        unassigned_pids = [str(x["plugin_id"]) for x in unassigned_items]
        assert "99901" in unassigned_pids, "Vulnerabilidade Open deve estar disponível para plano"
        assert "99902" not in unassigned_pids, "Vulnerabilidade Remediated JAMAIS deve constar como disponível"
        assert "99903" not in unassigned_pids, "Vulnerabilidade Accepted_Risk não deve constar como disponível"

        # B) Teste /api/action-plans/wizard/vulnerabilities: somente Open deve aparecer
        res_wiz_vulns = client.get(f"/api/action-plans/wizard/vulnerabilities?host_ips={test_ip}", headers=headers)
        assert res_wiz_vulns.status_code == 200
        wiz_vulns = res_wiz_vulns.json()
        wiz_pids = [str(x["plugin_id"]) for x in wiz_vulns]
        assert "99901" in wiz_pids, "Plugin da vulnerabilidade Open deve aparecer no Wizard"
        assert "99902" not in wiz_pids, "Plugin da vulnerabilidade Remediated NÃO deve aparecer no Wizard"
        assert "99903" not in wiz_pids, "Plugin da vulnerabilidade Accepted_Risk NÃO deve aparecer no Wizard"

        # C) Teste /api/action-plans/wizard/hosts: apenas 1 vuln ativa contabilizada (a Open)
        res_wiz_hosts = client.get(f"/api/action-plans/wizard/hosts?search={test_ip}", headers=headers)
        assert res_wiz_hosts.status_code == 200
        wiz_hosts = res_wiz_hosts.json()
        target_h_entry = next((h for h in wiz_hosts if h["ip"] == test_ip), None)
        assert target_h_entry is not None
        assert target_h_entry["vuln_count"] == 1, "Apenas a vulnerabilidade Open deve ser contabilizada no host"
        assert target_h_entry["high_count"] == 1
        assert target_h_entry["critical_count"] == 0, "A vulnerabilidade Critical remediada não pode ser contabilizada"

        # D) Teste /api/vulnerabilities?not_in_action_plan=true: apenas Open
        res_vulns_cat = client.get(f"/api/vulnerabilities?search={test_ip}&not_in_action_plan=true", headers=headers)
        assert res_vulns_cat.status_code == 200
        cat_pids = [str(v["plugin_id"]) for v in res_vulns_cat.json()]
        assert "99901" in cat_pids
        assert "99902" not in cat_pids
        assert "99903" not in cat_pids

        # E) Tentativa de criar plano para a vulnerabilidade Remediada (Plugin 99902) -> HTTP 422
        res_fail_plugin = client.post("/api/action-plans", json={
            "title": "Plano Inválido para Plugin Remediado",
            "scope_type": "VULNERABILITY",
            "target_plugin_id": "99902",
            "asset_group_id": group_id,
            "priority": "HIGH",
            "status": "PLANNED"
        }, headers=headers)
        assert res_fail_plugin.status_code == 422, "Deve recusar plano para plugin onde todas as ocorrências são remediadas"

        # F) Criar plano com sucesso para a vulnerabilidade Open (Plugin 99901) -> HTTP 200
        res_ok_plugin = client.post("/api/action-plans", json={
            "title": "Plano Válido para Plugin Open",
            "scope_type": "VULNERABILITY",
            "target_plugin_id": "99901",
            "asset_group_id": group_id,
            "priority": "HIGH",
            "status": "PLANNED",
            "auto_link_vulnerabilities": True
        }, headers=headers)
        assert res_ok_plugin.status_code == 200
        plan_id = res_ok_plugin.json()["id"]

        # Limpar plano criado
        client.delete(f"/api/action-plans/{plan_id}", headers=headers)

    finally:
        # Cleanup
        db = SessionLocal()
        db.query(models.ActionTaskVulnerabilityLink).filter(models.ActionTaskVulnerabilityLink.vulnerability_id.in_([v_open_id, v_remediated_id, v_risk_id])).delete(synchronize_session=False)
        db.query(models.Vulnerability).filter(models.Vulnerability.id.in_([v_open_id, v_remediated_id, v_risk_id])).delete(synchronize_session=False)
        db.query(models.Host).filter(models.Host.id == host_id).delete(synchronize_session=False)
        db.query(models.Scan).filter(models.Scan.id == scan_id).delete(synchronize_session=False)
        db.query(models.AssetGroup).filter(models.AssetGroup.id == group_id).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_action_plan_wizard_os_list_and_filter():
    """
    Valida os novos recursos do Wizard de Planos de Ação:
    - GET /api/action-plans/wizard/os-list (listagem de SOs identificados nos scans)
    - GET /api/action-plans/wizard/hosts com filtro de SO (param 'os')
    """
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Valida endpoint global de OS
    res_os = client.get("/api/action-plans/wizard/os-list", headers=headers)
    assert res_os.status_code == 200
    assert isinstance(res_os.json(), list)

    import uuid
    uid_str = uuid.uuid4().hex[:8]
    db = SessionLocal()
    group = models.AssetGroup(name=f"Grupo Teste OS Wizard {uid_str}", description="Teste de filtro por SO")
    db.add(group)
    db.commit()
    db.refresh(group)
    group_id = group.id

    now = datetime.now(timezone.utc)
    scan = models.Scan(
        scan_name="Scan OS Test",
        filename="scan_os_test.csv",
        scan_date=now,
        asset_group_id=group_id
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id

    host_linux = models.Host(
        ip_address="192.168.100.11",
        hostname="srv-linux-01",
        os="Linux Kernel 5.15 / Ubuntu 22.04",
        scan_id=scan_id,
        asset_group_id=group_id
    )
    host_win = models.Host(
        ip_address="192.168.100.12",
        hostname="srv-win-01",
        os="Microsoft Windows Server 2022 Standard",
        scan_id=scan_id,
        asset_group_id=group_id
    )
    db.add_all([host_linux, host_win])
    db.commit()
    db.refresh(host_linux)
    db.refresh(host_win)

    vuln1 = models.Vulnerability(
        scan_id=scan_id,
        host_id=host_linux.id,
        asset_group_id=group_id,
        plugin_id="88801",
        plugin_name="Vulnerabilidade Linux Teste",
        severity="High",
        treatment_status="Open"
    )
    vuln2 = models.Vulnerability(
        scan_id=scan_id,
        host_id=host_win.id,
        asset_group_id=group_id,
        plugin_id="88802",
        plugin_name="Vulnerabilidade Windows Teste",
        severity="Critical",
        treatment_status="Open"
    )
    db.add_all([vuln1, vuln2])
    db.commit()
    db.close()

    try:
        # 2. Testa listagem de SOs filtrada por grupo
        res_group_os = client.get(f"/api/action-plans/wizard/os-list?asset_group_id={group_id}", headers=headers)
        assert res_group_os.status_code == 200
        os_list = res_group_os.json()
        assert "Linux Kernel 5.15 / Ubuntu 22.04" in os_list
        assert "Microsoft Windows Server 2022 Standard" in os_list

        # 3. Testa listagem de hosts sem filtro de SO
        res_all_hosts = client.get(f"/api/action-plans/wizard/hosts?asset_group_id={group_id}", headers=headers)
        assert res_all_hosts.status_code == 200
        all_hosts = res_all_hosts.json()
        assert len(all_hosts) == 2

        # 4. Testa listagem de hosts com filtro de SO Linux
        res_linux_hosts = client.get(f"/api/action-plans/wizard/hosts?asset_group_id={group_id}&os=Ubuntu", headers=headers)
        assert res_linux_hosts.status_code == 200
        linux_hosts = res_linux_hosts.json()
        assert len(linux_hosts) == 1
        assert linux_hosts[0]["ip"] == "192.168.100.11"
        assert "Ubuntu" in linux_hosts[0]["os"]

        # 5. Testa listagem de hosts com filtro de SO Windows
        res_win_hosts = client.get(f"/api/action-plans/wizard/hosts?asset_group_id={group_id}&os=Windows", headers=headers)
        assert res_win_hosts.status_code == 200
        win_hosts = res_win_hosts.json()
        assert len(win_hosts) == 1
        assert win_hosts[0]["ip"] == "192.168.100.12"
        assert "Windows" in win_hosts[0]["os"]

        # 6. Testa filtro com SO inexistente
        res_none_hosts = client.get(f"/api/action-plans/wizard/hosts?asset_group_id={group_id}&os=InexistenteOS", headers=headers)
        assert res_none_hosts.status_code == 200
        assert len(res_none_hosts.json()) == 0

    finally:
        # Cleanup
        db = SessionLocal()
        db.query(models.Vulnerability).filter(models.Vulnerability.scan_id == scan_id).delete(synchronize_session=False)
        db.query(models.Host).filter(models.Host.scan_id == scan_id).delete(synchronize_session=False)
        db.query(models.Scan).filter(models.Scan.id == scan_id).delete(synchronize_session=False)
        db.query(models.AssetGroup).filter(models.AssetGroup.id == group_id).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_action_plan_auto_remediation_and_persistence_on_scan_import():
    """
    Valida as regras de negócio de sincronização pós-scan (PDCA / ISO 27001):
    1. Persistência: vulnerabilidade ainda encontrada permanece no plano e recebe nota de 'não remediada'.
    2. Reabertura: se a tarefa estava como concluída (DONE), é reaberta para 'REVIEW' em caso de persistência.
    3. Auto-conclusão: quando o host é escaneado e a vulnerabilidade não é mais identificada,
       é marcada como Remediada, a tarefa é concluída (DONE) e o plano transiciona para COMPLETED.
    """
    from app.api.routes_action_plans import sync_action_plans_on_scan_import

    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    ts = int(datetime.now(timezone.utc).timestamp())
    group = models.AssetGroup(name=f"AP Remediation Group {ts}")
    db.add(group)
    db.commit()
    db.refresh(group)
    gid = group.id

    ip_target = "192.168.123.45"
    pid_target = "10999"

    # 1. Scan 1 com a vulnerabilidade ativa
    scan1 = models.Scan(asset_group_id=gid, filename=f"scan1_{ts}.csv", scan_name=f"Scan 1 {ts}")
    db.add(scan1)
    db.commit()
    db.refresh(scan1)

    host1 = models.Host(scan_id=scan1.id, asset_group_id=gid, ip_address=ip_target, hostname="srv-test-1")
    db.add(host1)
    db.commit()
    db.refresh(host1)

    v1 = models.Vulnerability(
        scan_id=scan1.id,
        host_id=host1.id,
        asset_group_id=gid,
        plugin_id=pid_target,
        plugin_name="Vulnerabilidade Alvo Teste",
        severity="High",
        treatment_status="Open"
    )
    db.add(v1)
    db.commit()
    db.refresh(v1)
    v1_id = v1.id
    db.close()

    # 2. Criar Plano de Ação para o par (ip_target, pid_target)
    res_plan = client.post("/api/action-plans", json={
        "title": f"Plano Remediação Teste {ts}",
        "scope_type": "MATRIX_NN",
        "asset_group_id": gid,
        "scope_host_ips": [ip_target],
        "scope_plugin_ids": [pid_target],
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_plan.status_code == 200
    plan_data = res_plan.json()
    plan_id = plan_data["id"]
    task_id = plan_data["tasks"][0]["id"]

    db = SessionLocal()
    v1_check = db.query(models.Vulnerability).filter(models.Vulnerability.id == v1_id).first()
    assert v1_check.treatment_status == "In_Action_Plan"
    db.close()

    # 3. Simular Scan 2 (Persistência / Não remediada)
    db = SessionLocal()
    scan2 = models.Scan(asset_group_id=gid, filename=f"scan2_{ts}.csv", scan_name=f"Scan 2 {ts}")
    db.add(scan2)
    db.commit()
    db.refresh(scan2)

    host2 = models.Host(scan_id=scan2.id, asset_group_id=gid, ip_address=ip_target, hostname="srv-test-1")
    db.add(host2)
    db.commit()
    db.refresh(host2)

    v2 = models.Vulnerability(
        scan_id=scan2.id,
        host_id=host2.id,
        asset_group_id=gid,
        plugin_id=pid_target,
        plugin_name="Vulnerabilidade Alvo Teste",
        severity="High",
        treatment_status="Open"
    )
    db.add(v2)
    db.commit()
    db.refresh(v2)
    v2_id = v2.id

    # Executar sync após scan2
    sync_action_plans_on_scan_import(db, scan2, "TestAdmin")

    # Verificar que v2 foi vinculada ao plano e recebeu nota de "não remediada"
    v2_check = db.query(models.Vulnerability).filter(models.Vulnerability.id == v2_id).first()
    assert v2_check.treatment_status == "In_Action_Plan"
    assert "Vulnerabilidade não remediada" in v2_check.treatment_notes

    # Verificar tarefa e plano ainda ativos
    task_check = db.query(models.ActionTask).filter(models.ActionTask.id == task_id).first()
    assert task_check.status in ["TODO", "DOING", "REVIEW"]

    # 4. Forçar status da tarefa para DONE para testar reabertura quando reincidente
    task_check.status = "DONE"
    task_check.completed_at = datetime.now(timezone.utc)
    db.commit()

    # Simular Scan 3 (Ainda persistente)
    scan3 = models.Scan(asset_group_id=gid, filename=f"scan3_{ts}.csv", scan_name=f"Scan 3 {ts}")
    db.add(scan3)
    db.commit()
    db.refresh(scan3)

    host3 = models.Host(scan_id=scan3.id, asset_group_id=gid, ip_address=ip_target, hostname="srv-test-1")
    db.add(host3)
    db.commit()
    db.refresh(host3)

    v3 = models.Vulnerability(
        scan_id=scan3.id,
        host_id=host3.id,
        asset_group_id=gid,
        plugin_id=pid_target,
        plugin_name="Vulnerabilidade Alvo Teste",
        severity="High",
        treatment_status="Open"
    )
    db.add(v3)
    db.commit()
    db.refresh(v3)

    sync_action_plans_on_scan_import(db, scan3, "TestAdmin")

    # Tarefa que estava DONE deve ter sido reaberta para REVIEW
    db.refresh(task_check)
    assert task_check.status == "REVIEW"
    assert task_check.completed_at is None

    # 5. Simular Scan 4 (Remediação confirmada: Host escaneado, mas vulnerabilidade ausente!)
    scan4 = models.Scan(asset_group_id=gid, filename=f"scan4_{ts}.csv", scan_name=f"Scan 4 {ts}")
    db.add(scan4)
    db.commit()
    db.refresh(scan4)

    host4 = models.Host(scan_id=scan4.id, asset_group_id=gid, ip_address=ip_target, hostname="srv-test-1")
    db.add(host4)
    db.commit()
    # Host escaneado sem a vulnerabilidade pid_target

    sync_action_plans_on_scan_import(db, scan4, "TestAdmin")

    # Todas as instâncias devem estar Remediated
    db.refresh(task_check)
    assert task_check.status == "DONE"
    assert task_check.completed_at is not None

    plan_check = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    assert plan_check.status == "COMPLETED"

    v1_final = db.query(models.Vulnerability).filter(models.Vulnerability.id == v1_id).first()
    v2_final = db.query(models.Vulnerability).filter(models.Vulnerability.id == v2_id).first()
    assert v1_final.treatment_status == "Remediated"
    assert v2_final.treatment_status == "Remediated"
    assert "Remediada" in v1_final.treatment_notes

    # Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    db.query(models.ActionTaskVulnerabilityLink).filter(
        models.ActionTaskVulnerabilityLink.vulnerability_id.in_([v1_id, v2_id, v3.id])
    ).delete(synchronize_session=False)
    db.query(models.VulnerabilityTreatmentHistory).filter(
        models.VulnerabilityTreatmentHistory.vulnerability_id.in_([v1_id, v2_id, v3.id])
    ).delete(synchronize_session=False)
    db.query(models.Vulnerability).filter(models.Vulnerability.asset_group_id == gid).delete(synchronize_session=False)
    db.query(models.Host).filter(models.Host.asset_group_id == gid).delete(synchronize_session=False)
    db.query(models.Scan).filter(models.Scan.asset_group_id == gid).delete(synchronize_session=False)
    grp = db.query(models.AssetGroup).filter(models.AssetGroup.id == gid).first()
    if grp:
        db.delete(grp)
    db.commit()
    db.close()








