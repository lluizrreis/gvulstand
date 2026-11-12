import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app import models
from app.services.scan_service import get_latest_scan_ids

client = TestClient(app)

def get_admin_token():
    res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert res.status_code == 200
    return res.json()["access_token"]

def test_inventory_endpoint():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch general inventory
    res = client.get("/api/vulnerabilities/inventory?page=1&page_size=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert "stats" in data
    assert data["total"] > 0
    assert len(data["items"]) <= 10

    first = data["items"][0]
    assert "ip_address" in first
    assert "hostname" in first
    assert "os" in first
    assert "critical_count" in first
    assert "high_count" in first
    assert "medium_count" in first
    assert "low_count" in first
    assert "risk_score" in first

    # 2. Filter by search
    res_search = client.get(f"/api/vulnerabilities/inventory?search={first['ip_address']}", headers=headers)
    assert res_search.status_code == 200
    s_data = res_search.json()
    assert s_data["total"] >= 1
    assert any(h["ip_address"] == first["ip_address"] for h in s_data["items"])

    # 3. Filter by severity
    res_crit = client.get("/api/vulnerabilities/inventory?severity_filter=critical", headers=headers)
    assert res_crit.status_code == 200
    crit_data = res_crit.json()
    for h in crit_data["items"]:
        assert h["critical_count"] > 0

    # 4. Filter by asset group
    res_group = client.get(f"/api/vulnerabilities/inventory?asset_group_id={first['asset_group_id']}", headers=headers)
    assert res_group.status_code == 200
    g_data = res_group.json()
    assert g_data["total"] >= 1
    for h in g_data["items"]:
        assert h["asset_group_id"] == first["asset_group_id"] or h["asset_group_name"] != ""

def test_inventory_dynamic_risk_score_with_treatment():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch inventory and find a host with critical_count > 0
    res = client.get("/api/vulnerabilities/inventory?severity_filter=critical&page=1&page_size=10", headers=headers)
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) > 0
    
    target_host = None
    active_vuln_to_remediate = None
    for h in items:
        res_v = client.get(f"/api/vulnerabilities?host_id={h['id']}&severity=Critical", headers=headers)
        v_data = res_v.json()
        v_list = v_data["items"] if isinstance(v_data, dict) and "items" in v_data else v_data
        act = [v for v in v_list if v.get("treatment_status") != "Remediated"]
        if act:
            target_host = h
            active_vuln_to_remediate = act[0]
            break
            
    assert target_host is not None
    assert active_vuln_to_remediate is not None

    host_id = target_host["id"]
    initial_crit = target_host["critical_count"]
    initial_risk = target_host["risk_score"]

    # 2. Get host details endpoint to check consistency
    res_h = client.get(f"/api/vulnerabilities/hosts/{host_id}", headers=headers)
    assert res_h.status_code == 200
    assert res_h.json()["risk_score"] == initial_risk
    assert res_h.json()["critical_count"] == initial_crit

    # 3. Vulnerability to remediate
    vuln_id = active_vuln_to_remediate["id"]
    has_exploit = active_vuln_to_remediate.get("exploit_available", False)

    # 4. Mark vulnerability as Remediated
    res_treat = client.patch(
        f"/api/vulnerabilities/{vuln_id}/treatment",
        json={"treatment_status": "Remediated", "treatment_notes": "Patch de seguranca aplicado com sucesso."},
        headers=headers
    )
    assert res_treat.status_code == 200

    # 5. Fetch host inventory again
    res_after = client.get(f"/api/vulnerabilities/inventory?search={target_host['ip_address']}", headers=headers)
    assert res_after.status_code == 200
    after_items = res_after.json()["items"]
    updated_host = next(h for h in after_items if h["id"] == host_id)

    # Verify critical_count decreased by 1
    assert updated_host["critical_count"] == initial_crit - 1

    # Verify risk_score decreased by 10 (or 15 if exploit was present)
    expected_reduction = 15.0 if has_exploit else 10.0
    assert abs(updated_host["risk_score"] - (initial_risk - expected_reduction)) < 0.01

    # 6. Verify GET /api/vulnerabilities/hosts/{host_id} is also dynamically updated
    res_h_after = client.get(f"/api/vulnerabilities/hosts/{host_id}", headers=headers)
    assert res_h_after.status_code == 200
    assert res_h_after.json()["critical_count"] == initial_crit - 1
    assert abs(res_h_after.json()["risk_score"] - (initial_risk - expected_reduction)) < 0.01

def test_unique_os_and_multiselect_filters():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test unique-os endpoint
    res_os = client.get("/api/vulnerabilities/unique-os", headers=headers)
    assert res_os.status_code == 200
    os_list = res_os.json()
    assert isinstance(os_list, list)

    # 2. Test unique-hosts endpoint returns ip and hostname
    res_uh = client.get("/api/vulnerabilities/unique-hosts", headers=headers)
    assert res_uh.status_code == 200
    uh_list = res_uh.json()
    assert isinstance(uh_list, list)
    if len(uh_list) > 0:
        assert "ip" in uh_list[0]
        assert "hostname" in uh_list[0]

    # 3. Test multi-severity filtering (Critical, High, Medium, Low)
    res_multi_sev = client.get(
        "/api/vulnerabilities?severity=Critical,High,Medium,Low&page=1&page_size=50",
        headers=headers
    )
    assert res_multi_sev.status_code == 200
    data = res_multi_sev.json()
    items = data.get("items", [])
    # None of the returned items should have Info severity
    for item in items:
        assert item["severity"] in ["Critical", "High", "Medium", "Low"]
        assert item["severity"] != "Info"

    # 4. Test OS filtering if any OS exists
    if len(os_list) > 0:
        target_os = os_list[0]
        res_os_filter = client.get(
            f"/api/vulnerabilities?os={target_os}&page=1&page_size=20",
            headers=headers
        )
        assert res_os_filter.status_code == 200
