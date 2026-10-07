import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.main import app
from app import models
from app.auth import get_password_hash

test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="module", autouse=True)
def setup_test_environment():
    prev_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()

    # Seed Admin & Analyst users
    admin = models.User(
        username="AdminParams",
        email="admin_params@gvulstand.local",
        full_name="Admin Params",
        hashed_password=get_password_hash("Admin123"),
        role="admin",
        is_active=True
    )
    analyst = models.User(
        username="AnalystParams",
        email="analyst_params@gvulstand.local",
        full_name="Analyst Params",
        hashed_password=get_password_hash("Analyst123"),
        role="analyst",
        is_active=True
    )
    db.add_all([admin, analyst])

    # Seed an Asset Group
    group = models.AssetGroup(
        name="Param-Test-Group",
        description="Test Group for Parameters",
        sla_critical_days=7,
        sla_high_days=15,
        sla_medium_days=30,
        sla_low_days=60
    )
    db.add(group)
    db.commit()
    db.refresh(group)

    # Seed a Scan, Host, and 2 Vulnerabilities (one Critical Plugin 50001, one High Plugin 50002)
    scan = models.Scan(
        asset_group_id=group.id,
        scan_name="Param Test Scan",
        filename="test.csv",
        total_hosts=1,
        total_findings=2,
        critical_count=1,
        high_count=1
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    host = models.Host(
        scan_id=scan.id,
        asset_group_id=group.id,
        ip_address="192.168.10.50",
        hostname="srv-param-test",
        critical_count=1,
        high_count=1,
        risk_score=15.0
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    vuln_crit = models.Vulnerability(
        scan_id=scan.id,
        host_id=host.id,
        asset_group_id=group.id,
        plugin_id="50001",
        plugin_name="Critical Test Vuln 50001",
        severity="Critical",
        cvss_v3=9.8,
        exploit_available=True,
        treatment_status="Open"
    )
    vuln_high = models.Vulnerability(
        scan_id=scan.id,
        host_id=host.id,
        asset_group_id=group.id,
        plugin_id="50002",
        plugin_name="High Test Vuln 50002",
        severity="High",
        cvss_v3=7.5,
        exploit_available=False,
        treatment_status="Open"
    )
    db.add_all([vuln_crit, vuln_high])
    db.commit()
    yield
    if prev_override is not None:
        app.dependency_overrides[get_db] = prev_override
    else:
        app.dependency_overrides.pop(get_db, None)

def get_auth_headers(client: TestClient, username: str, password: str) -> dict:
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_get_default_parameters():
    client = TestClient(app)
    headers = get_auth_headers(client, "AdminParams", "Admin123")

    res = client.get("/api/parameters", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["timezone"] == "America/Sao_Paulo"
    assert "Brasília" in data["timezone_label"]
    assert data["sla_critical_days"] == 7
    assert data["sla_high_days"] == 15
    assert data["sla_medium_days"] == 30
    assert data["sla_low_days"] == 60
    assert data["ignored_vulnerability_ids"] == ""
    assert data["ignored_vulnerabilities_count"] == 0

def test_list_timezones_endpoint():
    client = TestClient(app)
    headers = get_auth_headers(client, "AdminParams", "Admin123")

    res = client.get("/api/parameters/timezones", headers=headers)
    assert res.status_code == 200
    tzs = res.json()
    assert len(tzs) > 10
    # Check Brazilian priority timezones
    sp_tz = next((t for t in tzs if t["id"] == "America/Sao_Paulo"), None)
    assert sp_tz is not None
    assert sp_tz["is_brazil"] is True
    assert "UTC" in sp_tz["offset"]

    manaus_tz = next((t for t in tzs if t["id"] == "America/Manaus"), None)
    assert manaus_tz is not None
    assert manaus_tz["is_brazil"] is True

def test_update_parameters_rbac_analyst_denied():
    client = TestClient(app)
    analyst_headers = get_auth_headers(client, "AnalystParams", "Analyst123")

    payload = {
        "timezone": "America/Manaus",
        "sla_critical_days": 5,
        "sla_high_days": 10,
        "sla_medium_days": 20,
        "sla_low_days": 40,
        "ignored_vulnerability_ids": "50001"
    }
    res = client.put("/api/parameters", json=payload, headers=analyst_headers)
    assert res.status_code == 403

def test_update_parameters_validation_errors():
    client = TestClient(app)
    headers = get_auth_headers(client, "AdminParams", "Admin123")

    # Invalid timezone
    res = client.put("/api/parameters", json={
        "timezone": "Invalid/Fake_Zone_123",
        "sla_critical_days": 7,
        "sla_high_days": 15,
        "sla_medium_days": 30,
        "sla_low_days": 60,
        "ignored_vulnerability_ids": ""
    }, headers=headers)
    assert res.status_code == 400
    assert "Fuso horário inválido" in res.json()["detail"]

    # Negative SLA days
    res = client.put("/api/parameters", json={
        "timezone": "America/Sao_Paulo",
        "sla_critical_days": -5,
        "sla_high_days": 15,
        "sla_medium_days": 30,
        "sla_low_days": 60,
        "ignored_vulnerability_ids": ""
    }, headers=headers)
    assert res.status_code == 422 # Pydantic Field ge=1 validation

def test_preview_ignored_vulnerabilities():
    client = TestClient(app)
    headers = get_auth_headers(client, "AdminParams", "Admin123")

    # Preview with plugin 50001
    res = client.post("/api/parameters/preview-ignored", json={"ignored_ids": "50001, 99999"}, headers=headers)
    assert res.status_code == 200
    preview = res.json()
    assert preview["total_matching_rules"] == 2
    assert preview["total_findings_affected"] == 1
    assert preview["total_affected_hosts"] == 1
    assert len(preview["items"]) == 1
    assert preview["items"][0]["plugin_id"] == "50001"
    assert preview["items"][0]["severity"] == "Critical"

def test_ignored_vulnerabilities_excluded_from_indicators():
    client = TestClient(app)
    headers = get_auth_headers(client, "AdminParams", "Admin123")

    # 1. Before ignoring: Dashboard has 1 critical (50001) and 1 high (50002)
    dash_before = client.get("/api/dashboard/stats", headers=headers).json()
    assert dash_before["critical_count"] == 1
    assert dash_before["high_count"] == 1
    assert dash_before["total_findings"] == 2

    top_crit_before = client.get("/api/dashboard/top-critical", headers=headers).json()
    assert any(item["plugin_id"] == "50001" for item in top_crit_before)

    # 2. Update parameters to ignore plugin 50001 as False Positive
    update_res = client.put("/api/parameters", json={
        "timezone": "America/Sao_Paulo",
        "sla_critical_days": 5,
        "sla_high_days": 10,
        "sla_medium_days": 20,
        "sla_low_days": 40,
        "ignored_vulnerability_ids": "50001\n99999"
    }, headers=headers)
    assert update_res.status_code == 200
    data = update_res.json()
    assert data["sla_critical_days"] == 5
    assert "50001" in data["ignored_ids_list"]
    assert "99999" in data["ignored_ids_list"]

    # 3. After ignoring: Dashboard indicators must dynamically exclude plugin 50001!
    dash_after = client.get("/api/dashboard/stats", headers=headers).json()
    assert dash_after["critical_count"] == 0 # 50001 was ignored!
    assert dash_after["high_count"] == 1     # 50002 remains!
    assert dash_after["total_findings"] == 1

    # Top 100 critical should no longer list plugin 50001
    top_crit_after = client.get("/api/dashboard/top-critical", headers=headers).json()
    assert not any(item["plugin_id"] == "50001" for item in top_crit_after)

    # 4. In Vulnerabilities list, 50001 has is_ignored_in_indicators = True
    vulns_res = client.get("/api/vulnerabilities", headers=headers).json()
    v50001 = next(v for v in vulns_res if v["plugin_id"] == "50001")
    assert v50001["is_ignored_in_indicators"] is True

    v50002 = next(v for v in vulns_res if v["plugin_id"] == "50002")
    assert v50002["is_ignored_in_indicators"] is False

    # And if exclude_ignored=True is queried, 50001 is omitted
    vulns_filtered = client.get("/api/vulnerabilities?exclude_ignored=true", headers=headers).json()
    assert not any(v["plugin_id"] == "50001" for v in vulns_filtered)
    assert any(v["plugin_id"] == "50002" for v in vulns_filtered)

def test_apply_slas_to_all_groups():
    client = TestClient(app)
    headers = get_auth_headers(client, "AdminParams", "Admin123")

    # Set parameters SLAs
    client.put("/api/parameters", json={
        "timezone": "America/Sao_Paulo",
        "sla_critical_days": 4,
        "sla_high_days": 8,
        "sla_medium_days": 16,
        "sla_low_days": 32,
        "ignored_vulnerability_ids": ""
    }, headers=headers)

    res = client.post("/api/parameters/apply-slas-to-all-groups", headers=headers)
    assert res.status_code == 200
    assert res.json()["updated_groups_count"] >= 1

    # Verify group in DB has new SLAs
    groups_res = client.get("/api/asset-groups", headers=headers).json()
    test_group = next(g for g in groups_res if g["name"] == "Param-Test-Group")
    assert test_group["sla_critical_days"] == 4
    assert test_group["sla_high_days"] == 8
    assert test_group["sla_medium_days"] == 16
    assert test_group["sla_low_days"] == 32

def test_vulnerability_treatment_timezone_behavior():
    client = TestClient(app)
    headers = get_auth_headers(client, "AdminParams", "Admin123")

    # 1. Configura fuso horário para America/Sao_Paulo (UTC-03:00)
    p_res = client.put("/api/parameters", json={
        "timezone": "America/Sao_Paulo",
        "sla_critical_days": 7,
        "sla_high_days": 15,
        "sla_medium_days": 30,
        "sla_low_days": 60,
        "ignored_vulnerability_ids": ""
    }, headers=headers)
    assert p_res.status_code == 200

    # 2. Localiza vulnerabilidade de teste
    vulns = client.get("/api/vulnerabilities", headers=headers).json()
    assert len(vulns) > 0
    vuln_id = vulns[0]["id"]

    # 3. Trata a vulnerabilidade
    patch_res = client.patch(f"/api/vulnerabilities/{vuln_id}/treatment", json={
        "treatment_status": "In_Remediation",
        "treatment_notes": "Aplicando correção no fuso de SP para auditoria"
    }, headers=headers)
    assert patch_res.status_code == 200
    treated_vuln = patch_res.json()

    # treated_at deve ter o offset -03:00 e treated_at_formatted preenchido
    assert treated_vuln["treated_at"] is not None
    assert "-03:00" in treated_vuln["treated_at"]
    assert treated_vuln["treated_at_formatted"] is not None
    assert "/" in treated_vuln["treated_at_formatted"]
    assert ":" in treated_vuln["treated_at_formatted"]

    # 4. Verifica histórico de auditoria
    hist_res = client.get(f"/api/vulnerabilities/{vuln_id}/treatment-history", headers=headers)
    assert hist_res.status_code == 200
    history = hist_res.json()
    assert len(history) > 0
    latest = history[0]
    assert "-03:00" in latest["changed_at"]
    assert latest["changed_at_formatted"] is not None
    assert "/" in latest["changed_at_formatted"]

    # 5. Altera fuso para America/Manaus (UTC-04:00)
    client.put("/api/parameters", json={
        "timezone": "America/Manaus",
        "sla_critical_days": 7,
        "sla_high_days": 15,
        "sla_medium_days": 30,
        "sla_low_days": 60,
        "ignored_vulnerability_ids": ""
    }, headers=headers)

    # Verifica se a consulta direta da vulnerabilidade reflete o novo fuso Manaus (-04:00)
    get_res = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert get_res.status_code == 200
    manaus_vuln = get_res.json()
    assert "-04:00" in manaus_vuln["treated_at"]

    # Verifica histórico no novo fuso (-04:00)
    hist_manaus = client.get(f"/api/vulnerabilities/{vuln_id}/treatment-history", headers=headers).json()
    assert "-04:00" in hist_manaus[0]["changed_at"]

    # Restaura para America/Sao_Paulo
    client.put("/api/parameters", json={
        "timezone": "America/Sao_Paulo",
        "sla_critical_days": 7,
        "sla_high_days": 15,
        "sla_medium_days": 30,
        "sla_low_days": 60,
        "ignored_vulnerability_ids": ""
    }, headers=headers)

