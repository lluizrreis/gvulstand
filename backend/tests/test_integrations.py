"""
Unit and Integration Tests for Scanner Integrations (Tenable and Microsoft Defender)
"""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app import models
from app.services.integrations.scheduler import should_run_integration, check_and_run_scheduled_syncs

client = TestClient(app)


def get_admin_token():
    res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_transient_connection_tests():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test Tenable Connection (Simulation Mode)
    res_tenable = client.post("/api/integrations/test-connection", json={
        "scanner_type": "tenable_io",
        "api_endpoint": "https://cloud.tenable.com",
        "access_key": "test_access_key",
        "secret_key": "test_secret_key"
    }, headers=headers)
    assert res_tenable.status_code == 200
    data_t = res_tenable.json()
    assert data_t["success"] is True
    assert "TENABLE_IO" in data_t["message"]

    # 2. Test Microsoft Defender Connection (Simulation Mode)
    res_def = client.post("/api/integrations/test-connection", json={
        "scanner_type": "ms_defender",
        "tenant_id": "test_tenant_id",
        "client_id": "test_client_id",
        "client_secret": "test_client_secret"
    }, headers=headers)
    assert res_def.status_code == 200
    data_d = res_def.json()
    assert data_d["success"] is True
    assert "Microsoft Defender" in data_d["message"]


def test_crud_and_lifecycle_integrations():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    assert group is not None
    group_id = group.id
    db.close()

    # 1. Create Tenable Integration
    res_create_t = client.post("/api/integrations", json={
        "asset_group_id": group_id,
        "name": "Sync Automático Tenable Datacenter",
        "scanner_type": "tenable_io",
        "is_enabled": True,
        "api_endpoint": "https://cloud.tenable.com",
        "access_key": "access_key_123456",
        "secret_key": "secret_key_654321",
        "schedule_type": "daily",
        "schedule_time": "03:00"
    }, headers=headers)
    assert res_create_t.status_code == 201
    int_t = res_create_t.json()
    assert int_t["name"] == "Sync Automático Tenable Datacenter"
    assert int_t["scanner_type"] == "tenable_io"
    assert int_t["access_key_masked"] == "acc...456"
    assert int_t["has_secret_key"] is True
    assert int_t["schedule_type"] == "daily"
    integ_t_id = int_t["id"]

    # 2. Create Defender Integration
    res_create_d = client.post("/api/integrations", json={
        "asset_group_id": group_id,
        "name": "Sync Automático Defender Endpoints",
        "scanner_type": "ms_defender",
        "is_enabled": True,
        "tenant_id": "tenant_abc_xyz",
        "client_id": "client_abc_xyz",
        "client_secret": "secret_abc_xyz",
        "schedule_type": "interval",
        "interval_hours": 12
    }, headers=headers)
    assert res_create_d.status_code == 201
    int_d = res_create_d.json()
    assert int_d["scanner_type"] == "ms_defender"
    assert int_d["has_client_secret"] is True
    assert int_d["interval_hours"] == 12
    integ_d_id = int_d["id"]

    # 3. List Integrations
    res_list = client.get(f"/api/integrations?asset_group_id={group_id}", headers=headers)
    assert res_list.status_code == 200
    all_integs = res_list.json()
    assert len(all_integs) >= 2
    assert any(i["id"] == integ_t_id for i in all_integs)
    assert any(i["id"] == integ_d_id for i in all_integs)

    # 4. Update Integration
    res_up = client.put(f"/api/integrations/{integ_t_id}", json={
        "interval_hours": 8,
        "schedule_type": "interval"
    }, headers=headers)
    assert res_up.status_code == 200
    updated_t = res_up.json()
    assert updated_t["schedule_type"] == "interval"
    assert updated_t["interval_hours"] == 8

    # 5. Test Saved Connection
    res_test_saved = client.post(f"/api/integrations/{integ_d_id}/test-connection", headers=headers)
    assert res_test_saved.status_code == 200

    # 6. Delete Integration
    res_del = client.delete(f"/api/integrations/{integ_d_id}", headers=headers)
    assert res_del.status_code == 200

    # Verify deleted
    res_get_del = client.get(f"/api/integrations/{integ_d_id}", headers=headers)
    assert res_get_del.status_code == 404

    # Cleanup Tenable integration
    client.delete(f"/api/integrations/{integ_t_id}", headers=headers)


def test_sync_now_execution_and_data_ingestion():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    assert group is not None
    group_id = group.id
    integ = models.ScannerIntegration(
        asset_group_id=group_id,
        name="Sync Test Tenable Ingestion",
        scanner_type="tenable_io",
        is_enabled=True,
        access_key="test_access_key",
        secret_key="test_secret_key",
        schedule_type="manual"
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    integ_id = integ.id
    db.close()

    # Trigger Sync Now
    res_sync = client.post(f"/api/integrations/{integ_id}/sync-now", headers=headers)
    assert res_sync.status_code == 200
    sync_out = res_sync.json()
    assert sync_out["success"] is True
    assert sync_out["status"] == "success"
    assert sync_out["scan_id"] is not None
    assert sync_out["hosts_count"] >= 1
    assert sync_out["vulnerabilities_count"] >= 1

    # Verify database ingestion
    db = SessionLocal()
    created_scan = db.query(models.Scan).filter(models.Scan.id == sync_out["scan_id"]).first()
    assert created_scan is not None
    assert created_scan.asset_group_id == group_id
    assert created_scan.total_hosts == sync_out["hosts_count"]
    assert created_scan.total_findings == sync_out["vulnerabilities_count"]
    assert created_scan.critical_count >= 1

    # Verify host and vulnerabilities records
    hosts = db.query(models.Host).filter(models.Host.scan_id == created_scan.id).all()
    assert len(hosts) == sync_out["hosts_count"]
    vulns = db.query(models.Vulnerability).filter(models.Vulnerability.scan_id == created_scan.id).all()
    assert len(vulns) == sync_out["vulnerabilities_count"]

    # Verify integration telemetry update
    refreshed_integ = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integ_id).first()
    assert refreshed_integ.last_sync_status == "success"
    assert refreshed_integ.last_sync_at is not None
    assert refreshed_integ.last_synced_scan_id == created_scan.id
    assert refreshed_integ.vulnerabilities_imported_count == len(vulns)

    # Cleanup
    db.delete(created_scan)
    db.delete(refreshed_integ)
    db.commit()
    db.close()


def test_scheduler_business_rules():
    now = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)  # Wednesday (isoweekday=3)

    # 1. Disabled integration should never run
    int_disabled = models.ScannerIntegration(is_enabled=False, schedule_type="interval", interval_hours=1)
    assert should_run_integration(int_disabled, now) is False

    # 2. Already running should not run concurrently
    int_running = models.ScannerIntegration(is_enabled=True, schedule_type="interval", last_sync_status="running")
    assert should_run_integration(int_running, now) is False

    # 3. Manual should not auto run
    int_manual = models.ScannerIntegration(is_enabled=True, schedule_type="manual")
    assert should_run_integration(int_manual, now) is False

    # 4. Interval: never ran before -> should run
    int_interval_fresh = models.ScannerIntegration(is_enabled=True, schedule_type="interval", interval_hours=4, last_sync_at=None)
    assert should_run_integration(int_interval_fresh, now) is True

    # 5. Interval: ran 2 hours ago with 4h interval -> should NOT run
    int_interval_recent = models.ScannerIntegration(
        is_enabled=True,
        schedule_type="interval",
        interval_hours=4,
        last_sync_at=datetime(2026, 9, 30, 8, 30, 0, tzinfo=timezone.utc)
    )
    assert should_run_integration(int_interval_recent, now) is False

    # 6. Interval: ran 5 hours ago with 4h interval -> should run
    int_interval_due = models.ScannerIntegration(
        is_enabled=True,
        schedule_type="interval",
        interval_hours=4,
        last_sync_at=datetime(2026, 9, 30, 5, 0, 0, tzinfo=timezone.utc)
    )
    assert should_run_integration(int_interval_due, now) is True

    # 7. Daily: scheduled at 09:00, current time 10:00, hasn't run today -> should run
    int_daily_due = models.ScannerIntegration(
        is_enabled=True,
        schedule_type="daily",
        schedule_time="09:00",
        last_sync_at=datetime(2026, 9, 29, 9, 0, 0, tzinfo=timezone.utc)
    )
    assert should_run_integration(int_daily_due, now) is True

    # 8. Daily: already ran today -> should NOT run
    int_daily_done = models.ScannerIntegration(
        is_enabled=True,
        schedule_type="daily",
        schedule_time="09:00",
        last_sync_at=datetime(2026, 9, 30, 9, 0, 0, tzinfo=timezone.utc)
    )
    assert should_run_integration(int_daily_done, now) is False

    # 9. Weekly: Wednesday (weekday 3), scheduled days "1,3,5" -> should run
    int_weekly_due = models.ScannerIntegration(
        is_enabled=True,
        schedule_type="weekly",
        schedule_days="1,3,5",
        schedule_time="08:00",
        last_sync_at=datetime(2026, 9, 23, 8, 0, 0, tzinfo=timezone.utc)
    )
    assert should_run_integration(int_weekly_due, now) is True

    # 10. Weekly: Tuesday (weekday 2 not in "1,3,5") -> should NOT run
    int_weekly_other_day = models.ScannerIntegration(
        is_enabled=True,
        schedule_type="weekly",
        schedule_days="1,2,5",  # Wednesday (3) not allowed
        schedule_time="08:00",
        last_sync_at=None
    )
    assert should_run_integration(int_weekly_other_day, now) is False


def test_tenable_real_error_no_mock_fallback():
    """
    Ensure non-mock clients never fall back to simulated/mock data when connection fails.
    """
    from app.services.integrations.tenable_client import TenableClient

    # Client with non-mock credentials and unreachable local port
    client = TenableClient(
        scanner_type="tenable_nessus_pro",
        api_endpoint="https://127.0.0.1:59999",
        access_key="real_prod_access_key_123456",
        secret_key="real_prod_secret_key_654321",
        verify_ssl=False,
        timeout=1.0
    )

    # 1. test_connection must return failure with clear error
    res = client.test_connection()
    assert res["success"] is False
    assert res["status_code"] in [503, 504]
    assert "Não foi possível conectar" in res["message"] or "Tempo limite" in res["message"]

    # 2. fetch_vulnerabilities must RAISE RuntimeError instead of returning fake findings
    with pytest.raises(RuntimeError) as exc_info:
        client.fetch_vulnerabilities()
    assert "Falha na comunicação com a API do Tenable/Nessus" in str(exc_info.value)


def test_sync_engine_aborts_cleanly_on_failure_without_creating_scans():
    """
    Ensure run_scanner_sync marks status as 'failed' and creates 0 scans/hosts/vulnerabilities on error.
    """
    from app.services.integrations.sync_engine import run_scanner_sync

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    assert group is not None

    scans_before = db.query(models.Scan).count()
    hosts_before = db.query(models.Host).count()
    vulns_before = db.query(models.Vulnerability).count()

    # Create integration with unreachable endpoint
    integ = models.ScannerIntegration(
        asset_group_id=group.id,
        name="Sync Unreachable Endpoint",
        scanner_type="tenable_nessus_pro",
        is_enabled=True,
        api_endpoint="https://127.0.0.1:59999",
        access_key="real_access_key_test_fail",
        secret_key="real_secret_key_test_fail",
        verify_ssl=False,
        schedule_type="manual"
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    integ_id = integ.id

    # Execute sync
    result = run_scanner_sync(db, integ_id)

    assert result["success"] is False
    assert result["status"] == "failed"
    assert result.get("scan_id") is None
    assert "Falha na sincronização" in result["message"]

    # Verify zero database artifacts were created
    assert db.query(models.Scan).count() == scans_before
    assert db.query(models.Host).count() == hosts_before
    assert db.query(models.Vulnerability).count() == vulns_before

    # Verify integration telemetry
    refreshed = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integ_id).first()
    assert refreshed.last_sync_status == "failed"
    assert refreshed.last_synced_scan_id is None
    assert refreshed.vulnerabilities_imported_count == 0
    assert refreshed.hosts_imported_count == 0

    # Cleanup
    db.delete(refreshed)
    db.commit()
    db.close()


def test_api_sync_triggers_action_plan_auto_remediation(monkeypatch):
    """
    Verifica se a sincronização via API (run_scanner_sync) aciona automaticamente
    a remediação de planos de ação quando uma vulnerabilidade monitorada é corrigida.
    """
    from app.services.integrations.sync_engine import run_scanner_sync
    from app.services.integrations.tenable_client import TenableClient

    db = SessionLocal()
    ts = int(datetime.now(timezone.utc).timestamp())
    group = models.AssetGroup(name=f"API Sync AP Group {ts}")
    db.add(group)
    db.commit()
    db.refresh(group)
    gid = group.id

    ip_target = "10.50.60.70"
    pid_target = "20555"

    # Criar scan 1 inicial com a vulnerabilidade
    scan1 = models.Scan(asset_group_id=gid, filename=f"init_{ts}.json", scan_name="Initial Scan")
    db.add(scan1)
    db.commit()
    db.refresh(scan1)

    host1 = models.Host(scan_id=scan1.id, asset_group_id=gid, ip_address=ip_target, hostname="endpoint-1")
    db.add(host1)
    db.commit()
    db.refresh(host1)

    v1 = models.Vulnerability(
        scan_id=scan1.id,
        host_id=host1.id,
        asset_group_id=gid,
        plugin_id=pid_target,
        plugin_name="API Sync Target Vuln",
        severity="High",
        treatment_status="Open"
    )
    db.add(v1)
    db.commit()
    db.refresh(v1)
    v1_id = v1.id

    # Criar plano de ação
    plan = models.ActionPlan(
        title=f"Plano API Sync {ts}",
        scope_type="MATRIX_NN",
        asset_group_id=gid,
        priority="HIGH",
        status="PLANNED",
        created_by_username="Admin"
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)

    task = models.ActionTask(
        action_plan_id=plan.id,
        title=ip_target,
        description="API Sync Target Vuln",
        status="TODO",
        order_index=0
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    link = models.ActionTaskVulnerabilityLink(action_task_id=task.id, vulnerability_id=v1_id)
    db.add(link)
    v1.treatment_status = "In_Action_Plan"
    db.commit()

    # Criar integração configurada para o grupo
    integ = models.ScannerIntegration(
        asset_group_id=gid,
        name=f"Integ Sync AP {ts}",
        scanner_type="tenable_io",
        is_enabled=True,
        api_endpoint="https://cloud.tenable.com",
        access_key="fake_acc",
        secret_key="fake_sec",
        schedule_type="manual"
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    integ_id = integ.id

    # Mock fetch_vulnerabilities retornando o host escaneado, mas SEM a vulnerabilidade 20555
    mock_data = {
        "hosts": {
            ip_target: {
                "ip_address": ip_target,
                "hostname": "endpoint-1",
                "os": "Linux",
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0
            }
        },
        "findings": [],
        "stats": {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    }

    monkeypatch.setattr(TenableClient, "fetch_vulnerabilities", lambda self, target_scope_filter=None: mock_data)

    # Executar sync via run_scanner_sync
    res = run_scanner_sync(db, integ_id)
    assert res["success"] is True

    # Verificar que o plano e a tarefa foram concluídos e a vulnerabilidade remediada
    db.refresh(plan)
    db.refresh(task)
    db.refresh(v1)
    assert v1.treatment_status == "Remediated"
    assert "Remediada" in v1.treatment_notes
    assert task.status == "DONE"
    assert plan.status == "COMPLETED"

    # Cleanup
    db.delete(link)
    db.delete(task)
    db.delete(plan)
    db.delete(integ)
    db.query(models.VulnerabilityTreatmentHistory).filter(models.VulnerabilityTreatmentHistory.vulnerability_id == v1_id).delete()
    db.query(models.Vulnerability).filter(models.Vulnerability.asset_group_id == gid).delete()
    db.query(models.Host).filter(models.Host.asset_group_id == gid).delete()
    db.query(models.Scan).filter(models.Scan.asset_group_id == gid).delete()
    db.delete(group)
    db.commit()
    db.close()


def test_target_scope_filter_in_crud_and_clients(monkeypatch):
    """
    Verifica se o campo target_scope_filter é salvo e consultado corretamente no CRUD,
    e se os clientes Tenable e Defender aplicam a filtragem de escopo por grupo.
    """
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    assert group is not None
    group_id = group.id
    db.close()

    # 1. Criar integração com target_scope_filter
    res = client.post("/api/integrations", json={
        "asset_group_id": group_id,
        "name": "Integration Com Filtro de Escopo",
        "scanner_type": "tenable_nessus_pro",
        "api_endpoint": "https://127.0.0.1:8834",
        "access_key": "test_access",
        "secret_key": "test_secret",
        "target_scope_filter": "Scan Datacenter DMZ",
        "schedule_type": "manual"
    }, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["target_scope_filter"] == "Scan Datacenter DMZ"
    integ_id = data["id"]

    # 2. Atualizar target_scope_filter
    res_up = client.put(f"/api/integrations/{integ_id}", json={
        "target_scope_filter": "Scan Rede Corp"
    }, headers=headers)
    assert res_up.status_code == 200
    assert res_up.json()["target_scope_filter"] == "Scan Rede Corp"

    # 3. Testar DefenderClient filtrando máquinas por rbacGroupName
    from app.services.integrations.defender_client import DefenderClient
    def_client = DefenderClient(tenant_id="t", client_id="c", client_secret="s")
    monkeypatch.setattr(def_client, "acquire_token", lambda: (True, "mock_token"))

    class MockResponse:
        def __init__(self, status_code, json_data):
            self.status_code = status_code
            self._json = json_data
            self.text = "mock text"
        def json(self):
            return self._json

    def mock_get(url, headers=None):
        if "machines" in url and "Vulnerabilities" not in url:
            return MockResponse(200, {
                "value": [
                    {"id": "m1", "computerDnsName": "srv-prod-1", "rbacGroupName": "Producao", "ipAddresses": ["10.0.1.10"]},
                    {"id": "m2", "computerDnsName": "srv-dev-1", "rbacGroupName": "Desenvolvimento", "ipAddresses": ["10.0.2.10"]}
                ]
            })
        elif "machinesVulnerabilities" in url:
            return MockResponse(200, {
                "value": [
                    {"machineId": "m1", "cveId": "CVE-2024-1111", "severity": "High", "vulnerabilitySeverityLevel": "High"},
                    {"machineId": "m2", "cveId": "CVE-2024-2222", "severity": "Critical", "vulnerabilitySeverityLevel": "Critical"}
                ]
            })
        return MockResponse(404, {})

    import httpx
    monkeypatch.setattr(httpx.Client, "get", lambda self, url, headers=None: mock_get(url, headers))

    # Sem filtro: retorna 2 máquinas
    all_res = def_client.fetch_vulnerabilities()
    assert len(all_res["hosts"]) == 2

    # Com filtro 'Producao': retorna apenas a máquina de Produção e sua vulnerabilidade
    prod_res = def_client.fetch_vulnerabilities(target_scope_filter="Producao")
    assert len(prod_res["hosts"]) == 1
    assert "10.0.1.10" in prod_res["hosts"]
    assert len(prod_res["findings"]) == 1
    assert prod_res["findings"][0]["cve"] == "CVE-2024-1111"

    # Cleanup
    client.delete(f"/api/integrations/{integ_id}", headers=headers)


def test_scanner_credentials_fernet_encryption():
    """
    Testa que as credenciais de scanner (access_key, secret_key, client_secret)
    são criptografadas com Fernet no banco de dados e nunca expostas em texto puro.
    """
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    from app.crypto_utils import is_encrypted, safe_decrypt_secret

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    assert group is not None
    group_id = group.id
    db.close()

    raw_acc = "my_super_secret_access_key_123"
    raw_sec = "my_ultra_confidential_secret_key_456"

    # Criação via API
    payload = {
        "asset_group_id": group_id,
        "name": "Integration Crypto Test",
        "scanner_type": "tenable_nessus_pro",
        "api_endpoint": "https://192.168.3.18:8834",
        "access_key": raw_acc,
        "secret_key": raw_sec,
        "is_enabled": True
    }
    res = client.post("/api/integrations", json=payload, headers=headers)
    assert res.status_code == 201
    created_data = res.json()
    integ_id = created_data["id"]

    # 1. API não deve retornar o segredo em texto puro
    assert "secret_key" not in created_data or created_data.get("secret_key") is None
    assert created_data["has_secret_key"] is True
    assert created_data["access_key_masked"] is not None
    assert raw_acc not in created_data["access_key_masked"]

    # 2. No banco de dados, os campos devem estar armazenados criptografados com Fernet (iniciando em gAAAAA)
    db = SessionLocal()
    integ_db = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integ_id).first()
    assert integ_db is not None
    assert is_encrypted(integ_db.access_key) is True
    assert is_encrypted(integ_db.secret_key) is True
    assert integ_db.access_key.startswith("gAAAAA")
    assert integ_db.secret_key.startswith("gAAAAA")

    # 3. Métodos auxiliares de descriptografia devem recuperar o texto puro original
    assert integ_db.get_decrypted_access_key() == raw_acc
    assert integ_db.get_decrypted_secret_key() == raw_sec
    assert safe_decrypt_secret(integ_db.access_key) == raw_acc
    assert safe_decrypt_secret(integ_db.secret_key) == raw_sec

    # 4. Atualização de chave/senha também deve criptografar
    new_sec = "new_rotated_secret_789"
    res_up = client.put(f"/api/integrations/{integ_id}", json={"secret_key": new_sec}, headers=headers)
    assert res_up.status_code == 200
    db.refresh(integ_db)
    assert is_encrypted(integ_db.secret_key) is True
    assert integ_db.get_decrypted_secret_key() == new_sec

    # Cleanup
    db.delete(integ_db)
    db.commit()
    db.close()


def test_reuse_saved_credentials_for_new_integration():
    """
    Testa o endpoint /saved-credentials e a criação de nova integração reutilizando
    credenciais salvas de cadastro anterior do mesmo servidor de destino via use_credentials_from_id.
    """
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    from app.crypto_utils import is_encrypted

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    assert group is not None
    group_id = group.id

    # Cria conector de origem com credenciais completas
    orig_integ = models.ScannerIntegration(
        asset_group_id=group_id,
        name="Servidor OpenVAS Matriz",
        scanner_type="openvas",
        api_endpoint="192.168.3.18:9390",
        is_enabled=True,
        access_key="admin_matriz",
        secret_key="pass_matriz_123"
    )
    from app.crypto_utils import safe_encrypt_secret
    orig_integ.access_key = safe_encrypt_secret(orig_integ.access_key)
    orig_integ.secret_key = safe_encrypt_secret(orig_integ.secret_key)
    db.add(orig_integ)
    db.commit()
    db.refresh(orig_integ)
    source_id = orig_integ.id
    db.close()

    # 1. Endpoint /saved-credentials deve listar a credencial disponível
    res_saved = client.get("/api/integrations/saved-credentials", headers=headers)
    assert res_saved.status_code == 200
    saved_list = res_saved.json()
    assert any(item["id"] == source_id for item in saved_list)

    # 2. Criar novo conector para outro Grupo ou escopo usando use_credentials_from_id
    new_payload = {
        "asset_group_id": group_id,
        "name": "Nova Conexao Reutilizando Credencial",
        "scanner_type": "openvas",
        "api_endpoint": "192.168.3.18:9390",
        "use_credentials_from_id": source_id,
        "is_enabled": True
    }
    res_new = client.post("/api/integrations", json=new_payload, headers=headers)
    assert res_new.status_code == 201
    new_data = res_new.json()
    new_id = new_data["id"]

    # 3. O novo conector deve ter herdado as credenciais criptografadas
    db = SessionLocal()
    new_db = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == new_id).first()
    assert new_db is not None
    assert is_encrypted(new_db.secret_key) is True
    assert new_db.get_decrypted_access_key() == "admin_matriz"
    assert new_db.get_decrypted_secret_key() == "pass_matriz_123"

    # Cleanup
    db.delete(new_db)
    orig_to_del = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == source_id).first()
    if orig_to_del:
        db.delete(orig_to_del)
    db.commit()
    db.close()



