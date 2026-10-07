"""
Unit Tests for GvulStand Native Job Queue & Background Import System (Opção A)
"""
import os
import io
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone

from app.main import app
from app.database import SessionLocal, init_db
from app import models
from app.services.job_queue import (
    claim_next_queued_job,
    process_next_queued_job,
    enqueue_csv_job,
    enqueue_api_sync_job,
)

SAMPLE_NESSUS_CSV = """Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output
10001,CVE-2023-1234,9.8,Critical,192.168.10.50,tcp,443,OpenSSL Remote Code Execution,OpenSSL is vulnerable to RCE,A buffer overflow allows remote attackers to execute arbitrary code.,Upgrade to OpenSSL 3.0.8,https://openssl.org,Remote host returned version 1.0.1
10002,CVE-2022-5678,7.5,High,192.168.10.50,tcp,80,Apache HTTP Server Vulnerability,Apache Web Server flaw,Information disclosure issue in mod_proxy.,Update Apache HTTP Server,https://httpd.apache.org,Apache 2.4.49 detected
10003,,5.3,Medium,192.168.10.60,tcp,22,SSH Weak MAC Algorithms,Weak MAC algorithms supported,The SSH server is configured to allow weak MAC algorithms.,Disable weak MAC algorithms,https://ssh.com,hmac-md5 supported
"""


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers(client):
    res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert res.status_code == 200, f"Login failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def test_group(client, auth_headers):
    db = SessionLocal()
    group = db.query(models.AssetGroup).filter(models.AssetGroup.name == "Fila Test Group").first()
    if not group:
        group = models.AssetGroup(
            name="Fila Test Group",
            description="Grupo de teste para validação de Fila de Trabalhos",
            network_range="192.168.10.0/24"
        )
        db.add(group)
        db.commit()
        db.refresh(group)
    gid = group.id
    db.close()
    return gid


def test_job_enqueue_and_listing(client, auth_headers, test_group):
    """Verifica enfileiramento e listagem de jobs com metadados e badges."""
    db = SessionLocal()
    user = db.query(models.User).filter(models.User.role == "admin").first()

    # Cria arquivo temporário de teste
    test_path = "/tmp/test_queue_sample.csv"
    with open(test_path, "w", encoding="utf-8") as f:
        f.write(SAMPLE_NESSUS_CSV)

    job = enqueue_csv_job(
        db=db,
        asset_group_id=test_group,
        filename="test_queue_sample.csv",
        file_path=test_path,
        file_size_bytes=len(SAMPLE_NESSUS_CSV),
        current_user=user,
        scan_name="Queue Test Scan",
        scan_type="baseline"
    )
    job_id = job.id
    db.close()

    # 1. Consulta detalhes do job
    res = client.get(f"/api/jobs/{job_id}", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == job_id
    assert data["status"] in ["queued", "running", "completed"]
    assert data["job_type"] == "csv_upload"
    assert data["job_type_label"] == "Upload CSV Nessus"
    assert data["asset_group_id"] == test_group

    # 2. Listagem geral de jobs
    res_list = client.get("/api/jobs?limit=20", headers=auth_headers)
    assert res_list.status_code == 200
    jobs_list = res_list.json()
    assert any(j["id"] == job_id for j in jobs_list)


def test_process_next_queued_csv_job(client, auth_headers, test_group):
    """Executa o processamento do job e valida criação dos dados de scan e vulnerabilidades."""
    db = SessionLocal()
    user = db.query(models.User).filter(models.User.role == "admin").first()

    test_path = "/tmp/test_queue_exec.csv"
    with open(test_path, "w", encoding="utf-8") as f:
        f.write(SAMPLE_NESSUS_CSV)

    job = enqueue_csv_job(
        db=db,
        asset_group_id=test_group,
        filename="test_queue_exec.csv",
        file_path=test_path,
        file_size_bytes=len(SAMPLE_NESSUS_CSV),
        current_user=user,
        scan_name="Scan Executado pela Fila",
        scan_type="baseline"
    )
    job_id = job.id
    db.close()

    # Aguarda o worker em background processar ou processa manualmente
    import time
    for _ in range(15):
        res = client.get(f"/api/jobs/{job_id}", headers=auth_headers)
        if res.status_code == 200 and res.json()["status"] in ["completed", "failed"]:
            break
        time.sleep(0.3)

    res = client.get(f"/api/jobs/{job_id}", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["status_label"] == "Concluído"
    assert data["progress_percent"] == 100
    assert data["hosts_count"] == 2
    assert data["findings_count"] == 3
    assert data["scan_id"] is not None

    # Valida no banco de dados que o Scan e as Vulnerabilidades foram criados corretamente
    db = SessionLocal()
    scan = db.query(models.Scan).filter(models.Scan.id == data["scan_id"]).first()
    assert scan is not None
    assert scan.total_hosts == 2
    assert scan.total_findings == 3
    assert scan.critical_count == 1
    assert scan.high_count == 1
    assert scan.medium_count == 1
    db.close()


def test_cancel_and_retry_job(client, auth_headers, test_group):
    """Testa cancelamento de job em fila e posterior reenfileiramento (retry)."""
    db = SessionLocal()
    user = db.query(models.User).filter(models.User.role == "admin").first()

    # Cria diretamente no banco com status 'queued' sem disparar notify para testar a rota de cancelamento
    job = models.ImportJob(
        job_type="csv_upload",
        status="queued",
        progress_percent=0,
        progress_message="Na fila...",
        asset_group_id=test_group,
        created_by_user_id=user.id,
        created_by_username=user.username,
        filename="cancel_test.csv",
        file_path="/tmp/nonexistent.csv",
        file_size_bytes=100
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    job_id = job.id
    db.close()

    # 1. Cancelar
    res_cancel = client.post(f"/api/jobs/{job_id}/cancel", headers=auth_headers)
    assert res_cancel.status_code == 200
    assert res_cancel.json()["success"] is True

    # Verifica status
    res = client.get(f"/api/jobs/{job_id}", headers=auth_headers)
    assert res.json()["status"] == "cancelled"

    # 2. Reenfileirar (Retry)
    res_retry = client.post(f"/api/jobs/{job_id}/retry", headers=auth_headers)
    assert res_retry.status_code == 200
    assert res_retry.json()["status"] == "queued"


def test_async_upload_endpoint(client, auth_headers, test_group):
    """Testa o endpoint /api/scans/upload com async_mode=true."""
    csv_bytes = SAMPLE_NESSUS_CSV.encode("utf-8")
    files = {"file": ("async_scan.csv", csv_bytes, "text/csv")}
    data = {
        "asset_group_id": str(test_group),
        "scan_name": "Async Scan via Endpoint",
        "scan_type": "baseline",
        "async_mode": "true"
    }

    res = client.post("/api/scans/upload", files=files, data=data, headers=auth_headers)
    assert res.status_code == 202
    resp_data = res.json()
    assert "job_id" in resp_data
    assert resp_data["status"] == "queued"
    assert resp_data["job_type"] == "csv_upload"

    job_id = resp_data["job_id"]

    # Aguarda o worker em background processar
    import time
    for _ in range(15):
        job_res = client.get(f"/api/jobs/{job_id}", headers=auth_headers)
        if job_res.status_code == 200 and job_res.json()["status"] in ["completed", "failed"]:
            break
        time.sleep(0.3)

    # Valida conclusão
    job_res_after = client.get(f"/api/jobs/{job_id}", headers=auth_headers)
    assert job_res_after.json()["status"] == "completed"
    assert job_res_after.json()["findings_count"] == 3


def test_api_sync_enqueue_background(client, auth_headers, test_group):
    """Testa o endpoint /api/integrations/{id}/sync-now?background=true."""
    db = SessionLocal()
    integ = models.ScannerIntegration(
        asset_group_id=test_group,
        name="Tenable Queue Test",
        scanner_type="tenable_io",
        api_endpoint="https://cloud.tenable.com",
        access_key="test_access",
        secret_key="test_secret",
        schedule_type="manual"
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    integ_id = integ.id
    db.close()

    # Dispara com background=true
    res = client.post(f"/api/integrations/{integ_id}/sync-now?background=true", headers=auth_headers)
    assert res.status_code == 202
    data = res.json()
    assert "job_id" in data
    assert data["job_type"] == "api_sync"
    assert data["status"] == "queued"

    job_id = data["job_id"]
    job_res = client.get(f"/api/jobs/{job_id}", headers=auth_headers)
    assert job_res.status_code == 200
    assert job_res.json()["job_type"] == "api_sync"
