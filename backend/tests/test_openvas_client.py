"""
Unit and Integration Tests for OpenVAS / Greenbone Community Edition (GVM) Collector
Tests:
1. Parameterization and Dynamic Constructor Initialization
2. TLSConnection Simulation & Connection Verification
3. Task List XML Parsing with Task Scope Filtering
4. Report XML Parsing, CVE Extraction, and GvulStand Normalization
5. Integration with Sync Engine, Job Queue & Database Persistence
"""
import pytest
import xml.etree.ElementTree as ET
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app import models
from app.services.integrations.openvas_client import OpenVasCollector
from app.services.integrations.sync_engine import run_scanner_sync
from app.services.job_queue import enqueue_api_sync_job, process_next_queued_job

client = TestClient(app)


def get_admin_token() -> str:
    res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_openvas_collector_initialization():
    """Validates that OpenVasCollector correctly cleans and stores parameterized inputs."""
    # Test 1: URL scheme and custom port
    c1 = OpenVasCollector(
        host="tls://greenbone-gvmd:9390",
        port=9390,
        username="admin",
        password="secretpassword"
    )
    assert c1.host == "greenbone-gvmd"
    assert c1.port == 9390
    assert c1.username == "admin"
    assert c1.password == "secretpassword"

    # Test 2: Host:port in host string
    c2 = OpenVasCollector(
        host="10.0.9.18:9392",
        username="operator",
        password="pwd"
    )
    assert c2.host == "10.0.9.18"
    assert c2.port == 9392

    # Test 3: Default port fallback
    c3 = OpenVasCollector(host="openvas-server")
    assert c3.host == "openvas-server"
    assert c3.port == 9390


def test_openvas_test_connection_simulation():
    """Validates test_connection behavior in simulation mode."""
    collector = OpenVasCollector(
        host="mock_openvas",
        port=9390,
        username="admin",
        password="password"
    )
    res = collector.test_connection()
    assert res["success"] is True
    assert res["status_code"] == 200
    assert "testada com sucesso" in res["message"]
    assert res["details"]["scanner_type"] == "openvas"


def test_openvas_test_connection_missing_credentials():
    """Validates test_connection failure when credentials are missing."""
    collector = OpenVasCollector(host="10.20.30.40", port=9390, username="", password="")
    res = collector.test_connection()
    assert res["success"] is False
    assert res["status_code"] == 401
    assert "Credenciais incompletas" in res["message"]


def test_openvas_tasks_xml_parsing():
    """Validates task parsing and last_report_id identification with filtering."""
    collector = OpenVasCollector(host="mock_openvas")

    tasks_xml = """<get_tasks_response status="200" status_text="OK">
      <task id="task-alpha-1">
        <name>Weekly Infrastructure Scan</name>
        <status>Done</status>
        <last_report>
          <report id="report-alpha-old">
            <timestamp>2026-09-20T10:00:00Z</timestamp>
          </report>
        </last_report>
      </task>
      <task id="task-beta-2">
        <name>DMZ Perimeter Production</name>
        <status>Done</status>
        <last_report>
          <report id="report-beta-latest">
            <timestamp>2026-10-01T18:00:00Z</timestamp>
          </report>
        </last_report>
      </task>
    </get_tasks_response>"""

    # 1. Default (selects latest by timestamp)
    task_name, rep_id = collector._parse_tasks_xml(tasks_xml)
    assert task_name == "DMZ Perimeter Production"
    assert rep_id == "report-beta-latest"

    # 2. Filter by name keyword
    task_name, rep_id = collector._parse_tasks_xml(tasks_xml, target_scope_filter="Infrastructure")
    assert task_name == "Weekly Infrastructure Scan"
    assert rep_id == "report-alpha-old"

    # 3. Filter by task ID
    task_name, rep_id = collector._parse_tasks_xml(tasks_xml, target_scope_filter="task-beta-2")
    assert task_name == "DMZ Perimeter Production"
    assert rep_id == "report-beta-latest"

    # 4. Filter with non-existent match raises descriptive error
    with pytest.raises(RuntimeError) as exc_info:
        collector._parse_tasks_xml(tasks_xml, target_scope_filter="NonExistentTarget")
    assert "Nenhuma tarefa do OpenVAS correspondeu ao filtro" in str(exc_info.value)


def test_openvas_report_xml_parsing_and_normalization():
    """Validates XML parsing of <result> tags and conversion into Tenable/MDVM structure."""
    collector = OpenVasCollector(host="mock_openvas")

    report_xml = """<get_reports_response status="200" status_text="OK">
      <report id="rep-uuid-99">
        <report id="rep-uuid-99">
          <results max="100" start="1">
            <result id="res-101">
              <name>Apache HTTP Server Privilege Escalation</name>
              <host name="srv-web-01.corp">192.168.1.100<asset asset_id="ass-1"/></host>
              <port>80/tcp</port>
              <nvt oid="1.3.6.1.4.1.25623.1.0.100101">
                <name>Apache HTTP Server Privilege Escalation</name>
                <cvss_base>9.8</cvss_base>
                <severities score="9.8">
                  <severity type="cvss_base_v3">
                    <score>9.8</score>
                  </severity>
                </severities>
                <cve>CVE-2022-22720, CVE-2022-23943</cve>
                <solution type="VendorFix">Upgrade to Apache HTTP Server 2.4.53 or higher.</solution>
                <tags>summary=Apache HTTP Server is prone to multiple buffer overflow vulnerabilities.|insight=Flaws allow arbitrary code execution with root privileges.|solution=Upgrade to 2.4.53.|exploit_available=true</tags>
              </nvt>
              <threat>Critical</threat>
              <severity>9.8</severity>
              <description>Apache HTTP Server 2.4.51 vulnerable to buffer overflow on port 80.</description>
            </result>
            <result id="res-102">
              <name>Weak SSL/TLS Ciphers</name>
              <host name="srv-web-01.corp">192.168.1.100</host>
              <port>443/tcp</port>
              <nvt oid="1.3.6.1.4.1.25623.1.0.100102">
                <name>Weak SSL/TLS Ciphers</name>
                <cvss_base>4.3</cvss_base>
                <cve>NOCVE</cve>
                <tags>summary=Weak 3DES ciphers enabled.|solution=Disable 3DES and CBC ciphers.</tags>
              </nvt>
              <threat>Medium</threat>
              <severity>4.3</severity>
              <description>Weak cipher suites sweet32 detected on port 443.</description>
            </result>
            <result id="res-103">
              <name>OS Identification</name>
              <host>192.168.1.100</host>
              <port>general/tcp</port>
              <nvt oid="1.3.6.1.4.1.25623.1.0.102003">
                <name>Operating System Detection</name>
                <cvss_base>0.0</cvss_base>
                <cve>NOCVE</cve>
                <tags>summary=OS detected.</tags>
              </nvt>
              <threat>Log</threat>
              <severity>0.0</severity>
              <description>Debian GNU/Linux 12 (bookworm)</description>
            </result>
          </results>
          <detection>
            <result id="app-det-1">
              <details><detail><name>product</name><value>cpe:/a:test:prod</value></detail></details>
            </result>
          </detection>
        </report>
        <host>
          <ip>192.168.1.100</ip>
          <detail><name>Closed CVE</name><value>CVE-2025-24081, CVE-2025-24082</value></detail>
          <detail><name>best_os_txt</name><value>Debian GNU/Linux 12 (bookworm)</value></detail>
          <detail><name>MAC</name><value>00:11:22:33:44:55</value></detail>
          <detail><name>hostname_determination</name><value>192.168.1.100,192.168.1.100,IP-address</value></detail>
        </host>
      </report>
    </get_reports_response>"""

    parsed = collector._parse_report_xml(report_xml)

    # 1. Hosts verification (strictly 1 host, no phantom 127.0.0.1 from detection result)
    hosts = parsed["hosts"]
    assert len(hosts) == 1
    assert "127.0.0.1" not in hosts
    assert "192.168.1.100" in hosts
    h = hosts["192.168.1.100"]
    assert h["ip_address"] == "192.168.1.100"
    assert h["hostname"] == "srv-web-01.corp"
    assert "Debian" in h["os"]
    assert "CVE-2025-24081" not in h["os"]
    assert h["mac_address"] == "00:11:22:33:44:55"
    assert h["critical_count"] == 1
    assert h["medium_count"] == 1
    assert h["info_count"] == 1
    assert h["exploitable_critical_count"] == 1
    # Risk score: (1 * 10) + (1 * 2) + (1 * 5) = 17.0
    assert h["risk_score"] == 17.0

    # 2. Findings verification (only 3 results, ignoring detection result)
    findings = parsed["findings"]
    assert len(findings) == 3

    # Check Critical finding
    crit_finding = next(f for f in findings if f["severity"] == "Critical")
    assert crit_finding["plugin_id"] == "1.3.6.1.4.1.25623.1.0.100101"
    assert "Apache HTTP Server" in crit_finding["plugin_name"]
    assert crit_finding["port"] == 80
    assert crit_finding["protocol"] == "tcp"
    assert "CVE-2022-22720" in crit_finding["cve"]
    assert "CVE-2022-23943" in crit_finding["cve"]
    assert crit_finding["cvss_v3"] == 9.8
    assert crit_finding["exploit_available"] is True
    assert "2.4.53" in crit_finding["solution"]

    # Check General/TCP port parsing
    os_finding = next(f for f in findings if f["severity"] == "Info")
    assert os_finding["port"] == 0
    assert os_finding["protocol"] == "tcp"

    # 3. Stats verification
    stats = parsed["stats"]
    assert stats["critical_count"] == 1
    assert stats["medium_count"] == 1
    assert stats["info_count"] == 1
    assert stats["exploitable_critical_count"] == 1


def test_api_routes_openvas_test_connection():
    """Tests the transient connection test API endpoint for OpenVAS."""
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/integrations/test-connection", json={
        "scanner_type": "openvas",
        "api_endpoint": "mock_openvas:9390",
        "access_key": "admin",
        "secret_key": "password",
        "verify_ssl": False
    }, headers=headers)

    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "OpenVAS" in data["message"] or "Greenbone" in data["message"]


def test_api_openvas_sync_and_persistence():
    """
    Tests creating an OpenVAS ScannerIntegration, executing run_scanner_sync,
    persisting into Scan/Host/Vulnerability tables, and verifying telemetry.
    """
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    assert group is not None
    group_id = group.id
    db.close()

    # 1. Create OpenVAS Integration Record
    res_create = client.post("/api/integrations", json={
        "asset_group_id": group_id,
        "name": "OpenVAS Datacenter Core",
        "scanner_type": "openvas",
        "is_enabled": True,
        "api_endpoint": "mock_openvas:9390",
        "access_key": "admin",
        "secret_key": "secret123",
        "verify_ssl": False,
        "schedule_type": "manual"
    }, headers=headers)
    assert res_create.status_code == 201
    integ_data = res_create.json()
    assert integ_data["scanner_type"] == "openvas"
    assert "OpenVAS" in integ_data["scanner_type_label"]
    integ_id = integ_data["id"]

    # 2. Execute run_scanner_sync (Sync Engine execution)
    db = SessionLocal()
    try:
        sync_result = run_scanner_sync(db, integ_id)
        assert sync_result["success"] is True
        assert sync_result["status"] == "success"
        assert sync_result["hosts_count"] >= 1
        assert sync_result["vulnerabilities_count"] >= 1
        scan_id = sync_result["scan_id"]
        assert scan_id is not None

        # Verify Scan in DB
        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        assert scan is not None
        assert "OpenVAS" in scan.scan_name
        assert scan.critical_count >= 1

        # Verify Hosts in DB
        hosts = db.query(models.Host).filter(models.Host.scan_id == scan_id).all()
        assert len(hosts) == sync_result["hosts_count"]
        for h in hosts:
            assert h.asset_group_id == group_id
            assert h.risk_score > 0

        # Verify Vulnerabilities in DB
        vulns = db.query(models.Vulnerability).filter(models.Vulnerability.scan_id == scan_id).all()
        assert len(vulns) == sync_result["vulnerabilities_count"]
        # Verify NVT OID plugin ID
        assert any("1.3.6.1.4.1.25623" in v.plugin_id for v in vulns)
        # Verify CVE populated
        assert any(v.cve and "CVE-" in v.cve for v in vulns)

    finally:
        db.close()


def test_openvas_job_queue_integration():
    """
    Tests enqueuing an OpenVAS API sync job into the native ImportJob queue,
    verifying FIFO serialization and background processing.
    """
    db = SessionLocal()
    try:
        admin_user = db.query(models.User).filter(models.User.username == "Admin").first()
        assert admin_user is not None

        # Find or create OpenVAS integration
        integ = db.query(models.ScannerIntegration).filter(
            models.ScannerIntegration.scanner_type == "openvas"
        ).first()
        assert integ is not None

        # Reset status
        integ.last_sync_status = "idle"
        db.commit()

        # Enqueue job
        job = enqueue_api_sync_job(db=db, integration=integ, current_user=admin_user)
        assert job.id is not None
        assert job.status == "queued"
        assert job.job_type == "api_sync"
        assert job.integration_id == integ.id

        # Process job via worker processor
        processed = process_next_queued_job()
        assert processed is True

        db.refresh(job)
        assert job.status == "completed"
        assert job.progress_percent == 100
        assert job.findings_count >= 1
        assert job.hosts_count >= 1
        assert job.scan_id is not None
        assert job.duration_seconds >= 0.0

    finally:
        db.close()
