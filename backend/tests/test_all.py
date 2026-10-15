import os
import sys
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Setup path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR / "backend"))

from app.database import Base, get_db
from app.main import app
from app import models
from app.services.parser_nessus import parse_nessus_csv
from app.services.comparative_service import compare_scans

# In-memory SQLite with StaticPool so all connections share the same in-memory DB
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
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=test_engine)
    # Seed users for RBAC testing
    db = TestingSessionLocal()
    from app.auth import get_password_hash
    admin = models.User(
        username="Admin",
        email="admin@gvulstand.local",
        full_name="Admin Test",
        hashed_password=get_password_hash("Admin"),
        role="admin",
        is_active=True
    )
    db.add(admin)

    analyst = models.User(
        username="analista",
        email="analista@gvulstand.local",
        full_name="Analista Seguranca",
        hashed_password=get_password_hash("analista"),
        role="analyst",
        is_active=True
    )
    db.add(analyst)

    auditor = models.User(
        username="auditor",
        email="auditor@gvulstand.local",
        full_name="Auditor ISO",
        hashed_password=get_password_hash("auditor"),
        role="auditor",
        is_active=True
    )
    db.add(auditor)
    
    # Seed sample Asset Group
    group = models.AssetGroup(
        name="Datacenter Test",
        description="Ambiente de Testes",
        network_range="192.168.10.0/24",
        owner="SecOps"
    )
    db.add(group)
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.pop(get_db, None)

client = TestClient(app)

def get_auth_token(username="Admin", password="Admin"):
    login_res = client.post("/api/auth/login", json={"username": username, "password": password})
    return login_res.json()["access_token"]

def test_nessus_parser_unit():
    sample_csv = """Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,Exploit?,Exploit Frameworks,DNS Name,MAC Address
58453,CVE-2012-1823,9.8,Critical,192.168.10.50,tcp,80,PHP CGI RCE,PHP CGI vulnerability,Command injection possible,Upgrade PHP,http://example.com,Vulnerable output,Yes,Metasploit,web-srv.local,00:50:56:01:02:03
10287,CVE-2014-0160,7.5,High,192.168.10.50,tcp,443,Heartbleed,SSL leak,Info leak in OpenSSL,Patch OpenSSL,http://example.com,Heartbleed leak,Yes,Exploit-DB,web-srv.local,00:50:56:01:02:03
"""
    parsed = parse_nessus_csv(sample_csv)
    assert len(parsed["hosts"]) == 1
    assert len(parsed["findings"]) == 2
    assert parsed["stats"]["critical_count"] == 1
    assert parsed["stats"]["high_count"] == 1
    assert parsed["stats"]["exploitable_critical_count"] == 1

    host = parsed["hosts"]["192.168.10.50"]
    assert host["critical_count"] == 1
    assert host["high_count"] == 1
    assert host["exploitable_critical_count"] == 1
    assert host["hostname"] == "web-srv.local"

def test_tenable_official_semicolon_csv():
    tenable_csv = """Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed
100464;CVE-2017-0144;9.3;Critical;SRV-PROD-DB01;tcp;445;Microsoft Windows SMBv1 RCE;SMBv1 vuln;Remote code execution in SMBv1;MS17-010;http://example.com;Vulnerable output;1111-2222;Active;10.10.0.15;srv-db.corp.local;SRV-DB;Windows Server 2016;00:50:56:A1:B2:C3;Windows;9.3;;;;9.8;;;;general;2026/09/01;2026/09/01;9.8;2026/09/01;2026/09/01;101;202;2026/09/01;2026/09/01;;true;Critical;Critical;Critical;;20;remote;1.42;cifs;2026/01/10;2017/03/14;false;true;true;true;true;true;true;true;false;false;true;true;false;
"""
    parsed = parse_nessus_csv(tenable_csv)
    assert "10.10.0.15" in parsed["hosts"]
    assert len(parsed["findings"]) == 1
    finding = parsed["findings"][0]
    assert finding["plugin_id"] == "100464"
    assert finding["cve"] == "CVE-2017-0144"
    assert finding["severity"] == "Critical"
    assert finding["cvss_v3"] == 9.8
    assert finding["exploit_available"] is True
    assert "Metasploit" in finding["exploit_frameworks"]
    assert "CANVAS" in finding["exploit_frameworks"]

    host = parsed["hosts"]["10.10.0.15"]
    assert host["hostname"] == "srv-db.corp.local"
    assert host["os"] == "Windows Server 2016"
    assert host["mac_address"] == "00:50:56:A1:B2:C3"
    assert host["critical_count"] == 1
    assert host["exploitable_critical_count"] == 1

def test_unquoted_newlines_and_mixed_endings():
    # Simulate Nessus output containing raw unquoted newlines and carriage returns
    raw_csv = (
        "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed\r\n"
        "1001;CVE-2022-1234;9.8;Critical;10.0.0.1;tcp;443;Test Unquoted Newline;Synopsis text;Description with\r\nmultiline unquoted\rtext and carriage returns;Upgrade solution;http://ref.com;Output line 1\r\nOutput line 2;uuid-1;Active;10.0.0.1;web.corp;WEB;Linux;00:11:22:33:44:55;Web;9.8;;;;9.8;;;;general;2026/01/01;2026/01/01;9.8;2026/01/01;2026/01/01;1;1;2026/01/01;2026/01/01;;true;Critical;Critical;Critical;;1;remote;1.0;https;2026/01/01;2026/01/01;false;true;false;false;false;false;true;false;false;false;true;true;false;\r\n"
    )
    parsed = parse_nessus_csv(raw_csv)
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["plugin_id"] == "1001"
    assert parsed["findings"][0]["severity"] == "Critical"
    assert parsed["findings"][0]["exploit_available"] is True


def test_login_default_admin():
    # Login with default Admin / Admin
    response = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["username"] == "Admin"
    assert data["user"]["role"] == "admin"

def test_login_invalid_credentials():
    response = client.post("/api/auth/login", json={"username": "Admin", "password": "WrongPassword"})
    assert response.status_code == 401

def test_create_user_and_auth():
    # Get Admin Token
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create new analyst user
    new_user = {
        "username": "analyst_maria",
        "email": "maria@empresa.com",
        "full_name": "Maria Silva",
        "password": "SenhaSegura123!",
        "role": "analyst",
        "is_active": True
    }
    create_res = client.post("/api/users", json=new_user, headers=headers)
    assert create_res.status_code == 201
    user_data = create_res.json()
    assert user_data["username"] == "analyst_maria"
    assert user_data["role"] == "analyst"

    # Login with new user
    login_analyst = client.post("/api/auth/login", json={"username": "analyst_maria", "password": "SenhaSegura123!"})
    assert login_analyst.status_code == 200
    assert login_analyst.json()["user"]["username"] == "analyst_maria"

def test_scan_upload_and_dashboard():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Get asset group id
    groups = client.get("/api/asset-groups", headers=headers).json()
    assert len(groups) >= 1
    group_id = groups[0]["id"]

    # Upload baseline scan
    baseline_csv_path = BASE_DIR / "samples" / "nessus_baseline_scan.csv"
    with open(baseline_csv_path, "rb") as f:
        files = {"file": ("baseline.csv", f, "text/csv")}
        data = {
            "asset_group_id": str(group_id),
            "scan_name": "Scan Baseline Test",
            "scan_type": "baseline",
            "notes": "Teste automatizado"
        }
        upload_res = client.post("/api/scans/upload", files=files, data=data, headers=headers)
        assert upload_res.status_code == 201
        scan_baseline = upload_res.json()
        assert scan_baseline["total_findings"] > 0
        assert scan_baseline["critical_count"] >= 3

    # Upload retest scan
    retest_csv_path = BASE_DIR / "samples" / "nessus_retest_post_remediation.csv"
    with open(retest_csv_path, "rb") as f:
        files = {"file": ("retest.csv", f, "text/csv")}
        data = {
            "asset_group_id": str(group_id),
            "scan_name": "Scan Reteste Test",
            "scan_type": "retest",
            "notes": "Teste de reteste"
        }
        upload_retest_res = client.post("/api/scans/upload", files=files, data=data, headers=headers)
        assert upload_retest_res.status_code == 201
        scan_retest = upload_retest_res.json()

    # Test Dashboard Stats
    stats_res = client.get("/api/dashboard/stats", headers=headers)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_findings"] > 0
    assert stats["critical_count"] > 0
    assert stats["iso27001_risk_score"] > 0
    assert "exploitable_total_count" in stats

    # Test Vulnerabilities with exploit consistency with dashboard
    vulns_exp_res = client.get("/api/vulnerabilities?has_exploit=true", headers=headers)
    assert vulns_exp_res.status_code == 200
    vulns_exp = vulns_exp_res.json()
    assert stats["exploitable_total_count"] == len(vulns_exp)

    # Test Top 100 Critical
    top_crit_res = client.get("/api/dashboard/top-critical", headers=headers)
    assert top_crit_res.status_code == 200
    top_crit = top_crit_res.json()
    assert len(top_crit) > 0
    assert top_crit[0]["severity"] == "Critical"

    # Test Top 20 Hosts with Exploits
    top_exp_res = client.get("/api/dashboard/top-hosts-exploits", headers=headers)
    assert top_exp_res.status_code == 200
    top_exp = top_exp_res.json()
    assert len(top_exp) > 0
    assert top_exp[0]["exploitable_critical_count"] > 0

    # Test Comparative Before vs After (ISO 9001 PDCA)
    diff_res = client.get(
        f"/api/comparative/diff?baseline_scan_id={scan_baseline['id']}&retest_scan_id={scan_retest['id']}", 
        headers=headers
    )
    assert diff_res.status_code == 200
    diff = diff_res.json()
    assert diff["remediation_rate_percent"] > 0
    assert len(diff["remediated_items"]) > 0
    assert len(diff["persisting_items"]) > 0
    assert len(diff["new_items"]) > 0

def test_exploit_verdadeiro_falso_and_info_exclusion():
    header = "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed"
    
    row1 = ["9001", "CVE-2023-0001", "9.8", "Critical", "10.0.0.1", "tcp", "443", "Test Verdadeiro", "Syn", "Desc", "Sol", "", "", "", "Active", "10.0.0.1", "", "", "Linux", "", "Web", "9.8", "", "", "", "9.8", "", "", "", "general", "2026/01/01", "2026/01/01", "9.8", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "Critical", "Critical", "Critical", "", "1", "remote", "1.0", "https", "2026/01/01", "2026/01/01", "false", "VERDADEIRO", "false", "false", "false", "false", "VERDADEIRO", "false", "false", "false", "true", "false", "false", ""]
    row2 = ["9002", "CVE-2023-0002", "5.0", "Medium", "10.0.0.1", "tcp", "80", "Test Falso", "Syn", "Desc", "Sol", "", "", "", "Active", "10.0.0.1", "", "", "Linux", "", "Web", "5.0", "", "", "", "5.0", "", "", "", "general", "2026/01/01", "2026/01/01", "5.0", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "Medium", "Medium", "Medium", "", "1", "remote", "1.0", "http", "2026/01/01", "2026/01/01", "false", "FALSO", "false", "false", "false", "false", "FALSO", "false", "false", "false", "true", "false", "false", ""]
    row3 = ["9003", "", "0.0", "None", "10.0.0.1", "tcp", "0", "Test Info Finding", "Syn", "Desc", "Sol", "", "", "", "Active", "10.0.0.1", "", "", "Linux", "", "Web", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/01/01", "2026/01/01", "0.0", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "http", "2026/01/01", "2026/01/01", "false", "FALSO", "false", "false", "false", "false", "FALSO", "false", "false", "false", "false", "false", "false", ""]

    csv_content = header + "\n" + ";".join(row1) + "\n" + ";".join(row2) + "\n" + ";".join(row3)
    parsed = parse_nessus_csv(csv_content)
    assert len(parsed["findings"]) == 3
    
    # Check exploit true for VERDADEIRO
    f1 = [f for f in parsed["findings"] if f["plugin_id"] == "9001"][0]
    assert f1["exploit_available"] is True
    assert "Metasploit" in f1["exploit_frameworks"]

    # Check exploit false for FALSO
    f2 = [f for f in parsed["findings"] if f["plugin_id"] == "9002"][0]
    assert f2["exploit_available"] is False

    # Check info finding
    f3 = [f for f in parsed["findings"] if f["plugin_id"] == "9003"][0]
    assert f3["severity"] == "Info"

def test_scan_diagnostics_troubleshooting():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    groups = client.get("/api/asset-groups", headers=headers).json()
    group_id = groups[0]["id"]

    header = "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed"
    
    row1 = ["1102", "", "0.0", "None", "192.168.99.1", "icmp", "0", "ICMP Ping Failed", "Host Unreachable", "The host did not reply to ping", "Check firewall", "", "No ICMP response", "", "Active", "192.168.99.1", "", "", "Linux", "", "General", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/01/01", "2026/01/01", "0.0", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "icmp", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]
    row2 = ["24786", "", "0.0", "None", "192.168.99.2", "tcp", "445", "Nessus Windows Credential Checks Not Run", "SMB Auth Failed", "Failed to authenticate via SMB", "Provide valid admin credentials", "", "SMB: Access Denied", "", "Active", "192.168.99.2", "", "", "Windows Server", "", "Windows", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/01/01", "2026/01/01", "0.0", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "cifs", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]
    row3 = ["102095", "", "0.0", "None", "192.168.99.3", "tcp", "22", "SSH Authentication Failure", "SSH Login Failed", "SSH login rejected credentials", "Check authorized_keys", "", "Permission Denied (publickey)", "", "Active", "192.168.99.3", "", "", "Ubuntu Linux", "", "General", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/01/01", "2026/01/01", "0.0", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "ssh", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]

    diag_csv = header + "\n" + ";".join(row1) + "\n" + ";".join(row2) + "\n" + ";".join(row3)
    files = {"file": ("diag_test.csv", diag_csv.encode("utf-8"), "text/csv")}
    data = {
        "asset_group_id": str(group_id),
        "scan_name": "Scan Diagnostico Troubleshoot Test",
        "scan_type": "baseline"
    }
    up_res = client.post("/api/scans/upload", files=files, data=data, headers=headers)
    assert up_res.status_code == 201

    # Call diagnostics API
    diag_res = client.get("/api/dashboard/scan-diagnostics", headers=headers)
    assert diag_res.status_code == 200
    diag_data = diag_res.json()
    assert diag_data["total_error_items"] >= 3
    assert diag_data["auth_errors_count"] >= 1 # 24786 (Windows SMB)
    assert diag_data["permission_errors_count"] >= 1 # 102095 (SSH sudo/elevação)
    assert diag_data["connection_errors_count"] >= 1 # 1102 (ICMP)
    assert len(diag_data["items"]) >= 3

    # Assert plugins 10107 and 10902 are explicitly excluded
    pids = [item["plugin_id"] for item in diag_data["items"]]
    assert "10107" not in pids
    assert "10902" not in pids

def test_multiple_mac_addresses_and_cvss_formats():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    groups = client.get("/api/asset-groups", headers=headers).json()
    group_id = groups[0]["id"]

    header = "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed"
    
    # Multiple MACs separated by spaces and CVSS written as 75 (integer) and 9.8 (float)
    row1 = [
        "8881", "CVE-2023-8881", "75", "High", "10.233.20.4", "tcp", "443", 
        "Test Multi MAC", "Synopsis text", "Description text", "Solution text", "", "Output text", 
        "", "Active", "10.233.20.4", "tecsca2", "TECSCA2", "Microsoft Windows Server 2019 Standard Build 17763", 
        "00:50:56:9C:56:EC 00:50:56:9C:FC:2B 00:50:56:9C:09:60 00:50:56:9C:C5:8E 00:50:56:9C:E3:55", 
        "Windows", "75", "", "", "", "75", "", "", "", "general", "2026/01/01", "2026/01/01", "75", "2026/01/01", "2026/01/01", 
        "1", "1", "2026/01/01", "2026/01/01", "", "true", "High", "High", "High", "", "1", "remote", "1.0", "https", 
        "2026/01/01", "2026/01/01", "FALSO", "VERDADEIRO", "FALSO", "FALSO", "FALSO", "FALSO", "VERDADEIRO", "FALSO", "FALSO", "FALSO", "VERDADEIRO", "FALSO", "FALSO", ""
    ]

    csv_data = header + "\n" + ";".join(row1)
    files = {"file": ("multi_mac_test.csv", csv_data.encode("utf-8"), "text/csv")}
    data = {
        "asset_group_id": str(group_id),
        "scan_name": "Scan Multi MAC Test",
        "scan_type": "baseline"
    }
    res = client.post("/api/scans/upload", files=files, data=data, headers=headers)
    assert res.status_code == 201
    scan_info = res.json()
    assert scan_info["total_findings"] == 1

    # Verify Host Details endpoint
    top_hosts = client.get("/api/dashboard/top-hosts-exploits", headers=headers).json()
    assert len(top_hosts) > 0
    target_host_id = top_hosts[0]["host_id"]
    
    host_res = client.get(f"/api/vulnerabilities/hosts/{target_host_id}", headers=headers)
    assert host_res.status_code == 200
    host_data = host_res.json()
    assert host_data["id"] == target_host_id
    assert host_data["ip_address"] != ""

def test_aging_breakdown_and_treatment_audit_trail():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Verify Aging Breakdown in Dashboard Stats
    stats_res = client.get("/api/dashboard/stats", headers=headers)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "aging_breakdown" in stats
    assert "0_30" in stats["aging_breakdown"]
    assert "31_60" in stats["aging_breakdown"]
    assert "61_90" in stats["aging_breakdown"]
    assert "above_90" in stats["aging_breakdown"]

    # 2. Get a vulnerability and update its treatment status
    vulns_res = client.get("/api/vulnerabilities?limit=5", headers=headers)
    assert vulns_res.status_code == 200
    vulns = vulns_res.json()
    assert len(vulns) > 0
    target_vuln_id = vulns[0]["id"]

    patch_payload = {
        "treatment_status": "In_Remediation",
        "treatment_notes": "Chamado aberto com SecOps #99482"
    }
    patch_res = client.patch(f"/api/vulnerabilities/{target_vuln_id}/treatment", json=patch_payload, headers=headers)
    assert patch_res.status_code == 200
    updated_vuln = patch_res.json()
    assert updated_vuln["treatment_status"] == "In_Remediation"
    assert updated_vuln["treatment_notes"] == "Chamado aberto com SecOps #99482"
    assert updated_vuln["treated_by_username"] in ["Admin", "Administrador Geral", "Admin Test"]
    assert updated_vuln["treated_at"] is not None
    assert updated_vuln["aging_days"] is not None

def test_first_found_date_formats_and_aging_calculation():
    from app.services.parser_nessus import parse_date_safe
    from datetime import datetime

    # 1. Test ISO 8601 with milliseconds and Z
    dt1 = parse_date_safe("2025-08-14T18:01:16.096Z")
    assert dt1 is not None
    assert dt1.year == 2025 and dt1.month == 8 and dt1.day == 14
    assert dt1.hour == 18 and dt1.minute == 1 and dt1.second == 16

    # 2. Test Brazilian format dd/MM/yyyy HH:mm:ss
    dt2 = parse_date_safe("14/08/2025 18:01:16")
    assert dt2 is not None
    assert dt2.year == 2025 and dt2.month == 8 and dt2.day == 14

    # 3. Test Brazilian format dd/MM/yyyy
    dt3 = parse_date_safe("02/09/2024")
    assert dt3 is not None
    assert dt3.year == 2024 and dt3.month == 9 and dt3.day == 2

    # 4. Test Aging calculation
    now = datetime.now()
    aging_days = (now - dt1).days
    assert aging_days > 300  # More than 300 days since Aug 2025

def test_tenable_dashboard_widgets_metrics():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/dashboard/stats", headers=headers)
    assert res.status_code == 200
    stats = res.json()

    # VPR Breakdown
    assert "vpr_breakdown" in stats
    assert "rating_9_10" in stats["vpr_breakdown"]
    assert "rating_7_8_9" in stats["vpr_breakdown"]
    assert "rating_4_6_9" in stats["vpr_breakdown"]
    assert "rating_0_3_9" in stats["vpr_breakdown"]

    # SLA Progress
    assert "sla_progress" in stats
    for sev in ["Critical", "High", "Medium", "Low"]:
        assert sev in stats["sla_progress"]
        assert "meeting" in stats["sla_progress"][sev]
        assert "not_meeting" in stats["sla_progress"][sev]

    # Age SLA Matrix
    assert "age_sla_matrix" in stats
    for sev in ["Critical", "High", "Medium", "Low"]:
        assert sev in stats["age_sla_matrix"]
        for bucket in ["d0_7", "d8_14", "d15_30", "d31_60", "d61_90", "above_90"]:
            assert bucket in stats["age_sla_matrix"][sev]

    # Exploitable Types
    assert "exploitable_types" in stats
    assert "malware" in stats["exploitable_types"]
    assert "remote_low" in stats["exploitable_types"]
    assert "local_low" in stats["exploitable_types"]
    assert "framework_metasploit" in stats["exploitable_types"]
    assert "remote_high" in stats["exploitable_types"]

    # Scan Health & Advisory
    assert "scan_health" in stats
    assert "auth_success" in stats["scan_health"]
    assert "insufficient_access" in stats["scan_health"]
    assert "auth_failure" in stats["scan_health"]

    assert "patch_advisory" in stats
    assert "missing_patches" in stats["patch_advisory"]
    assert "applied_patches" in stats["patch_advisory"]
    if stats["patch_advisory"]["applied_patches"] == 0:
        assert stats["iso9001_remediation_efficiency"] is None

    # CVE Counts per Severity
    assert "cve_counts" in stats
    for k in ["critical", "high", "medium", "low", "exploit", "total"]:
        assert k in stats["cve_counts"]

    # Treatment Breakdown by Severity
    assert "treatment_breakdown" in stats
    for st in ["In_Remediation", "Accepted_Risk", "Remediated", "Open"]:
        assert st in stats["treatment_breakdown"]
        assert "total" in stats["treatment_breakdown"][st]
        assert "critical" in stats["treatment_breakdown"][st]
        assert "high" in stats["treatment_breakdown"][st]
        assert "medium" in stats["treatment_breakdown"][st]
        assert "low" in stats["treatment_breakdown"][st]

def test_bulk_vulnerability_treatment():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # List vulnerabilities to pick some IDs
    list_res = client.get("/api/vulnerabilities?limit=5", headers=headers)
    assert list_res.status_code == 200
    vulns = list_res.json()
    assert len(vulns) > 0
    vuln_ids = [v["id"] for v in vulns]

    # Perform bulk update
    payload = {
        "vulnerability_ids": vuln_ids,
        "treatment_status": "Accepted_Risk",
        "treatment_notes": "Risco aceito em massa para auditoria ISO 27001."
    }
    bulk_res = client.post("/api/vulnerabilities/bulk-treatment", json=payload, headers=headers)
    assert bulk_res.status_code == 200
    res_json = bulk_res.json()
    assert res_json["updated_count"] == len(vuln_ids)
    assert "atualizadas com sucesso" in res_json["message"]

    # Verify each updated vulnerability
    for vid in vuln_ids:
        get_res = client.get(f"/api/vulnerabilities/{vid}", headers=headers)
        assert get_res.status_code == 200
        v_data = get_res.json()
        assert v_data["treatment_status"] == "Accepted_Risk"
        assert v_data["treatment_notes"] == "Risco aceito em massa para auditoria ISO 27001."
        assert v_data["treated_by_username"] is not None
        assert v_data["treated_at"] is not None

def test_comparative_diff_excludes_info_and_none():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create distinct asset group
    grp_res = client.post("/api/asset-groups", json={"name": "Grupo Comparativo Teste Info", "description": "Teste"}, headers=headers)
    assert grp_res.status_code == 201
    group_id = grp_res.json()["id"]

    header = "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed"
    
    # Baseline: 1 Critical, 1 High, 2 Info
    b_row1 = ["1001", "CVE-2026-1001", "9.8", "Critical", "10.0.0.1", "tcp", "445", "Crit Vuln", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "9.8", "", "", "", "9.8", "", "", "", "general", "2026/01/01", "2026/01/01", "9.8", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "Critical", "Critical", "Critical", "", "1", "remote", "1.0", "cifs", "2026/01/01", "2026/01/01", "false", "true", "false", "false", "false", "false", "false", "false", "false", "false", "true", "false", "false", ""]
    b_row2 = ["1002", "CVE-2026-1002", "7.5", "High", "10.0.0.1", "tcp", "80", "High Vuln", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "7.5", "", "", "", "7.5", "", "", "", "general", "2026/01/01", "2026/01/01", "7.5", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "High", "High", "High", "", "1", "remote", "1.0", "http", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]
    b_row3 = ["1003", "", "0.0", "None", "10.0.0.1", "tcp", "22", "SSH Banner Info", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/01/01", "2026/01/01", "0.0", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "ssh", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]
    b_row4 = ["1004", "", "0.0", "None", "10.0.0.1", "icmp", "0", "ICMP Info", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/01/01", "2026/01/01", "0.0", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "icmp", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]

    base_csv = header + "\n" + ";".join(b_row1) + "\n" + ";".join(b_row2) + "\n" + ";".join(b_row3) + "\n" + ";".join(b_row4)
    res_b = client.post("/api/scans/upload", files={"file": ("base.csv", base_csv.encode("utf-8"), "text/csv")}, data={"asset_group_id": str(group_id), "scan_name": "Base Scan", "scan_type": "baseline"}, headers=headers)
    assert res_b.status_code == 201
    base_id = res_b.json()["id"]

    # Retest: 1 High (persisting 1002), 1 Medium (new 1005), 3 Info (1003 + 1004 + 1006) -> 1001 was remediated!
    r_row2 = ["1002", "CVE-2026-1002", "7.5", "High", "10.0.0.1", "tcp", "80", "High Vuln", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "7.5", "", "", "", "7.5", "", "", "", "general", "2026/02/01", "2026/02/01", "7.5", "2026/02/01", "2026/02/01", "2", "2", "2026/02/01", "2026/02/01", "", "true", "High", "High", "High", "", "1", "remote", "1.0", "http", "2026/02/01", "2026/02/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]
    r_row5 = ["1005", "CVE-2026-1005", "5.3", "Medium", "10.0.0.1", "tcp", "8080", "Med Vuln", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "5.3", "", "", "", "5.3", "", "", "", "general", "2026/02/01", "2026/02/01", "5.3", "2026/02/01", "2026/02/01", "2", "2", "2026/02/01", "2026/02/01", "", "true", "Medium", "Medium", "Medium", "", "1", "remote", "1.0", "http", "2026/02/01", "2026/02/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]
    r_row3 = ["1003", "", "0.0", "None", "10.0.0.1", "tcp", "22", "SSH Banner Info", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/02/01", "2026/02/01", "0.0", "2026/02/01", "2026/02/01", "2", "2", "2026/02/01", "2026/02/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "ssh", "2026/02/01", "2026/02/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]
    r_row4 = ["1004", "", "0.0", "None", "10.0.0.1", "icmp", "0", "ICMP Info", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/02/01", "2026/02/01", "0.0", "2026/02/01", "2026/02/01", "2", "2", "2026/02/01", "2026/02/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "icmp", "2026/02/01", "2026/02/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]
    r_row6 = ["1006", "", "0.0", "None", "10.0.0.1", "tcp", "53", "DNS Info", "syn", "desc", "sol", "", "out", "", "Active", "10.0.0.1", "", "", "Linux", "", "General", "0.0", "", "", "", "0.0", "", "", "", "general", "2026/02/01", "2026/02/01", "0.0", "2026/02/01", "2026/02/01", "2", "2", "2026/02/01", "2026/02/01", "", "true", "None", "Info", "None", "", "1", "remote", "1.0", "dns", "2026/02/01", "2026/02/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", ""]

    retest_csv = header + "\n" + ";".join(r_row2) + "\n" + ";".join(r_row5) + "\n" + ";".join(r_row3) + "\n" + ";".join(r_row4) + "\n" + ";".join(r_row6)
    res_r = client.post("/api/scans/upload", files={"file": ("retest.csv", retest_csv.encode("utf-8"), "text/csv")}, data={"asset_group_id": str(group_id), "scan_name": "Retest Scan", "scan_type": "retest"}, headers=headers)
    assert res_r.status_code == 201
    retest_id = res_r.json()["id"]

    # Execute comparative diff
    diff_res = client.get(f"/api/comparative/diff?baseline_scan_id={base_id}&retest_scan_id={retest_id}", headers=headers)
    assert diff_res.status_code == 200
    report = diff_res.json()

    # Verify counts exclude Info/None
    assert report["total_before"] == 2 # Only 1001 (Crit) and 1002 (High)
    assert report["total_after"] == 2  # Only 1002 (High) and 1005 (Med)
    assert report["remediated_count"] == 1 # 1001 was remediated
    assert report["persisting_count"] == 1 # 1002 is persisting
    assert report["new_count"] == 1        # 1005 is new
    assert report["remediation_rate_percent"] == 50.0 # 1 out of 2 = 50%

    # Verify no Info items in remediated, persisting or new
    all_diff_items = report["remediated_items"] + report["persisting_items"] + report["new_items"]
    for item in all_diff_items:
        assert item["severity"] in ["Critical", "High", "Medium", "Low"]
        assert item["severity"] not in ["Info", "None", "none", "info"]

    assert report["severity_before"]["Info"] == 0
    assert report["severity_after"]["Info"] == 0

def test_multi_cve_aggregation_in_parser_and_upload():
    """Valida a agregação correta de múltiplas CVEs em linhas separadas e na mesma célula para um mesmo plugin."""
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Create a fresh group for this test
    g_res = client.post("/api/asset-groups", json={"name": "Multi-CVE Test Group", "network_range": "10.50.0.0/24"}, headers=headers)
    assert g_res.status_code == 201
    group_id = g_res.json()["id"]

    header = "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed"
    
    # 3 rows for Plugin 320184 on same host and port 445, each with different CVEs, plus row 1 has a comma-separated CVE
    r1 = ["320184", "CVE-2026-48563, CVE-2026-9999", "10.0", "High", "10.50.0.10", "tcp", "445", "Windows Cumulative Security Update", "synopsis text", "desc text", "sol text", "", "output 1", "", "Active", "10.50.0.10", "", "", "Windows Server", "", "General", "10.0", "", "", "", "10.0", "", "", "", "general", "2026/01/01", "2026/01/01", "10.0", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "High", "High", "High", "", "1", "remote", "1.0", "cifs", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "true", "false", "false", ""]
    r2 = ["320184", "CVE-2026-8863", "9.8", "Critical", "10.50.0.10", "tcp", "445", "Windows Cumulative Security Update", "synopsis text", "desc text", "sol text", "", "output 2", "", "Active", "10.50.0.10", "", "", "Windows Server", "", "General", "9.8", "", "", "", "9.8", "", "", "", "general", "2026/01/01", "2026/01/01", "9.8", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "Critical", "Critical", "Critical", "", "1", "remote", "1.0", "cifs", "2026/01/01", "2026/01/01", "false", "true", "false", "false", "false", "false", "true", "false", "false", "false", "true", "false", "false", ""]
    r3 = ["320184", "CVE-2026-41092", "7.5", "High", "10.50.0.10", "tcp", "445", "Windows Cumulative Security Update", "synopsis text", "desc text", "sol text", "", "output 3", "", "Active", "10.50.0.10", "", "", "Windows Server", "", "General", "7.5", "", "", "", "7.5", "", "", "", "general", "2026/01/01", "2026/01/01", "7.5", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "High", "High", "High", "", "1", "remote", "1.0", "cifs", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "true", "false", "false", ""]

    csv_content = header + "\n" + ";".join(r1) + "\n" + ";".join(r2) + "\n" + ";".join(r3)
    
    # 1. Test parser unit level
    parsed = parse_nessus_csv(csv_content)
    assert len(parsed["hosts"]) == 1
    assert len(parsed["findings"]) == 1 # All 3 rows aggregated into 1 finding!
    f0 = parsed["findings"][0]
    assert f0["plugin_id"] == "320184"
    assert f0["severity"] == "Critical" # Escalated from High to Critical
    assert f0["cvss_v3"] == 10.0
    assert f0["exploit_available"] is True # Aggregated from r2
    assert "Metasploit" in f0["exploit_frameworks"]
    for expected_cve in ["CVE-2026-48563", "CVE-2026-9999", "CVE-2026-8863", "CVE-2026-41092"]:
        assert expected_cve in f0["cve"]

    # 2. Test upload endpoint and API responses
    up_res = client.post(
        "/api/scans/upload",
        files={"file": ("multi_cve_scan.csv", csv_content.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(group_id), "scan_name": "Multi CVE Scan", "scan_type": "baseline"},
        headers=headers
    )
    assert up_res.status_code == 201
    scan_id = up_res.json()["id"]

    # Check vulnerability API
    v_res = client.get(f"/api/vulnerabilities?scan_id={scan_id}", headers=headers)
    assert v_res.status_code == 200
    vulns = v_res.json()
    assert len(vulns) == 1
    v = vulns[0]
    assert v["cve_count"] == 4
    assert set(v["cve_list"]) == {"CVE-2026-48563", "CVE-2026-9999", "CVE-2026-8863", "CVE-2026-41092"}

    # Check Top 100 API
    top_res = client.get(f"/api/dashboard/top-critical?asset_group_id={group_id}", headers=headers)
    assert top_res.status_code == 200
    top_items = top_res.json()
    assert len(top_items) == 1
    assert top_items[0]["cve_count"] == 4
    assert "CVE-2026-48563" in top_items[0]["cve_list"]

def test_parent_and_subgroup_management_and_filtering():
    """Valida criação de hierarquia Corporativa (Pai e Subgrupos) e filtros consolidados nos painéis."""
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create Parent / Corporate Group
    corp_res = client.post(
        "/api/asset-groups",
        json={"name": "Grupo Corporativo Global", "description": "Holding Corporativa"},
        headers=headers
    )
    assert corp_res.status_code == 201
    corp_id = corp_res.json()["id"]

    # 2. Create two subgroups
    sub1_res = client.post(
        "/api/asset-groups",
        json={"name": "Subgrupo Datacenter SP", "parent_id": corp_id, "network_range": "10.10.0.0/24"},
        headers=headers
    )
    assert sub1_res.status_code == 201
    sub1_id = sub1_res.json()["id"]

    sub2_res = client.post(
        "/api/asset-groups",
        json={"name": "Subgrupo Nuvem AWS", "parent_id": corp_id, "network_range": "172.30.0.0/16"},
        headers=headers
    )
    assert sub2_res.status_code == 201
    sub2_id = sub2_res.json()["id"]

    # 3. Verify hierarchy in list
    list_res = client.get("/api/asset-groups", headers=headers)
    assert list_res.status_code == 200
    groups_data = {g["id"]: g for g in list_res.json()}
    assert groups_data[corp_id]["subgroups_count"] == 2
    assert groups_data[sub1_id]["parent_id"] == corp_id
    assert groups_data[sub1_id]["parent_name"] == "Grupo Corporativo Global"
    assert groups_data[sub2_id]["parent_id"] == corp_id

    # 4. Verify loop prevention on update
    bad_up1 = client.put(f"/api/asset-groups/{corp_id}", json={"parent_id": corp_id}, headers=headers)
    assert bad_up1.status_code == 400 # Cannot be own parent

    bad_up2 = client.put(f"/api/asset-groups/{corp_id}", json={"parent_id": sub1_id}, headers=headers)
    assert bad_up2.status_code == 400 # Circular reference

    # 5. Upload scan to Subgroup 1
    header = "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed"
    row_sub1 = ["2001", "CVE-2026-2001", "9.8", "Critical", "10.10.0.5", "tcp", "445", "Crit SP", "syn", "desc", "sol", "", "out", "", "Active", "10.10.0.5", "", "", "Linux", "", "General", "9.8", "", "", "", "9.8", "", "", "", "general", "2026/01/01", "2026/01/01", "9.8", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "Critical", "Critical", "Critical", "", "1", "remote", "1.0", "cifs", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "true", "false", "false", ""]
    csv_sub1 = header + "\n" + ";".join(row_sub1)
    
    up1 = client.post(
        "/api/scans/upload",
        files={"file": ("scan_sp.csv", csv_sub1.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(sub1_id), "scan_name": "Scan Datacenter SP", "scan_type": "baseline"},
        headers=headers
    )
    assert up1.status_code == 201

    # 6. Upload scan to Subgroup 2
    row_sub2 = ["2002", "CVE-2026-2002", "7.5", "High", "172.30.0.8", "tcp", "80", "High AWS", "syn", "desc", "sol", "", "out", "", "Active", "172.30.0.8", "", "", "Linux", "", "General", "7.5", "", "", "", "7.5", "", "", "", "general", "2026/01/01", "2026/01/01", "7.5", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "High", "High", "High", "", "1", "remote", "1.0", "http", "2026/01/01", "2026/01/01", "false", "false", "false", "false", "false", "false", "false", "false", "false", "false", "true", "false", "false", ""]
    csv_sub2 = header + "\n" + ";".join(row_sub2)
    
    up2 = client.post(
        "/api/scans/upload",
        files={"file": ("scan_aws.csv", csv_sub2.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(sub2_id), "scan_name": "Scan AWS Cloud", "scan_type": "baseline"},
        headers=headers
    )
    assert up2.status_code == 201

    # 7. Query Scans filtering by Parent Corporate Group -> must return scans from BOTH subgroups!
    corp_scans = client.get(f"/api/scans?asset_group_id={corp_id}", headers=headers).json()
    assert len(corp_scans) == 2

    # Query Scans filtering by Subgroup 1 -> returns ONLY 1 scan
    sub1_scans = client.get(f"/api/scans?asset_group_id={sub1_id}", headers=headers).json()
    assert len(sub1_scans) == 1
    assert sub1_scans[0]["scan_name"] == "Scan Datacenter SP"

    # 8. Query Dashboard Stats for Parent Corporate Group -> Consolidated (Critical from SP + High from AWS = 2 findings)
    corp_stats = client.get(f"/api/dashboard/stats?asset_group_id={corp_id}", headers=headers).json()
    assert corp_stats["critical_count"] == 1
    assert corp_stats["high_count"] == 1
    assert corp_stats["total_findings"] == 2

    # Query Dashboard Stats for Subgroup 1 specifically -> Only Critical (1 finding)
    sub1_stats = client.get(f"/api/dashboard/stats?asset_group_id={sub1_id}", headers=headers).json()
    assert sub1_stats["critical_count"] == 1
    assert sub1_stats["high_count"] == 0
    assert sub1_stats["total_findings"] == 1

def test_plugin_solution_and_affected_hosts():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Create two different asset groups
    g1 = client.post("/api/asset-groups", json={"name": "Grupo Producao A", "network_range": "10.1.0.0/24"}, headers=headers).json()
    g2 = client.post("/api/asset-groups", json={"name": "Grupo Producao B", "network_range": "10.2.0.0/24"}, headers=headers).json()

    header = "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed"

    # Scan for Group A with Critical Plugin 99999 on 10.1.0.10
    row_a = ["99999", "CVE-2023-9999", "9.8", "Critical", "10.1.0.10", "tcp", "443", "Apache Vulnerability", "Web server issue", "Detailed vuln description", "Upgrade Apache to latest version", "https://httpd.apache.org", "Apache 2.4.49", "", "Active", "10.1.0.10", "web1.prod", "SRV-WEB1", "Linux", "", "Web Servers", "9.8", "", "", "", "9.8", "", "", "", "general", "2026/01/01", "2026/01/01", "9.8", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "Critical", "Critical", "Critical", "", "1", "remote", "1.0", "https", "2026/01/01", "2026/01/01", "false", "true", "false", "false", "false", "false", "true", "false", "false", "false", "true", "false", "false", ""]
    csv_a = header + "\n" + ";".join(row_a)
    up_a = client.post(
        "/api/scans/upload",
        files={"file": ("scan_a.csv", csv_a.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(g1["id"]), "scan_name": "Scan Prod A", "scan_type": "baseline"},
        headers=headers
    )
    assert up_a.status_code == 201

    # Scan for Group B with SAME Critical Plugin 99999 on 10.2.0.20
    row_b = ["99999", "CVE-2023-9999, CVE-2023-8888", "9.8", "Critical", "10.2.0.20", "tcp", "8443", "Apache Vulnerability", "Web server issue", "Detailed vuln description", "Upgrade Apache to latest version", "https://httpd.apache.org", "Apache 2.4.49", "", "Active", "10.2.0.20", "web2.prod", "SRV-WEB2", "Linux", "", "Web Servers", "9.8", "", "", "", "9.8", "", "", "", "general", "2026/01/01", "2026/01/01", "9.8", "2026/01/01", "2026/01/01", "1", "1", "2026/01/01", "2026/01/01", "", "true", "Critical", "Critical", "Critical", "", "1", "remote", "1.0", "https", "2026/01/01", "2026/01/01", "false", "true", "false", "false", "false", "false", "true", "false", "false", "false", "true", "false", "false", ""]
    csv_b = header + "\n" + ";".join(row_b)
    up_b = client.post(
        "/api/scans/upload",
        files={"file": ("scan_b.csv", csv_b.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(g2["id"]), "scan_name": "Scan Prod B", "scan_type": "baseline"},
        headers=headers
    )
    assert up_b.status_code == 201

    # Now call plugin solution endpoint across ALL groups
    res = client.get("/api/dashboard/plugin-solution/99999", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["plugin_id"] == "99999"
    assert data["plugin_name"] == "Apache Vulnerability"
    assert data["solution"] == "Upgrade Apache to latest version"
    assert data["exploit_available"] is True
    # Verify multi-CVE consolidation
    assert "CVE-2023-9999" in data["cve_list"]
    assert "CVE-2023-8888" in data["cve_list"]
    assert data["cve_count"] == 2

    # Verify ALL affected hosts are listed with their respective groups
    assert data["total_affected_hosts"] == 2
    hosts = data["affected_hosts"]
    assert len(hosts) == 2
    
    ips = [h["ip_address"] for h in hosts]
    assert "10.1.0.10" in ips
    assert "10.2.0.20" in ips

    group_names = [h["asset_group_name"] for h in hosts]
    assert "Grupo Producao A" in group_names
    assert "Grupo Producao B" in group_names

    # Verify individual ports
    ports = {h["ip_address"]: h["port"] for h in hosts}
    assert ports["10.1.0.10"] == 443
    assert ports["10.2.0.20"] == 8443

    # Test filtering by specific asset group
    res_filtered = client.get(f"/api/dashboard/plugin-solution/99999?asset_group_id={g1['id']}", headers=headers)
    assert res_filtered.status_code == 200
    data_filtered = res_filtered.json()
    assert data_filtered["total_affected_hosts"] == 1
    assert data_filtered["affected_hosts"][0]["ip_address"] == "10.1.0.10"
    assert data_filtered["affected_hosts"][0]["asset_group_name"] == "Grupo Producao A"


def test_rbac_user_management():
    admin_token = get_auth_token("Admin", "Admin")
    analyst_token = get_auth_token("analista", "analista")
    auditor_token = get_auth_token("auditor", "auditor")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

    # 1. Admin can list users and create a new user
    res = client.get("/api/users", headers=admin_headers)
    assert res.status_code == 200
    assert len(res.json()) >= 3

    new_user_payload = {
        "username": "novousuario",
        "email": "novo@gvulstand.local",
        "full_name": "Novo Usuario Teste",
        "password": "Password123!",
        "role": "analyst",
        "is_active": True
    }
    create_res = client.post("/api/users", json=new_user_payload, headers=admin_headers)
    assert create_res.status_code == 201
    created_id = create_res.json()["id"]

    # 2. Analyst CANNOT list users or create users (403 Forbidden)
    res_analyst = client.get("/api/users", headers=analyst_headers)
    assert res_analyst.status_code == 403

    res_analyst_create = client.post("/api/users", json=new_user_payload, headers=analyst_headers)
    assert res_analyst_create.status_code == 403

    # 3. Auditor CANNOT list users or create users (403 Forbidden)
    res_auditor = client.get("/api/users", headers=auditor_headers)
    assert res_auditor.status_code == 403

    res_auditor_create = client.post("/api/users", json=new_user_payload, headers=auditor_headers)
    assert res_auditor_create.status_code == 403

    # Clean up created user by admin
    del_res = client.delete(f"/api/users/{created_id}", headers=admin_headers)
    assert del_res.status_code == 200


def test_rbac_asset_group_permissions():
    admin_token = get_auth_token("Admin", "Admin")
    analyst_token = get_auth_token("analista", "analista")
    auditor_token = get_auth_token("auditor", "auditor")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

    # 1. Auditor can view/list groups, but CANNOT create, update or delete (403)
    res_list = client.get("/api/asset-groups", headers=auditor_headers)
    assert res_list.status_code == 200

    res_audit_create = client.post(
        "/api/asset-groups",
        json={"name": "Auditor Group", "network_range": "10.50.0.0/24"},
        headers=auditor_headers
    )
    assert res_audit_create.status_code == 403

    # 2. Analyst CAN create and update asset groups
    res_analyst_create = client.post(
        "/api/asset-groups",
        json={"name": "Analyst Created Group", "network_range": "10.60.0.0/24", "description": "Criado por analista"},
        headers=analyst_headers
    )
    assert res_analyst_create.status_code == 201
    group_id = res_analyst_create.json()["id"]

    res_analyst_update = client.put(
        f"/api/asset-groups/{group_id}",
        json={"name": "Analyst Updated Group", "network_range": "10.60.0.0/24"},
        headers=analyst_headers
    )
    assert res_analyst_update.status_code == 200
    assert res_analyst_update.json()["name"] == "Analyst Updated Group"

    # 3. Analyst CANNOT delete asset groups (Only Admin can delete)
    res_analyst_del = client.delete(f"/api/asset-groups/{group_id}", headers=analyst_headers)
    assert res_analyst_del.status_code == 403

    # 4. Auditor CANNOT update or delete
    res_auditor_update = client.put(
        f"/api/asset-groups/{group_id}",
        json={"name": "Auditor Attempt Update"},
        headers=auditor_headers
    )
    assert res_auditor_update.status_code == 403

    res_auditor_del = client.delete(f"/api/asset-groups/{group_id}", headers=auditor_headers)
    assert res_auditor_del.status_code == 403

    # 5. Admin CAN delete the asset group
    res_admin_del = client.delete(f"/api/asset-groups/{group_id}", headers=admin_headers)
    assert res_admin_del.status_code == 200


def test_rbac_scan_import_and_deletion():
    admin_token = get_auth_token("Admin", "Admin")
    analyst_token = get_auth_token("analista", "analista")
    auditor_token = get_auth_token("auditor", "auditor")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

    # Group for scanning
    grp_res = client.post(
        "/api/asset-groups",
        json={"name": "Scan RBAC Group", "network_range": "10.70.0.0/24"},
        headers=admin_headers
    )
    grp_id = grp_res.json()["id"]

    sample_csv = """Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed
10001;CVE-2023-0001;7.5;High;10.70.0.5;tcp;80;RBAC Test Vuln;Synopsis;Desc;Sol;http://ref.local;Out;;Active;10.70.0.5;h1;H1;Linux;;Web;7.5;;;;7.5;;;;general;2026/01/01;2026/01/01;7.5;2026/01/01;2026/01/01;1;1;2026/01/01;2026/01/01;;true;High;High;High;;1;remote;1.0;http;2026/01/01;2026/01/01;false;false;false;false;false;false;false;false;false;false;false;false;false;
"""

    # 1. Auditor CANNOT upload scans (403 Forbidden)
    up_auditor = client.post(
        "/api/scans/upload",
        files={"file": ("audit.csv", sample_csv.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(grp_id), "scan_name": "Audit Upload Attempt", "scan_type": "baseline"},
        headers=auditor_headers
    )
    assert up_auditor.status_code == 403

    # 2. Analyst CAN upload scans (201 Created)
    up_analyst = client.post(
        "/api/scans/upload",
        files={"file": ("analyst.csv", sample_csv.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(grp_id), "scan_name": "Analyst Upload", "scan_type": "baseline"},
        headers=analyst_headers
    )
    assert up_analyst.status_code == 201
    scan_id = up_analyst.json()["id"]

    # 3. Analyst CANNOT delete scans (403 Forbidden - only Admin can delete)
    del_analyst = client.delete(f"/api/scans/{scan_id}", headers=analyst_headers)
    assert del_analyst.status_code == 403

    # 4. Auditor CANNOT delete scans (403 Forbidden)
    del_auditor = client.delete(f"/api/scans/{scan_id}", headers=auditor_headers)
    assert del_auditor.status_code == 403

    # 5. Admin CAN delete scans (200 OK)
    del_admin = client.delete(f"/api/scans/{scan_id}", headers=admin_headers)
    assert del_admin.status_code == 200

    # Clean up group
    client.delete(f"/api/asset-groups/{grp_id}", headers=admin_headers)


def test_rbac_vulnerability_treatment_and_auditing():
    admin_token = get_auth_token("Admin", "Admin")
    analyst_token = get_auth_token("analista", "analista")
    auditor_token = get_auth_token("auditor", "auditor")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

    # Create scan with vulnerability to test treatment
    grp_res = client.post(
        "/api/asset-groups",
        json={"name": "Treatment RBAC Group", "network_range": "10.80.0.0/24"},
        headers=admin_headers
    )
    grp_id = grp_res.json()["id"]

    csv_data = """Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed
20001;CVE-2023-20001;8.5;High;10.80.0.10;tcp;443;Treatment Test Vuln;Synopsis;Desc;Sol;http://ref.local;Out;;Active;10.80.0.10;h2;H2;Linux;;Web;8.5;;;;8.5;;;;general;2026/01/01;2026/01/01;8.5;2026/01/01;2026/01/01;1;1;2026/01/01;2026/01/01;;true;High;High;High;;1;remote;1.0;https;2026/01/01;2026/01/01;false;false;false;false;false;false;false;false;false;false;false;false;false;
20002;CVE-2023-20002;9.8;Critical;10.80.0.10;tcp;22;Bulk Treatment Test Vuln;Synopsis;Desc;Sol;http://ref.local;Out;;Active;10.80.0.10;h2;H2;Linux;;SSH;9.8;;;;9.8;;;;general;2026/01/01;2026/01/01;9.8;2026/01/01;2026/01/01;1;1;2026/01/01;2026/01/01;;true;Critical;Critical;Critical;;1;remote;1.0;ssh;2026/01/01;2026/01/01;false;false;false;false;false;false;false;false;false;false;false;false;false;
"""
    up = client.post(
        "/api/scans/upload",
        files={"file": ("treatment_test.csv", csv_data.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(grp_id), "scan_name": "Treatment Scan", "scan_type": "baseline"},
        headers=admin_headers
    )
    assert up.status_code == 201

    # Fetch vulnerabilities
    vulns_res = client.get(f"/api/vulnerabilities?asset_group_id={grp_id}", headers=auditor_headers)
    assert vulns_res.status_code == 200
    vulns_data = vulns_res.json()
    vulns = vulns_data["items"] if isinstance(vulns_data, dict) and "items" in vulns_data else vulns_data
    assert len(vulns) == 2
    v1_id = vulns[0]["id"]
    v2_id = vulns[1]["id"]

    # 1. Auditor CAN read vulnerability details
    v_detail = client.get(f"/api/vulnerabilities/{v1_id}", headers=auditor_headers)
    assert v_detail.status_code == 200
    assert v_detail.json()["id"] == v1_id

    # 2. Auditor CANNOT perform single treatment (403 Forbidden)
    audit_treat = client.patch(
        f"/api/vulnerabilities/{v1_id}/treatment",
        json={"treatment_status": "Remediated", "treatment_notes": "Auditor Tentando Salvar"},
        headers=auditor_headers
    )
    assert audit_treat.status_code == 403

    # 3. Auditor CANNOT perform bulk treatment (403 Forbidden)
    audit_bulk = client.post(
        "/api/vulnerabilities/bulk-treatment",
        json={"vulnerability_ids": [v1_id, v2_id], "treatment_status": "Remediated", "treatment_notes": "Bulk por Auditor"},
        headers=auditor_headers
    )
    assert audit_bulk.status_code == 403

    # 4. Analyst CAN perform single treatment (200 OK)
    analyst_treat = client.patch(
        f"/api/vulnerabilities/{v1_id}/treatment",
        json={"treatment_status": "In_Remediation", "treatment_notes": "Tratativa iniciada pelo analista de seguranca"},
        headers=analyst_headers
    )
    assert analyst_treat.status_code == 200
    assert analyst_treat.json()["treatment_status"] == "In_Remediation"
    assert analyst_treat.json()["treated_by_username"] in ("analista", "Analista Seguranca")

    # 5. Analyst CAN perform bulk treatment (200 OK)
    analyst_bulk = client.post(
        "/api/vulnerabilities/bulk-treatment",
        json={"vulnerability_ids": [v1_id, v2_id], "treatment_status": "Accepted_Risk", "treatment_notes": "Risco aceito justificativa ISO 27001"},
        headers=analyst_headers
    )
    assert analyst_bulk.status_code == 200
    assert analyst_bulk.json()["updated_count"] == 2

    # Verify auditor sees the updated treatment and audit trail (read-only)
    v_check = client.get(f"/api/vulnerabilities/{v1_id}", headers=auditor_headers)
    assert v_check.status_code == 200
    assert v_check.json()["treatment_status"] == "Accepted_Risk"
    assert v_check.json()["treated_by_username"] in ("analista", "Analista Seguranca")

    # 6. Admin CAN also perform treatments
    admin_treat = client.patch(
        f"/api/vulnerabilities/{v1_id}/treatment",
        json={"treatment_status": "Remediated", "treatment_notes": "Validado pelo Admin"},
        headers=admin_headers
    )
    assert admin_treat.status_code == 200
    assert admin_treat.json()["treatment_status"] == "Remediated"
    assert admin_treat.json()["treated_by_username"] in ("Admin", "Admin Test")


def test_scan_date_and_free_comparative_selection():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create a new asset group
    group_res = client.post("/api/asset-groups", json={
        "name": "Scan Date Selection Test Group",
        "description": "Teste de comparativo e data de scan",
        "network_range": "10.50.0.0/24",
        "owner": "SecOps"
    }, headers=headers)
    assert group_res.status_code == 201
    group_id = group_res.json()["id"]

    sample_csv_1 = """Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,Exploit?,Exploit Frameworks,DNS Name,MAC Address
10001,CVE-2024-0001,9.8,Critical,10.50.0.1,tcp,443,Vuln Scan 1,Synopsis 1,Desc 1,Sol 1,,Output 1,No,,srv1,00:11:22:33:44:55
"""
    sample_csv_2 = """Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,Exploit?,Exploit Frameworks,DNS Name,MAC Address
10002,CVE-2024-0002,9.8,Critical,10.50.0.2,tcp,443,Vuln Scan 2,Synopsis 2,Desc 2,Sol 2,,Output 2,No,,srv2,00:11:22:33:44:56
"""

    # 1. Upload scan 1 with scan_date = "2026-09-10" without scan_type
    res_1 = client.post(
        "/api/scans/upload",
        files={"file": ("scan1.csv", sample_csv_1.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(group_id), "scan_name": "Scan Mais Recente Setembro", "scan_date": "2026-09-10"},
        headers=headers
    )
    assert res_1.status_code == 201
    scan_1_id = res_1.json()["id"]
    assert res_1.json()["scan_type"] == "baseline"

    # 2. Upload scan 2 with older scan_date = "2026-05-01" uploaded AFTER scan 1
    res_2 = client.post(
        "/api/scans/upload",
        files={"file": ("scan2.csv", sample_csv_2.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(group_id), "scan_name": "Scan Mais Antigo Maio", "scan_date": "2026-05-01"},
        headers=headers
    )
    assert res_2.status_code == 201
    scan_2_id = res_2.json()["id"]

    # 3. Check list_vulnerabilities without scan_id for this group:
    # It must return vulnerabilities from the scan with the most recent scan_date (scan 1, 2026-09-10), NOT scan 2!
    vulns_res = client.get(f"/api/vulnerabilities?asset_group_id={group_id}", headers=headers)
    assert vulns_res.status_code == 200
    vulns = vulns_res.json()
    assert len(vulns) == 1
    assert vulns[0]["plugin_id"] == "10001"
    assert vulns[0]["scan_id"] == scan_1_id

    # 4. Check /comparative/scans-by-group: returns both scans ordered by scan_date asc
    comp_scans_res = client.get(f"/api/comparative/scans-by-group/{group_id}", headers=headers)
    assert comp_scans_res.status_code == 200
    comp_scans = comp_scans_res.json()
    assert len(comp_scans) == 2
    # Oldest date first
    assert comp_scans[0]["id"] == scan_2_id
    assert comp_scans[1]["id"] == scan_1_id


def test_vulnerabilities_host_filter_and_unique_hosts():
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create a dedicated asset group
    ag_res = client.post("/api/asset-groups", json={"name": "Grupo Teste Host Filter", "description": "Desc"}, headers=headers)
    assert ag_res.status_code == 201
    group_id = ag_res.json()["id"]

    csv_data = """Plugin,Plugin Name,Family,Severity,IP Address,Protocol,Port,Exploit?,CVE,Risk,Host Name
1001,Vuln Host Alpha,General,High,10.0.0.10,TCP,443,No,CVE-2026-0001,High,srv-alpha.corp
1002,Vuln Host Beta,General,Critical,10.0.0.20,TCP,80,Yes,CVE-2026-0002,Critical,srv-beta.corp
1003,Vuln Host Alpha 2,General,Medium,10.0.0.10,TCP,22,No,,Medium,srv-alpha.corp
"""
    upload_res = client.post(
        "/api/scans/upload",
        files={"file": ("test_host_filter.csv", csv_data.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(group_id), "scan_name": "Scan Host Test", "scan_date": "2026-09-11"},
        headers=headers
    )
    assert upload_res.status_code == 201

    # 2. Test /api/vulnerabilities/unique-hosts endpoint
    uh_res = client.get(f"/api/vulnerabilities/unique-hosts?asset_group_id={group_id}", headers=headers)
    assert uh_res.status_code == 200
    unique_hosts = uh_res.json()
    assert len(unique_hosts) == 2
    ips = [h["ip"] for h in unique_hosts]
    assert "10.0.0.10" in ips
    assert "10.0.0.20" in ips

    # 3. Test filtering by specific IP "10.0.0.10"
    filter_ip_res = client.get(f"/api/vulnerabilities?asset_group_id={group_id}&host=10.0.0.10", headers=headers)
    assert filter_ip_res.status_code == 200
    vulns_ip = filter_ip_res.json()
    assert len(vulns_ip) == 2
    assert all(v["host_ip"] == "10.0.0.10" for v in vulns_ip)

    # 4. Test filtering by hostname "srv-beta"
    filter_host_res = client.get(f"/api/vulnerabilities?asset_group_id={group_id}&host=srv-beta", headers=headers)
    assert filter_host_res.status_code == 200
    vulns_host = filter_host_res.json()
    assert len(vulns_host) == 1
    assert vulns_host[0]["host_ip"] == "10.0.0.20"
    assert vulns_host[0]["host_name"] == "srv-beta.corp"

    # 5. Test with pagination
    paged_res = client.get(f"/api/vulnerabilities?asset_group_id={group_id}&host=10.0.0.10&page=1&page_size=10", headers=headers)
    assert paged_res.status_code == 200
    paged_data = paged_res.json()
    assert paged_data["total"] == 2
    assert len(paged_data["items"]) == 2
    assert paged_data["items"][0]["host_ip"] == "10.0.0.10"

def test_asset_group_scoped_permissions_and_scan_deletion():
    client = TestClient(app)
    # 1. Login as Admin
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert login_res.status_code == 200
    admin_token = login_res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Create Group A and Group B
    grp_a_res = client.post("/api/asset-groups", json={"name": "Scope-Group-Alpha", "sla_critical_days": 7}, headers=admin_headers)
    assert grp_a_res.status_code in [201, 400]
    grp_a_id = grp_a_res.json()["id"] if grp_a_res.status_code == 201 else [g["id"] for g in client.get("/api/asset-groups", headers=admin_headers).json() if g["name"] == "Scope-Group-Alpha"][0]

    grp_b_res = client.post("/api/asset-groups", json={"name": "Scope-Group-Beta", "sla_critical_days": 7}, headers=admin_headers)
    assert grp_b_res.status_code in [201, 400]
    grp_b_id = grp_b_res.json()["id"] if grp_b_res.status_code == 201 else [g["id"] for g in client.get("/api/asset-groups", headers=admin_headers).json() if g["name"] == "Scope-Group-Beta"][0]

    # 3. Create scoped analyst: permitted for Group A (treat=True, import=False, author=True), NO permission for Group B
    client.delete(f"/api/users/{grp_a_id}", headers=admin_headers) # safe check
    user_payload = {
        "username": "analista_scoped",
        "email": "scoped@gvulstand.local",
        "full_name": "Analista Restrito",
        "password": "scoped123password",
        "role": "analyst",
        "is_active": True,
        "auth_type": "local",
        "allowed_groups": [
            {
                "asset_group_id": grp_a_id,
                "can_treat": True,
                "can_import": False,
                "can_author": True
            }
        ]
    }
    create_user_res = client.post("/api/users", json=user_payload, headers=admin_headers)
    assert create_user_res.status_code == 201
    created_user = create_user_res.json()
    assert len(created_user["allowed_groups"]) == 1
    assert created_user["allowed_group_ids"] == [grp_a_id]

    # 4. Login as analista_scoped
    scoped_login = client.post("/api/auth/login", json={"username": "analista_scoped", "password": "scoped123password"})
    assert scoped_login.status_code == 200
    scoped_token = scoped_login.json()["access_token"]
    scoped_headers = {"Authorization": f"Bearer {scoped_token}"}

    # 5. Check /me and /asset-groups
    me_res = client.get("/api/auth/me", headers=scoped_headers)
    assert me_res.status_code == 200
    assert me_res.json()["allowed_group_ids"] == [grp_a_id]

    grps_res = client.get("/api/asset-groups", headers=scoped_headers)
    assert grps_res.status_code == 200
    grps_data = grps_res.json()
    returned_ids = [g["id"] for g in grps_data]
    assert grp_a_id in returned_ids
    assert grp_b_id not in returned_ids

    # 6. Try to import scan for Group A -> 403 (since can_import is False)
    csv_content = """Plugin,Plugin Name,Family,Severity,IP Address,Protocol,Port,Exploit?,Synopsis,Description,Solution,See Also,CVE,CVSS v3.0 Base Score
200001,Test Vuln A,General,Critical,192.168.10.1,tcp,443,No,Synopsis,Desc,Solution,,CVE-2026-1001,9.8
"""
    upload_fail_a = client.post(
        "/api/scans/upload",
        files={"file": ("test_a.csv", csv_content, "text/csv")},
        data={"asset_group_id": grp_a_id, "scan_name": "Scan Alpha"},
        headers=scoped_headers
    )
    assert upload_fail_a.status_code == 403

    # 7. Try to import scan for Group B -> 403 (no access to Group B)
    upload_fail_b = client.post(
        "/api/scans/upload",
        files={"file": ("test_b.csv", csv_content, "text/csv")},
        data={"asset_group_id": grp_b_id, "scan_name": "Scan Beta"},
        headers=scoped_headers
    )
    assert upload_fail_b.status_code == 403

    # 8. Admin uploads scans for Group A and Group B
    upload_admin_a = client.post(
        "/api/scans/upload",
        files={"file": ("test_a.csv", csv_content, "text/csv")},
        data={"asset_group_id": grp_a_id, "scan_name": "Admin Scan Alpha"},
        headers=admin_headers
    )
    assert upload_admin_a.status_code == 201
    scan_a_id = upload_admin_a.json()["id"]

    csv_content_b = """Plugin,Plugin Name,Family,Severity,IP Address,Protocol,Port,Exploit?,Synopsis,Description,Solution,See Also,CVE,CVSS v3.0 Base Score
200002,Test Vuln B,General,High,192.168.20.1,tcp,80,No,Synopsis B,Desc B,Solution B,,CVE-2026-2002,8.1
"""
    upload_admin_b = client.post(
        "/api/scans/upload",
        files={"file": ("test_b.csv", csv_content_b, "text/csv")},
        data={"asset_group_id": grp_b_id, "scan_name": "Admin Scan Beta"},
        headers=admin_headers
    )
    assert upload_admin_b.status_code == 201
    scan_b_id = upload_admin_b.json()["id"]

    # 9. Scoped analyst vulnerability view & treatment
    vulns_scoped = client.get("/api/vulnerabilities", headers=scoped_headers).json()
    vuln_plugin_ids = [v["plugin_id"] for v in vulns_scoped]
    assert "200001" in vuln_plugin_ids
    assert "200002" not in vuln_plugin_ids # Group B vuln not visible

    vuln_a = next(v for v in vulns_scoped if v["plugin_id"] == "200001")
    # Treatment for vuln in Group A -> 200 OK (can_treat is True)
    treat_res_a = client.patch(
        f"/api/vulnerabilities/{vuln_a['id']}/treatment",
        json={"treatment_status": "In_Remediation", "treatment_notes": "Tratando grupo A"},
        headers=scoped_headers
    )
    assert treat_res_a.status_code == 200
    assert treat_res_a.json()["treatment_status"] == "In_Remediation"

    # Fetch vuln_b as admin
    vulns_admin = client.get(f"/api/vulnerabilities?scan_id={scan_b_id}", headers=admin_headers).json()
    vuln_b = vulns_admin[0]
    # Scoped analyst attempts treatment on vuln in Group B -> 403 Forbidden (sem acesso ao grupo B)
    treat_res_b = client.patch(
        f"/api/vulnerabilities/{vuln_b['id']}/treatment",
        json={"treatment_status": "In_Remediation", "treatment_notes": "Tentativa de acesso indevido ao grupo B"},
        headers=scoped_headers
    )
    assert treat_res_b.status_code == 403

    # 10. Reports authoring
    # Authoring report for Group A -> 200 OK (can_author is True)
    rep_a = client.get(f"/api/reports/summary-data?asset_group_id={grp_a_id}", headers=scoped_headers)
    assert rep_a.status_code == 200
    assert rep_a.json()["metadata"]["title"] == "Relatório Sumário de Gestão de Vulnerabilidades"

    # Authoring report for Group B -> 403 Forbidden
    rep_b = client.get(f"/api/reports/summary-data?asset_group_id={grp_b_id}", headers=scoped_headers)
    assert rep_b.status_code == 403

    # 11. Scan deletion restriction: only Admin can delete
    del_scoped = client.delete(f"/api/scans/{scan_a_id}", headers=scoped_headers)
    assert del_scoped.status_code == 403
    assert "Acesso restrito apenas a Administradores" in del_scoped.json()["detail"]

    del_admin = client.delete(f"/api/scans/{scan_a_id}", headers=admin_headers)
    assert del_admin.status_code == 200
    assert del_admin.json()["message"] == "Scan e vulnerabilidades removidos com sucesso."


def test_multilevel_asset_group_hierarchy_and_rbac():
    # 1. Login as Admin
    login_res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    token = login_res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {token}"}

    # 2. Create 3 levels of hierarchy:
    # Level 1: Holdings Global
    res_l1 = client.post("/api/asset-groups", json={"name": "Holdings Global", "description": "Nivel 1 Corporativo"}, headers=admin_headers)
    assert res_l1.status_code == 201
    l1_id = res_l1.json()["id"]
    assert res_l1.json()["level"] == 1
    assert res_l1.json()["hierarchy_path"] == "Holdings Global"

    # Level 2: TI América Latina (parent: Holdings Global)
    res_l2 = client.post("/api/asset-groups", json={"name": "TI América Latina", "parent_id": l1_id, "description": "Nivel 2 Subgrupo"}, headers=admin_headers)
    assert res_l2.status_code == 201
    l2_id = res_l2.json()["id"]
    assert res_l2.json()["level"] == 2
    assert res_l2.json()["parent_name"] == "Holdings Global"
    assert res_l2.json()["hierarchy_path"] == "Holdings Global > TI América Latina"

    # Level 3: Datacenter SP (parent: TI América Latina)
    res_l3 = client.post("/api/asset-groups", json={"name": "Datacenter SP", "parent_id": l2_id, "description": "Nivel 3 Sub-subgrupo"}, headers=admin_headers)
    assert res_l3.status_code == 201
    l3_id = res_l3.json()["id"]
    assert res_l3.json()["level"] == 3
    assert res_l3.json()["parent_name"] == "TI América Latina"
    assert res_l3.json()["hierarchy_path"] == "Holdings Global > TI América Latina > Datacenter SP"

    # 3. Test circular reference rejection across 3 levels:
    # Attempt to make Holdings Global (L1) a child of Datacenter SP (L3)
    bad_cycle = client.put(f"/api/asset-groups/{l1_id}", json={"parent_id": l3_id}, headers=admin_headers)
    assert bad_cycle.status_code == 400
    assert "Referência circular" in bad_cycle.json()["detail"]

    # 4. Upload scan to Level 3 (Datacenter SP)
    csv_l3 = """Plugin,Plugin Name,Family,Severity,IP Address,Protocol,Port,Exploit?,CVE,Risk,Host Name
3001,Vuln Nivel 3,General,Critical,10.30.0.1,TCP,443,Yes,CVE-2026-3001,Critical,srv-l3.corp
"""
    upload_l3 = client.post(
        "/api/scans/upload",
        files={"file": ("scan_l3.csv", csv_l3.encode("utf-8"), "text/csv")},
        data={"asset_group_id": str(l3_id), "scan_name": "Scan Nivel 3"},
        headers=admin_headers
    )
    assert upload_l3.status_code == 201

    # 5. Check consolidated queries:
    # Querying Level 1 includes scans and vulns from Level 3!
    vulns_l1 = client.get(f"/api/vulnerabilities?asset_group_id={l1_id}", headers=admin_headers)
    assert vulns_l1.status_code == 200
    assert any(v["plugin_id"] == "3001" for v in vulns_l1.json())

    # Querying Level 2 includes scans and vulns from Level 3!
    vulns_l2 = client.get(f"/api/vulnerabilities?asset_group_id={l2_id}", headers=admin_headers)
    assert vulns_l2.status_code == 200
    assert any(v["plugin_id"] == "3001" for v in vulns_l2.json())

    # 6. Test RBAC inheritance across 3 levels:
    # User Level 2 Analyst (assigned to Level 2 TI América Latina)
    user_l2_res = client.post("/api/users", json={
        "username": "analista_l2",
        "email": "analista_l2@test.corp",
        "password": "Password123!",
        "role": "analyst",
        "allowed_groups": [{"asset_group_id": l2_id}]
    }, headers=admin_headers)
    assert user_l2_res.status_code == 201

    # Login as User Level 2 Analyst
    login_l2 = client.post("/api/auth/login", json={"username": "analista_l2", "password": "Password123!"})
    token_l2 = login_l2.json()["access_token"]
    headers_l2 = {"Authorization": f"Bearer {token_l2}"}

    # User L2 has access to Level 2 (200 OK)
    check_l2 = client.get(f"/api/asset-groups/{l2_id}", headers=headers_l2)
    assert check_l2.status_code == 200

    # User L2 inherits access to Level 3 (200 OK)
    check_l3 = client.get(f"/api/asset-groups/{l3_id}", headers=headers_l2)
    assert check_l3.status_code == 200

    # User L2 CANNOT access parent Level 1 (403 Forbidden)
    check_l1 = client.get(f"/api/asset-groups/{l1_id}", headers=headers_l2)
    assert check_l1.status_code == 403

    # User Level 3 Analyst (assigned ONLY to Level 3 Datacenter SP)
    user_l3_res = client.post("/api/users", json={
        "username": "analista_l3",
        "email": "analista_l3@test.corp",
        "password": "Password123!",
        "role": "analyst",
        "allowed_groups": [{"asset_group_id": l3_id}]
    }, headers=admin_headers)
    assert user_l3_res.status_code == 201

    login_l3 = client.post("/api/auth/login", json={"username": "analista_l3", "password": "Password123!"})
    token_l3 = login_l3.json()["access_token"]
    headers_l3 = {"Authorization": f"Bearer {token_l3}"}

    # User L3 has access to Level 3 (200 OK)
    assert client.get(f"/api/asset-groups/{l3_id}", headers=headers_l3).status_code == 200

    # User L3 CANNOT access Level 2 or Level 1 (403 Forbidden)
    assert client.get(f"/api/asset-groups/{l2_id}", headers=headers_l3).status_code == 403
    assert client.get(f"/api/asset-groups/{l1_id}", headers=headers_l3).status_code == 403











