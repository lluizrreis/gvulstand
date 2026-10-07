"""
GvulStand Scanner Sync Engine
Orchestrates API calls to external scanners (Tenable / Defender),
ingests normalized vulnerability data into GvulStand's database as a new Scan,
and updates telemetry and relational links for the associated Asset Group.
"""
import time
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app import models
from .tenable_client import TenableClient
from .defender_client import DefenderClient
from .openvas_client import OpenVasCollector

logger = logging.getLogger("sync_engine")


def _parse_host_and_port(endpoint: Optional[str], default_port: int = 9390) -> Tuple[str, int]:
    """Helper to cleanly extract host and port from endpoint strings or URLs."""
    if not endpoint:
        return "127.0.0.1", default_port
    raw = endpoint.strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.rstrip("/")
    port = default_port
    if ":" in raw and not raw.endswith("]"):
        parts = raw.split(":")
        raw = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass
    return raw or "127.0.0.1", port


def get_scanner_client(integration: models.ScannerIntegration):
    from app.crypto_utils import safe_decrypt_secret
    stype = (integration.scanner_type or "").lower()
    access_key = safe_decrypt_secret(integration.access_key)
    secret_key = safe_decrypt_secret(integration.secret_key)
    client_secret = safe_decrypt_secret(integration.client_secret)

    if "defender" in stype:
        return DefenderClient(
            tenant_id=integration.tenant_id,
            client_id=integration.client_id,
            client_secret=client_secret,
            api_endpoint=integration.api_endpoint,
            verify_ssl=integration.verify_ssl
        )
    elif "openvas" in stype or "greenbone" in stype:
        host, port = _parse_host_and_port(integration.api_endpoint, default_port=9390)
        username = access_key or integration.client_id or ""
        password = secret_key or client_secret or ""
        return OpenVasCollector(
            host=host,
            port=port,
            username=username,
            password=password,
            verify_ssl=integration.verify_ssl
        )
    else:
        return TenableClient(
            scanner_type=stype,
            api_endpoint=integration.api_endpoint,
            access_key=access_key,
            secret_key=secret_key,
            verify_ssl=integration.verify_ssl
        )


def test_scanner_connection(
    scanner_type: str,
    api_endpoint: Optional[str] = None,
    verify_ssl: bool = True,
    auth_type: str = "api_keys",
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None
) -> Dict[str, Any]:
    """
    Tests connection to a scanner instance without saving.
    """
    from app.crypto_utils import safe_decrypt_secret
    access_key = safe_decrypt_secret(access_key)
    secret_key = safe_decrypt_secret(secret_key)
    client_secret = safe_decrypt_secret(client_secret)

    stype = (scanner_type or "").lower()
    if "defender" in stype:
        client = DefenderClient(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            api_endpoint=api_endpoint,
            verify_ssl=verify_ssl
        )
    elif "openvas" in stype or "greenbone" in stype:
        host, port = _parse_host_and_port(api_endpoint, default_port=9390)
        username = access_key or client_id or ""
        password = secret_key or client_secret or ""
        client = OpenVasCollector(
            host=host,
            port=port,
            username=username,
            password=password,
            verify_ssl=verify_ssl
        )
    else:
        client = TenableClient(
            scanner_type=stype,
            api_endpoint=api_endpoint,
            access_key=access_key,
            secret_key=secret_key,
            verify_ssl=verify_ssl
        )
    return client.test_connection()


def run_scanner_sync(db: Session, integration_id: int) -> Dict[str, Any]:
    """
    Executes a complete vulnerability sync for a configured ScannerIntegration.
    Persists data into scans, hosts, and vulnerabilities tables.
    """
    start_time = time.time()
    now = datetime.now(timezone.utc)

    integration = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integration_id).first()
    if not integration:
        return {
            "success": False,
            "status": "failed",
            "message": f"Configuração de integração #{integration_id} não encontrada.",
            "duration_seconds": 0.0
        }

    # Prevenção de conflito de concorrência: verificar se a integração já está em execução
    if integration.last_sync_status == "running":
        elapsed = 0
        if integration.last_sync_at:
            last_dt = integration.last_sync_at if integration.last_sync_at.tzinfo else integration.last_sync_at.replace(tzinfo=timezone.utc)
            elapsed = (now - last_dt).total_seconds()
        # Se estiver em execução há menos de 15 minutos, bloquear nova execução simultânea
        if elapsed < 900 and integration.last_sync_at is not None:
            return {
                "success": False,
                "status": "conflict",
                "message": f"A integração '{integration.name}' já está em execução no momento. Aguarde o término da sincronização atual para evitar concorrência.",
                "duration_seconds": 0.0
            }

    logger.info(f"Starting API synchronization for integration #{integration.id} ({integration.name})...")
    integration.last_sync_status = "running"
    integration.last_sync_at = now
    integration.last_sync_message = "Sincronização em andamento com a API externa..."
    db.commit()

    try:
        client = get_scanner_client(integration)
        parsed_data = client.fetch_vulnerabilities(target_scope_filter=integration.target_scope_filter)

        hosts_data = parsed_data.get("hosts") or {}
        findings_data = parsed_data.get("findings") or []
        stats = parsed_data.get("stats") or {}

        scanner_labels = {
            "tenable_io": "Tenable.io",
            "tenable_sc": "Tenable.sc",
            "tenable_nessus_pro": "Nessus Pro",
            "ms_defender": "MS Defender",
            "openvas": "OpenVAS / Greenbone GVM",
            "greenbone_gvm": "Greenbone GVM"
        }
        scanner_label = scanner_labels.get(integration.scanner_type, "API Scanner")
        scan_name = f"[API {scanner_label}] {integration.name} - {now.strftime('%d/%m/%Y %H:%M')}"
        safe_filename = f"api_sync_{integration.scanner_type}_{integration.id}_{int(now.timestamp())}.json"

        # 1. Create Scan Record
        scan = models.Scan(
            asset_group_id=integration.asset_group_id,
            scan_name=scan_name,
            scan_type="baseline",
            filename=safe_filename,
            file_size_bytes=len(str(parsed_data).encode("utf-8")),
            total_hosts=len(hosts_data),
            total_findings=len(findings_data),
            critical_count=stats.get("critical_count", 0),
            high_count=stats.get("high_count", 0),
            medium_count=stats.get("medium_count", 0),
            low_count=stats.get("low_count", 0),
            info_count=stats.get("info_count", 0),
            exploitable_critical_count=stats.get("exploitable_critical_count", 0),
            scan_date=now,
            notes=f"Sincronização automatizada via API ({integration.scanner_type}) em {now.strftime('%d/%m/%Y %H:%M:%S UTC')}."
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # 2. Create Host Records
        ip_to_host_id: Dict[str, int] = {}
        for ip, h_info in hosts_data.items():
            host = models.Host(
                scan_id=scan.id,
                asset_group_id=integration.asset_group_id,
                ip_address=h_info["ip_address"],
                hostname=h_info.get("hostname"),
                mac_address=h_info.get("mac_address"),
                os=h_info.get("os"),
                critical_count=h_info.get("critical_count", 0),
                high_count=h_info.get("high_count", 0),
                medium_count=h_info.get("medium_count", 0),
                low_count=h_info.get("low_count", 0),
                info_count=h_info.get("info_count", 0),
                exploitable_critical_count=h_info.get("exploitable_critical_count", 0),
                risk_score=h_info.get("risk_score", 0.0)
            )
            db.add(host)
            db.flush()
            ip_to_host_id[ip] = host.id

        # 3. Create Vulnerability Records
        for f in findings_data:
            host_ip = f.get("host_ip")
            host_id = ip_to_host_id.get(host_ip)
            if not host_id:
                # If host not found in map, fallback to first created host
                host_id = list(ip_to_host_id.values())[0] if ip_to_host_id else None

            if not host_id:
                continue

            vuln = models.Vulnerability(
                scan_id=scan.id,
                host_id=host_id,
                asset_group_id=integration.asset_group_id,
                plugin_id=str(f.get("plugin_id") or "100000"),
                plugin_name=f.get("plugin_name") or f"Finding {f.get('plugin_id')}",
                cve=f.get("cve"),
                cvss_v3=f.get("cvss_v3"),
                cvss_v2=f.get("cvss_v2"),
                severity=f.get("severity") or "Medium",
                port=f.get("port") or 0,
                protocol=f.get("protocol") or "tcp",
                synopsis=f.get("synopsis"),
                description=f.get("description"),
                solution=f.get("solution"),
                see_also=f.get("see_also"),
                plugin_output=f.get("plugin_output"),
                exploit_available=f.get("exploit_available", False),
                exploit_frameworks=f.get("exploit_frameworks"),
                exploited_by_malware=f.get("exploited_by_malware", False),
                patch_available=f.get("patch_available", False),
                vpr=f.get("vpr"),
                treatment_status="Open",
                first_found=now,
                last_found=now
            )
            db.add(vuln)

        # 4. Update Integration Telemetry
        duration = round(time.time() - start_time, 2)
        integration.last_sync_status = "success"
        integration.last_sync_at = now
        integration.last_synced_scan_id = scan.id
        integration.vulnerabilities_imported_count = len(findings_data)
        integration.hosts_imported_count = len(hosts_data)
        integration.last_sync_message = (
            f"Sincronização concluída com sucesso em {duration}s: "
            f"{len(hosts_data)} hosts e {len(findings_data)} vulnerabilidades importadas."
        )
        db.commit()
        db.refresh(scan)

        # 5. Post-Import Hook: Sincronização automática com Planos de Ação Ativos (ISO 27001 / ISO 9001 PDCA)
        try:
            from app.api.routes_action_plans import sync_action_plans_on_scan_import
            sync_action_plans_on_scan_import(
                db=db,
                scan=scan,
                current_username=f"API Sync ({integration.name})"
            )
        except Exception as hook_err:
            logger.warning(f"Aviso no post-import hook de sincronização de planos (integração #{integration.id}): {hook_err}", exc_info=True)

        logger.info(f"Sync successful for integration #{integration.id}: scan_id={scan.id}")
        return {
            "success": True,
            "status": "success",
            "message": integration.last_sync_message,
            "scan_id": scan.id,
            "hosts_count": len(hosts_data),
            "vulnerabilities_count": len(findings_data),
            "duration_seconds": duration
        }

    except Exception as e:
        duration = round(time.time() - start_time, 2)
        logger.error(f"Error during API sync for integration #{integration.id}: {e}", exc_info=True)
        integration.last_sync_status = "failed"
        integration.last_sync_message = f"Falha na sincronização ({duration}s): {str(e)}"
        db.commit()
        return {
            "success": False,
            "status": "failed",
            "message": integration.last_sync_message,
            "duration_seconds": duration
        }
