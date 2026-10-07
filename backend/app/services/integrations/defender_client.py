"""
Microsoft Defender for Endpoint / MDVM (Microsoft Defender Vulnerability Management) Client
Supports OAuth2 Client Credentials via Microsoft Entra ID (Azure AD).
"""
import logging
from typing import Dict, Any, List, Optional, Tuple
import httpx
from datetime import datetime, timezone

logger = logging.getLogger("defender_client")

class DefenderClient:
    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_endpoint: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: float = 30.0
    ):
        self.tenant_id = (tenant_id or "").strip()
        self.client_id = (client_id or "").strip()
        self.client_secret = (client_secret or "").strip()
        self.api_endpoint = (api_endpoint or "https://api.securitycenter.microsoft.com").rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _is_mock(self) -> bool:
        return (
            self.tenant_id.startswith("mock_")
            or "mock" in self.api_endpoint.lower()
            or (self.client_id == "test_client_id" and self.tenant_id == "test_tenant_id")
            or (self.client_id == "mock_client" or self.client_secret == "mock_secret")
        )

    def acquire_token(self) -> Tuple[bool, str]:
        """
        Acquires an OAuth2 bearer token from Microsoft Entra ID.
        Returns (success: bool, token_or_err: str)
        """
        if self._is_mock():
            return True, "mock_bearer_token_entra_id_2026"

        if not self.tenant_id or not self.client_id or not self.client_secret:
            return False, "Tenant ID, Client ID e Client Secret são obrigatórios para autenticação Entra ID."

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": f"{self.api_endpoint}/.default"
        }

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                res = client.post(token_url, data=payload)
                if res.status_code == 200:
                    data = res.json()
                    return True, data.get("access_token", "")
                else:
                    err_desc = ""
                    try:
                        err_desc = res.json().get("error_description", "")
                    except Exception:
                        err_desc = res.text[:200]
                    return False, f"Falha na obtenção do token OAuth2 (HTTP {res.status_code}): {err_desc}"
        except Exception as e:
            return False, f"Erro ao comunicar com Microsoft Entra ID ({token_url}): {str(e)}"

    def test_connection(self) -> Dict[str, Any]:
        """
        Tests connection to Microsoft Defender API by obtaining a token and requesting a sample machine.
        """
        if self._is_mock():
            return {
                "success": True,
                "status_code": 200,
                "message": "Conexão com Microsoft Defender for Endpoint / MDVM autenticada com sucesso! (Modo Simulação)",
                "details": {
                    "tenant_id": self.tenant_id,
                    "endpoint": self.api_endpoint,
                    "status": "ready"
                }
            }

        ok, token_or_err = self.acquire_token()
        if not ok:
            return {
                "success": False,
                "status_code": 401,
                "message": f"Erro de autenticação no Microsoft Defender: {token_or_err}",
                "details": {"error": token_or_err}
            }

        headers = {
            "Authorization": f"Bearer {token_or_err}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        url = f"{self.api_endpoint}/api/machines?$top=1"

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                res = client.get(url, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    return {
                        "success": True,
                        "status_code": 200,
                        "message": "Conexão com Microsoft Defender for Endpoint / MDVM autenticada com sucesso.",
                        "details": {
                            "tenant_id": self.tenant_id,
                            "endpoint": self.api_endpoint,
                            "response": data
                        }
                    }
                elif res.status_code in [401, 403]:
                    return {
                        "success": False,
                        "status_code": res.status_code,
                        "message": "A aplicação possui token válido mas não tem a permissão de API necessária no Microsoft Defender (ex: 'Machine.Read.All', 'Vulnerability.Read.All').",
                        "details": {"status_code": res.status_code}
                    }
                else:
                    return {
                        "success": False,
                        "status_code": res.status_code,
                        "message": f"Resposta inesperada do Defender (HTTP {res.status_code}): {res.text[:200]}",
                        "details": {"status_code": res.status_code}
                    }
        except Exception as e:
            err_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in err_str or "certificate verify failed" in err_str.lower():
                return {
                    "success": False,
                    "status_code": 495,
                    "message": (
                        f"Falha de Validação SSL ({self.api_endpoint}): O certificado HTTPS do endpoint "
                        "é autoassinado ou não confiável. Desmarque 'Verificar certificado SSL válido' caso esteja usando proxy corporativo/inspeção SSL."
                    ),
                    "details": {"error": err_str}
                }
            return {
                "success": False,
                "status_code": 500,
                "message": f"Erro ao acessar API do Microsoft Defender: {err_str}",
                "details": {"error": err_str}
            }

    def fetch_vulnerabilities(self, target_scope_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetches vulnerability findings from Microsoft Defender and normalizes them into GvulStand standard format.
        """
        if self._is_mock():
            return self._generate_simulated_payload(target_scope_filter)

        ok, token_or_err = self.acquire_token()
        if not ok:
            raise RuntimeError(f"Falha na autenticação do Microsoft Defender: {token_or_err}")

        headers = {
            "Authorization": f"Bearer {token_or_err}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                # 1. Fetch machines list
                machines_res = client.get(f"{self.api_endpoint}/api/machines?$top=100", headers=headers)
                if machines_res.status_code in [401, 403]:
                    raise RuntimeError("Permissão insuficiente no Microsoft Defender: Requer 'Machine.Read.All'.")
                if machines_res.status_code != 200:
                    raise RuntimeError(f"Falha ao consultar máquinas no Microsoft Defender (HTTP {machines_res.status_code}): {machines_res.text[:200]}")

                machines_data = machines_res.json().get("value", [])

                # Filtrar máquinas pelo Device Group, Tag, Hostname ou IP se target_scope_filter informado
                if target_scope_filter and target_scope_filter.strip():
                    term = target_scope_filter.strip().lower()
                    filtered = []
                    for m in machines_data:
                        rbac = (m.get("rbacGroupName") or "").lower()
                        tags = [str(t).lower() for t in (m.get("machineTags") or [])]
                        comp_name = (m.get("computerDnsName") or "").lower()
                        ip_addrs = [str(ip).lower() for ip in (m.get("ipAddresses") or [])]
                        if (
                            term in rbac
                            or any(term in t for t in tags)
                            or term in comp_name
                            or any(term in ip for ip in ip_addrs)
                        ):
                            filtered.append(m)
                    if not filtered:
                        available_groups = set(filter(None, [m.get("rbacGroupName") for m in machines_data]))
                        available_str = f"Grupos disponíveis: {', '.join(available_groups)}" if available_groups else "Nenhum grupo RBAC configurado."
                        raise RuntimeError(
                            f"Nenhuma máquina encontrada no Microsoft Defender correspondente ao filtro '{target_scope_filter}'. "
                            f"{available_str}"
                        )
                    machines_data = filtered

                # 2. Fetch vulnerabilities
                vulns_res = client.get(f"{self.api_endpoint}/api/Vulnerabilities/machinesVulnerabilities?$top=200", headers=headers)
                if vulns_res.status_code in [401, 403]:
                    raise RuntimeError("Permissão insuficiente no Microsoft Defender: Requer 'Vulnerability.Read.All'.")
                if vulns_res.status_code != 200:
                    raise RuntimeError(f"Falha ao consultar vulnerabilidades no Microsoft Defender (HTTP {vulns_res.status_code}): {vulns_res.text[:200]}")

                vulns_data = vulns_res.json().get("value", [])
                return self._normalize_defender_data(machines_data, vulns_data)

        except Exception as e:
            err_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in err_str or "certificate verify failed" in err_str.lower():
                raise RuntimeError(
                    f"Falha de Certificado SSL: O endpoint ({self.api_endpoint}) possui certificado autoassinado. "
                    "Desmarque a opção 'Verificar certificado SSL válido' na configuração."
                ) from e
            if isinstance(e, RuntimeError):
                raise
            raise RuntimeError(f"Erro durante sincronização com Microsoft Defender: {err_str}") from e

    def _normalize_defender_data(self, machines: List[Dict[str, Any]], vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Normalizes Defender JSON data to GvulStand format.
        """
        hosts_dict: Dict[str, Any] = {}
        findings_list: List[Dict[str, Any]] = []
        stats = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "exploitable_critical_count": 0
        }

        machine_map = {}
        for m in machines:
            mid = m.get("id")
            ip = (m.get("ipAddresses") or ["10.0.0.1"])[0] if m.get("ipAddresses") else (m.get("lastIpAddress") or "10.0.0.1")
            hostname = m.get("computerDnsName") or f"mde-{mid[:8]}"
            os_name = f"{m.get('osPlatform', 'Windows')} {m.get('osVersion', '')}".strip()
            
            machine_map[mid] = ip
            hosts_dict[ip] = {
                "ip_address": ip,
                "hostname": hostname,
                "mac_address": "",
                "os": os_name,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "exploitable_critical_count": 0,
                "risk_score": 0.0
            }

        for v in vulns:
            cve_id = v.get("cveId") or v.get("id") or "CVE-UNKNOWN"
            mid = v.get("machineId")
            if mid:
                if mid not in machine_map:
                    continue
                host_ip = machine_map[mid]
            else:
                host_ip = list(hosts_dict.keys())[0] if hosts_dict else "10.0.0.1"
            
            raw_sev = str(v.get("severity") or "Medium").capitalize()
            if raw_sev not in ["Critical", "High", "Medium", "Low", "Info"]:
                raw_sev = "Medium"

            cvss = float(v.get("cvssV3") or v.get("cvssV2") or 5.0)
            exploit_status = v.get("exploitabilityLevel") or ""
            exploit_bool = "exploit" in exploit_status.lower() or bool(v.get("publicExploit", False))

            finding = {
                "host_ip": host_ip,
                "plugin_id": f"MDE-{cve_id}",
                "plugin_name": v.get("vulnerabilityName") or f"Microsoft Defender: {cve_id}",
                "severity": raw_sev,
                "cve": cve_id,
                "cvss_v3": cvss,
                "cvss_v2": None,
                "port": 0,
                "protocol": "tcp",
                "synopsis": f"Vulnerabilidade identificada pelo Microsoft Defender Vulnerability Management: {cve_id}",
                "description": v.get("description") or f"O agente do Microsoft Defender detectou que o host está vulnerável a {cve_id}.",
                "solution": "Aplicar atualizações de segurança recomendadas pela Microsoft (Windows Update / MSRC).",
                "see_also": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                "plugin_output": f"Componente afetado: {v.get('affectedComponent', 'Windows System')}",
                "exploit_available": exploit_bool,
                "exploit_frameworks": "Public Exploit" if exploit_bool else "",
                "exploited_by_malware": False,
                "patch_available": True,
                "vpr": cvss
            }
            findings_list.append(finding)

            if host_ip in hosts_dict:
                if raw_sev == "Critical":
                    hosts_dict[host_ip]["critical_count"] += 1
                    stats["critical_count"] += 1
                    if exploit_bool:
                        hosts_dict[host_ip]["exploitable_critical_count"] += 1
                        stats["exploitable_critical_count"] += 1
                elif raw_sev == "High":
                    hosts_dict[host_ip]["high_count"] += 1
                    stats["high_count"] += 1
                elif raw_sev == "Medium":
                    hosts_dict[host_ip]["medium_count"] += 1
                    stats["medium_count"] += 1
                elif raw_sev == "Low":
                    hosts_dict[host_ip]["low_count"] += 1
                    stats["low_count"] += 1
                else:
                    hosts_dict[host_ip]["info_count"] += 1
                    stats["info_count"] += 1

        for h in hosts_dict.values():
            h["risk_score"] = round(
                (h["critical_count"] * 10.0) +
                (h["high_count"] * 5.0) +
                (h["medium_count"] * 2.0) +
                (h["low_count"] * 0.5) +
                (h["exploitable_critical_count"] * 5.0),
                1
            )

        return {
            "hosts": hosts_dict,
            "findings": findings_list,
            "stats": stats
        }

    def _generate_simulated_payload(self, target_scope_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Generates realistic standardized Defender / MDVM findings for testing.
        """
        ts = int(datetime.now(timezone.utc).timestamp())
        hosts_dict = {
            f"10.150.2.{ts % 200 + 10}": {
                "ip_address": f"10.150.2.{ts % 200 + 10}",
                "hostname": f"WKS-FIN-01-{ts % 200 + 10}.contoso.local",
                "mac_address": "00:15:5D:12:34:56",
                "os": "Windows 11 Enterprise 23H2 (Build 22631)",
                "critical_count": 2,
                "high_count": 2,
                "medium_count": 4,
                "low_count": 1,
                "info_count": 3,
                "exploitable_critical_count": 1,
                "risk_score": 43.5
            },
            f"10.150.2.{ts % 200 + 11}": {
                "ip_address": f"10.150.2.{ts % 200 + 11}",
                "hostname": f"SRV-APP-PROD-{ts % 200 + 11}.contoso.local",
                "mac_address": "00:15:5D:65:43:21",
                "os": "Windows Server 2022 Datacenter",
                "critical_count": 1,
                "high_count": 3,
                "medium_count": 3,
                "low_count": 2,
                "info_count": 4,
                "exploitable_critical_count": 1,
                "risk_score": 37.0
            }
        }

        h_ips = list(hosts_dict.keys())
        findings_list = [
            {
                "host_ip": h_ips[0],
                "plugin_id": "MDE-CVE-2024-38063",
                "plugin_name": "Windows TCP/IP Remote Code Execution Vulnerability (IPv6)",
                "severity": "Critical",
                "cve": "CVE-2024-38063",
                "cvss_v3": 9.8,
                "cvss_v2": None,
                "port": 0,
                "protocol": "tcp",
                "synopsis": "O Microsoft Defender for Endpoint identificou vulnerabilidade de execução remota de código no TCP/IP do Windows.",
                "description": "Um atacante remoto não autenticado pode enviar pacotes IPv6 especialmente criados para executar código com privilégios de SYSTEM.",
                "solution": "Aplicar a atualização de segurança de Agosto de 2024 da Microsoft ou desabilitar temporariamente o IPv6.",
                "see_also": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063",
                "plugin_output": "Pilha de rede IPv6 ativa com KB5041585 ausente.",
                "exploit_available": True,
                "exploit_frameworks": "Metasploit",
                "exploited_by_malware": False,
                "patch_available": True,
                "vpr": 9.8
            },
            {
                "host_ip": h_ips[0],
                "plugin_id": "MDE-CVE-2024-38106",
                "plugin_name": "Windows Kernel Elevation of Privilege Vulnerability",
                "severity": "Critical",
                "cve": "CVE-2024-38106",
                "cvss_v3": 8.8,
                "cvss_v2": None,
                "port": 0,
                "protocol": "tcp",
                "synopsis": "Falha de escalonamento de privilégios para SYSTEM no Kernel do Windows.",
                "description": "Uma condição de corrida no kernel do Windows permite que um atacante local execute código com privilégios de SYSTEM.",
                "solution": "Instale as atualizações cumulativas de Agosto de 2024 da Microsoft.",
                "see_also": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38106",
                "plugin_output": "Exploração ativa observada pela telemetria do Defender.",
                "exploit_available": True,
                "exploit_frameworks": "Wild Exploitation",
                "exploited_by_malware": True,
                "patch_available": True,
                "vpr": 9.5
            },
            {
                "host_ip": h_ips[1],
                "plugin_id": "MDE-CVE-2024-30078",
                "plugin_name": "Windows Wi-Fi Driver Remote Code Execution Vulnerability",
                "severity": "Critical",
                "cve": "CVE-2024-30078",
                "cvss_v3": 8.8,
                "cvss_v2": None,
                "port": 0,
                "protocol": "tcp",
                "synopsis": "Execução remota de código no driver de rede sem fio da Microsoft.",
                "description": "Um atacante dentro do alcance do sinal Wi-Fi pode enviar pacotes maliciosos para comprometer o host sem interação do usuário.",
                "solution": "Aplicar a atualização de segurança de Junho de 2024 da Microsoft.",
                "see_also": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30078",
                "plugin_output": "Driver de rede sem fio nwifi.sys sem patch KB5039211.",
                "exploit_available": True,
                "exploit_frameworks": "Proof of Concept",
                "exploited_by_malware": False,
                "patch_available": True,
                "vpr": 8.9
            }
        ]

        stats = {
            "critical_count": 3,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "exploitable_critical_count": 3
        }

        return {
            "hosts": hosts_dict,
            "findings": findings_list,
            "stats": stats
        }
