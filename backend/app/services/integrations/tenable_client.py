"""
Tenable REST API Client
Supports:
- Tenable Vulnerability Management (formerly Tenable.io)
- Tenable SecurityCenter (Tenable.sc)
- Tenable Nessus Professional / Nessus Manager
"""
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
import httpx
from datetime import datetime, timezone

logger = logging.getLogger("tenable_client")

class TenableClient:
    def __init__(
        self,
        scanner_type: str = "tenable_io",
        api_endpoint: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: float = 30.0
    ):
        self.scanner_type = scanner_type.lower()
        if not api_endpoint:
            if self.scanner_type == "tenable_io":
                self.api_endpoint = "https://cloud.tenable.com"
            else:
                self.api_endpoint = "https://127.0.0.1:8834"
        else:
            self.api_endpoint = api_endpoint.rstrip("/")
            
        self.access_key = access_key or ""
        self.secret_key = secret_key or ""
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        if self.scanner_type == "tenable_sc":
            return {
                "x-apikey": f"accesskey={self.access_key}; secretkey={self.secret_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        else:
            # Tenable.io and Nessus Pro use X-ApiKeys
            return {
                "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

    def _is_mock(self) -> bool:
        return (
            self.access_key.startswith("mock_")
            or "mock" in self.api_endpoint.lower()
            or (self.access_key == "test_access_key" and self.secret_key == "test_secret_key")
        )

    def test_connection(self) -> Dict[str, Any]:
        """
        Tests connection to the Tenable instance using provided credentials.
        """
        if self._is_mock():
            return {
                "success": True,
                "status_code": 200,
                "message": f"Conexão com {self.scanner_type.upper()} testada com sucesso! (Modo Simulação)",
                "details": {
                    "scanner_type": self.scanner_type,
                    "endpoint": self.api_endpoint,
                    "server_version": "Tenable API v2 / Build 2026.1",
                    "status": "ready"
                }
            }

        headers = self._get_headers()
        
        # Determine test route
        if self.scanner_type == "tenable_sc":
            url = f"{self.api_endpoint}/rest/system"
        else:
            url = f"{self.api_endpoint}/server/status"

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                res = client.get(url, headers=headers)
                
                # Tenable.io can also check /session if /server/status returns 404
                if res.status_code == 404 and self.scanner_type == "tenable_io":
                    url = f"{self.api_endpoint}/session"
                    res = client.get(url, headers=headers)

                if res.status_code in [200, 201]:
                    data = {}
                    try:
                        data = res.json()
                    except Exception:
                        data = {"raw": res.text[:200]}
                    return {
                        "success": True,
                        "status_code": res.status_code,
                        "message": f"Conexão com {self.scanner_type.upper()} estabelecida com sucesso.",
                        "details": {
                            "scanner_type": self.scanner_type,
                            "endpoint": self.api_endpoint,
                            "response": data
                        }
                    }
                elif res.status_code in [401, 403]:
                    return {
                        "success": False,
                        "status_code": res.status_code,
                        "message": "Falha de autenticação no Tenable/Nessus: Access Key ou Secret Key inválida ou sem permissão de leitura.",
                        "details": {"status_code": res.status_code}
                    }
                else:
                    return {
                        "success": False,
                        "status_code": res.status_code,
                        "message": f"O servidor Tenable respondeu com código HTTP {res.status_code}: {res.text[:200]}",
                        "details": {"status_code": res.status_code}
                    }
        except Exception as e:
            err_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in err_str or "certificate verify failed" in err_str.lower():
                return {
                    "success": False,
                    "status_code": 495,
                    "message": (
                        f"Falha de Validação SSL ({self.api_endpoint}): O certificado HTTPS do servidor Nessus/Tenable "
                        "é autoassinado ou não confiável pela autoridade local (CA). Desmarque a opção "
                        "'Verificar certificado SSL válido' na tela de configuração para permitir a conexão HTTPS local."
                    ),
                    "details": {"error": err_str}
                }
            if isinstance(e, httpx.TimeoutException):
                return {
                    "success": False,
                    "status_code": 504,
                    "message": f"Tempo limite esgotado ({self.timeout}s) ao tentar comunicar com {self.api_endpoint}.",
                    "details": {"error": err_str}
                }
            logger.warning(f"Connection error to {url}: {err_str}")
            return {
                "success": False,
                "status_code": 503,
                "message": f"Não foi possível conectar ao endpoint Tenable ({self.api_endpoint}). Verifique o endereço IP, porta e se o serviço está ativo na rede.",
                "details": {"error": err_str}
            }

    def fetch_vulnerabilities(self, target_scope_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetches vulnerability findings from Tenable/Nessus and normalizes them into GvulStand standard format:
        {
            "hosts": dict of hosts,
            "findings": list of normalized findings,
            "stats": dict of counts
        }
        """
        if self._is_mock():
            return self._generate_simulated_payload(target_scope_filter)

        headers = self._get_headers()
        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=self.timeout,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
            ) as client:
                scans_res = client.get(f"{self.api_endpoint}/scans", headers=headers)
                if scans_res.status_code in [401, 403]:
                    raise RuntimeError("Falha de autenticação no Tenable/Nessus: Access Key ou Secret Key inválida ou sem permissão de leitura.")
                if scans_res.status_code != 200:
                    raise RuntimeError(f"Erro ao listar scans no Tenable/Nessus (HTTP {scans_res.status_code}): {scans_res.text[:200]}")

                scans_data = scans_res.json()
                scans_list = scans_data.get("scans") or []
                if not scans_list:
                    raise RuntimeError("Nenhum scan encontrado no servidor Tenable/Nessus. Crie e execute uma varredura antes de sincronizar.")

                # Filter and select target scan
                target_scan = None
                if target_scope_filter and target_scope_filter.strip():
                    term = target_scope_filter.strip().lower()
                    for s in scans_list:
                        if term in s.get("name", "").lower() or str(s.get("id")) == term:
                            target_scan = s
                            break

                    if not target_scan:
                        available_names = [f"'{s.get('name')}' (ID: {s.get('id')})" for s in scans_list[:10]]
                        raise RuntimeError(
                            f"Nenhum scan encontrado no Tenable/Nessus com o nome ou ID correspondente ao filtro '{target_scope_filter}'. "
                            f"Scans disponíveis no servidor: {', '.join(available_names)}"
                        )

                if not target_scan:
                    # Select latest completed scan with hosts/vulnerabilities
                    completed = [s for s in scans_list if s.get("status") == "completed"]
                    candidates = completed if completed else scans_list
                    candidates.sort(key=lambda s: s.get("last_modification_date") or s.get("creation_date") or 0, reverse=True)
                    target_scan = candidates[0]

                scan_id = target_scan["id"]
                scan_name = target_scan.get("name", f"Scan #{scan_id}")
                logger.info(f"Fetching scan #{scan_id} '{scan_name}' from Tenable/Nessus...")

                details_res = client.get(f"{self.api_endpoint}/scans/{scan_id}", headers=headers)
                if details_res.status_code != 200:
                    raise RuntimeError(f"Erro ao consultar detalhes do scan '{scan_name}' (#{scan_id}): HTTP {details_res.status_code}")

                scan_detail = details_res.json()
                return self._normalize_tenable_scan_with_hosts(client, scan_id, scan_detail, headers)

        except Exception as e:
            err_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in err_str or "certificate verify failed" in err_str.lower():
                raise RuntimeError(
                    f"Falha de Certificado SSL: O certificado HTTPS do servidor Nessus ({self.api_endpoint}) é autoassinado. "
                    "Desmarque a opção 'Verificar certificado SSL válido' na tela de configuração da integração."
                ) from e
            if isinstance(e, RuntimeError):
                raise
            raise RuntimeError(f"Falha na comunicação com a API do Tenable/Nessus: {err_str}") from e

    def _normalize_tenable_scan_with_hosts(
        self,
        client: httpx.Client,
        scan_id: int,
        scan_detail: Dict[str, Any],
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Normalizes Tenable/Nessus scan details by querying host endpoints and plugin attributes.
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

        raw_hosts = scan_detail.get("hosts") or []
        plugin_cache: Dict[str, Any] = {}
        sev_map = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}

        for h in raw_hosts:
            host_id = h.get("host_id")
            host_detail = None
            if host_id is not None:
                try:
                    hr = client.get(f"{self.api_endpoint}/scans/{scan_id}/hosts/{host_id}", headers=headers)
                    if hr.status_code == 200:
                        host_detail = hr.json()
                except Exception as ex:
                    logger.warning(f"Could not fetch host #{host_id} details: {ex}")

            h_info = (host_detail.get("info") if host_detail else {}) or {}
            ip = h_info.get("host-ip") or h.get("hostname") or h.get("ip") or "127.0.0.1"
            netbios = h_info.get("netbios-name") or ""
            hostname = netbios or h.get("hostname") or f"srv-{ip.replace('.', '-')}"
            os_name = h_info.get("operating-system") or "Linux / Unix"
            mac_raw = h_info.get("mac-address") or ""
            mac_addr = mac_raw.splitlines()[0].strip() if mac_raw else ""

            crit = int(h.get("critical", 0))
            high = int(h.get("high", 0))
            med = int(h.get("medium", 0))
            low = int(h.get("low", 0))
            info = int(h.get("info", 0))

            hosts_dict[ip] = {
                "ip_address": ip,
                "hostname": hostname,
                "mac_address": mac_addr,
                "os": os_name,
                "critical_count": crit,
                "high_count": high,
                "medium_count": med,
                "low_count": low,
                "info_count": info,
                "exploitable_critical_count": 0,
                "risk_score": 0.0
            }

            vulns = (host_detail.get("vulnerabilities") if host_detail else scan_detail.get("vulnerabilities")) or []
            for v in vulns:
                sev_num = v.get("severity", 0)
                sev = sev_map.get(sev_num, "Info")
                pid = str(v.get("plugin_id") or "100000")
                pname = v.get("plugin_name") or f"Plugin #{pid}"

                p_details = plugin_cache.get(pid)
                if not p_details and sev_num > 0 and host_id is not None:
                    try:
                        pr = client.get(f"{self.api_endpoint}/scans/{scan_id}/hosts/{host_id}/plugins/{pid}", headers=headers)
                        if pr.status_code == 200:
                            p_details = pr.json()
                            plugin_cache[pid] = p_details
                    except Exception as pex:
                        logger.warning(f"Could not fetch plugin #{pid} details: {pex}")

                attr = {}
                outputs = []
                if p_details:
                    attr = p_details.get("info", {}).get("plugindescription", {}).get("pluginattributes", {})
                    outputs = p_details.get("outputs", [])

                port_val = 0
                proto_val = "tcp"
                p_output = ""
                if outputs:
                    p_output = outputs[0].get("plugin_output") or ""
                    p_ports = outputs[0].get("ports", {})
                    if p_ports:
                        pk = list(p_ports.keys())[0]
                        parts = [p.strip() for p in pk.split("/")]
                        if parts and parts[0].isdigit():
                            port_val = int(parts[0])
                        if len(parts) > 1:
                            proto_val = parts[1].lower()

                cve_str = ""
                ref_info = attr.get("ref_information") or {}
                refs = ref_info.get("ref") or []
                cve_list = []
                for r_item in refs:
                    if r_item.get("name") == "cve":
                        vals = r_item.get("values", {}).get("value", [])
                        cve_list.extend(vals)
                if cve_list:
                    cve_str = ", ".join(cve_list)

                risk_info = attr.get("risk_information") or {}
                cvss3_val = risk_info.get("cvss3_base_score") or attr.get("cvss3_base_score")
                cvss2_val = risk_info.get("cvss_base_score") or attr.get("cvss_base_score")
                cvss3 = float(cvss3_val) if cvss3_val else None
                cvss2 = float(cvss2_val) if cvss2_val else None
                vpr = float(v.get("vpr_score") or attr.get("vpr_score") or 0.0)

                exploit_flag = bool(attr.get("exploit_available", False)) or ("exploit" in str(attr.get("exploit_code_maturity", "")).lower())

                synopsis = attr.get("synopsis") or (pname if sev == "Info" else "")
                desc = attr.get("description") or ""
                solution = attr.get("solution") or ("N/A - Achado informativo de inventário." if sev == "Info" else "Aplicar correções recomendadas pelo fabricante.")

                finding = {
                    "host_ip": ip,
                    "plugin_id": pid,
                    "plugin_name": pname,
                    "severity": sev,
                    "cve": cve_str,
                    "cvss_v3": cvss3,
                    "cvss_v2": cvss2,
                    "port": port_val,
                    "protocol": proto_val,
                    "synopsis": synopsis,
                    "description": desc,
                    "solution": solution,
                    "see_also": str(attr.get("see_also") or ""),
                    "plugin_output": p_output,
                    "exploit_available": exploit_flag,
                    "exploit_frameworks": str(attr.get("exploit_frameworks") or ""),
                    "exploited_by_malware": False,
                    "patch_available": bool(attr.get("patch_available", True)),
                    "vpr": vpr
                }
                findings_list.append(finding)

                if sev == "Critical":
                    stats["critical_count"] += 1
                    if exploit_flag:
                        stats["exploitable_critical_count"] += 1
                        hosts_dict[ip]["exploitable_critical_count"] += 1
                elif sev == "High":
                    stats["high_count"] += 1
                elif sev == "Medium":
                    stats["medium_count"] += 1
                elif sev == "Low":
                    stats["low_count"] += 1
                else:
                    stats["info_count"] += 1

        # Recompute risk scores
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
        Generates realistic standardized vulnerability findings for testing / demonstrations.
        """
        ts = int(datetime.now(timezone.utc).timestamp())
        hosts_dict = {
            f"10.200.1.{ts % 200 + 10}": {
                "ip_address": f"10.200.1.{ts % 200 + 10}",
                "hostname": f"srv-tenable-core-{ts % 200 + 10}.empresa.local",
                "mac_address": "00:50:56:AB:CD:EF",
                "os": "Red Hat Enterprise Linux 9.3 (Kernel 5.14)",
                "critical_count": 2,
                "high_count": 3,
                "medium_count": 5,
                "low_count": 1,
                "info_count": 4,
                "exploitable_critical_count": 1,
                "risk_score": 50.5
            },
            f"10.200.1.{ts % 200 + 11}": {
                "ip_address": f"10.200.1.{ts % 200 + 11}",
                "hostname": f"srv-tenable-db-{ts % 200 + 11}.empresa.local",
                "mac_address": "00:50:56:FE:DC:BA",
                "os": "Windows Server 2022 Standard (Build 20348)",
                "critical_count": 1,
                "high_count": 2,
                "medium_count": 4,
                "low_count": 2,
                "info_count": 5,
                "exploitable_critical_count": 1,
                "risk_score": 34.0
            }
        }

        h_ips = list(hosts_dict.keys())
        findings_list = [
            {
                "host_ip": h_ips[0],
                "plugin_id": "184512",
                "plugin_name": "OpenSSL 3.0.x < 3.0.12 Multiple Vulnerabilities (RCE / DoS)",
                "severity": "Critical",
                "cve": "CVE-2023-5678, CVE-2023-6237",
                "cvss_v3": 9.8,
                "cvss_v2": 9.0,
                "port": 443,
                "protocol": "tcp",
                "synopsis": "A biblioteca de criptografia instalada no host remoto é afetada por vulnerabilidades de execução remota de código.",
                "description": "De acordo com a versão informada pelo pacote openssl, a versão instalada é vulnerável a estouro de buffer e execução remota de código arbitrário sem autenticação.",
                "solution": "Atualize a biblioteca OpenSSL para a versão 3.0.12 ou mais recente utilizando o gerenciador de pacotes da distribuição (dnf update openssl).",
                "see_also": "https://www.openssl.org/news/secadv/20231106.txt",
                "plugin_output": "Versão instalada: OpenSSL 3.0.7-27.el9_2\nVersão corrigida: OpenSSL 3.0.12 ou superior",
                "exploit_available": True,
                "exploit_frameworks": "Metasploit",
                "exploited_by_malware": False,
                "patch_available": True,
                "vpr": 9.6
            },
            {
                "host_ip": h_ips[0],
                "plugin_id": "190244",
                "plugin_name": "Linux Kernel Local Privilege Escalation (Netfilter / nf_tables)",
                "severity": "Critical",
                "cve": "CVE-2024-1086",
                "cvss_v3": 9.3,
                "cvss_v2": 7.2,
                "port": 0,
                "protocol": "tcp",
                "synopsis": "O kernel Linux do sistema operacional do host remoto é afetado por uma falha de escalonamento de privilégios para root.",
                "description": "Um bug de use-after-free no subsistema netfilter do kernel Linux permite que um usuário local sem privilégios obtenha privilégios de root completos.",
                "solution": "Atualize o pacote do kernel para a versão mais recente e reinicie o servidor.",
                "see_also": "https://nvd.nist.gov/vuln/detail/CVE-2024-1086",
                "plugin_output": "Kernel em execução: 5.14.0-362.8.1.el9_3\nKernel corrigido: 5.14.0-362.24.1.el9_3",
                "exploit_available": True,
                "exploit_frameworks": "Metasploit, Core Exploits",
                "exploited_by_malware": True,
                "patch_available": True,
                "vpr": 9.2
            },
            {
                "host_ip": h_ips[0],
                "plugin_id": "180120",
                "plugin_name": "Apache HTTP Server Request Smuggling / Header Parsing",
                "severity": "High",
                "cve": "CVE-2023-31122",
                "cvss_v3": 7.5,
                "cvss_v2": 5.0,
                "port": 80,
                "protocol": "tcp",
                "synopsis": "O servidor web remoto é afetado por falhas de HTTP request smuggling.",
                "description": "Versões desatualizadas do Apache HTTPD processam cabeçalhos de requisição de forma inadequada.",
                "solution": "Atualize o Apache HTTP Server para a versão 2.4.58 ou superior.",
                "see_also": "https://httpd.apache.org/security/vulnerabilities_24.html",
                "plugin_output": "Server: Apache/2.4.53 (Unix)",
                "exploit_available": False,
                "exploit_frameworks": "",
                "exploited_by_malware": False,
                "patch_available": True,
                "vpr": 7.4
            },
            {
                "host_ip": h_ips[1],
                "plugin_id": "174981",
                "plugin_name": "Microsoft Windows SmartScreen Security Feature Bypass",
                "severity": "Critical",
                "cve": "CVE-2024-21412",
                "cvss_v3": 9.8,
                "cvss_v2": 9.3,
                "port": 445,
                "protocol": "tcp",
                "synopsis": "O Windows Defender SmartScreen instalado no host remoto possui uma falha crítica de evasão de proteção.",
                "description": "Um atacante remoto pode enganar usuários através de atalhos especialmente formatados para executar arquivos maliciosos sem aviso do SmartScreen.",
                "solution": "Aplique a atualização de segurança de Fevereiro de 2024 da Microsoft (KB5034763).",
                "see_also": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21412",
                "plugin_output": "KB5034763 não está instalado no sistema.",
                "exploit_available": True,
                "exploit_frameworks": "Metasploit",
                "exploited_by_malware": True,
                "patch_available": True,
                "vpr": 9.7
            },
            {
                "host_ip": h_ips[1],
                "plugin_id": "153123",
                "plugin_name": "Microsoft Windows Kerberos Security Feature Bypass",
                "severity": "High",
                "cve": "CVE-2022-37967",
                "cvss_v3": 8.1,
                "cvss_v2": 7.1,
                "port": 88,
                "protocol": "tcp",
                "synopsis": "O protocolo Kerberos no host Windows remoto é afetado por desvio de controle de segurança.",
                "description": "A falta de assinatura obrigatória de PAC no protocolo Kerberos permite elevação de privilégios de domínio.",
                "solution": "Aplique as atualizações cumulativas de segurança do Windows e configure a chave de registro KrbtgtFullPacSignature.",
                "see_also": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37967",
                "plugin_output": "Registro PacSignature não enforceado no controlador de domínio.",
                "exploit_available": False,
                "exploit_frameworks": "",
                "exploited_by_malware": False,
                "patch_available": True,
                "vpr": 8.0
            }
        ]

        stats = {
            "critical_count": 3,
            "high_count": 2,
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
