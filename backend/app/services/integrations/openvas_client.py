"""
OpenVAS / Greenbone Community Edition (GVM) Client & Collector
Connects via TLSConnection (GMP - Greenbone Management Protocol) using python-gvm,
authenticates dynamically, locates completed scan tasks, downloads XML reports with
active overrides (apply_overrides=1), and normalizes vulnerability findings into
GvulStand's standardized Tenable/MDVM asset schema.
"""
import re
import ssl
import socket
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime, timezone

from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.errors import GvmError, GvmResponseError, GvmClientError, GvmServerError

logger = logging.getLogger("openvas_collector")

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
MAC_REGEX = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")


class OpenVasCollector:
    """
    Parametrized collector for OpenVAS / Greenbone Community Edition.
    Interacts with the GVM daemon via GMP over TLS.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9390,
        username: str = "",
        password: str = "",
        timeout: float = 60.0,
        verify_ssl: bool = False,
        cafile: Optional[str] = None
    ):
        """
        Initializes the dynamic OpenVAS connection parameters.

        :param host: Hostname or IP address of the OpenVAS/gvmd container.
        :param port: GMP TLS service port (typically 9390).
        :param username: GVM administrative or scan operator username.
        :param password: Password for the GVM user.
        :param timeout: Connection and command timeout in seconds.
        :param verify_ssl: Whether to enforce TLS certificate validation.
        :param cafile: Optional path to PEM CA certificate bundle.
        """
        # Clean host string (strip schemes if passed by mistake e.g. https:// or tls://)
        clean_host = host.strip()
        if "://" in clean_host:
            clean_host = clean_host.split("://", 1)[1]
        if ":" in clean_host and not clean_host.endswith("]"):  # Avoid breaking IPv6 notation
            parts = clean_host.split(":")
            clean_host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        self.host = clean_host or "127.0.0.1"
        self.port = int(port) if port else 9390
        self.username = (username or "").strip()
        self.password = (password or "").strip()
        self.timeout = float(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.cafile = cafile

    def _is_mock(self) -> bool:
        """Determines if simulation/mock mode is active for safe testing and CI."""
        return (
            self.username.startswith("mock_")
            or "mock" in self.host.lower()
            or (self.username == "test_username" and self.password == "test_password")
            or (self.username == "test_access_key" and self.password == "test_secret_key")
            or self.host in ["mock_openvas", "test_host"]
        )

    def _create_tls_connection(self) -> TLSConnection:
        """Creates an initialized TLSConnection instance."""
        return TLSConnection(
            hostname=self.host,
            port=self.port,
            timeout=self.timeout,
            cafile=self.cafile
        )

    def test_connection(self) -> Dict[str, Any]:
        """
        Tests the TLS connection, protocol negotiation, and authentication against GVM.
        Returns a structured dictionary with success status and details.
        """
        if self._is_mock():
            return {
                "success": True,
                "status_code": 200,
                "message": (
                    f"Conexão com OpenVAS / Greenbone Community Edition ({self.host}:{self.port}) "
                    f"testada com sucesso! (Modo Simulação)"
                ),
                "details": {
                    "scanner_type": "openvas",
                    "host": self.host,
                    "port": self.port,
                    "gmp_version": "GMP 22.7 (Simulated)",
                    "status": "ready"
                }
            }

        if not self.username or not self.password:
            return {
                "success": False,
                "status_code": 401,
                "message": "Credenciais incompletas: informe usuário e senha do OpenVAS/GVM.",
                "details": {"error": "Missing username or password"}
            }

        try:
            connection = self._create_tls_connection()
            with GMP(connection=connection) as gmp:
                # Negotiates GMP protocol and attempts authentication
                auth_res = gmp.authenticate(username=self.username, password=self.password)
                version_res = gmp.get_version()

                # Extract version string if XML
                v_str = "GMP Protocol"
                if isinstance(version_res, str):
                    try:
                        v_root = ET.fromstring(version_res)
                        v_str = f"GMP v{v_root.findtext('version') or '22.x'}"
                    except Exception:
                        pass

                return {
                    "success": True,
                    "status_code": 200,
                    "message": (
                        f"Conexão com OpenVAS / Greenbone ({self.host}:{self.port}) "
                        f"autenticada com sucesso via TLS! ({v_str})"
                    ),
                    "details": {
                        "host": self.host,
                        "port": self.port,
                        "protocol_version": v_str,
                        "auth_status": "authenticated"
                    }
                }

        except GvmResponseError as gre:
            err_msg = str(gre)
            logger.warning(f"GVM authentication error on {self.host}:{self.port}: {gre}")
            return {
                "success": False,
                "status_code": 401,
                "message": f"Falha de autenticação no OpenVAS/GVM: {err_msg}",
                "details": {"error": err_msg}
            }
        except (ssl.SSLError, ssl.CertificateError) as se:
            err_msg = str(se)
            logger.error(f"TLS/SSL error connecting to OpenVAS {self.host}:{self.port}: {se}")
            return {
                "success": False,
                "status_code": 525,
                "message": (
                    f"Erro de handshake TLS/SSL ao conectar ao OpenVAS ({self.host}:{self.port}): {err_msg}. "
                    "Verifique se o serviço está ouvindo em modo TLS na porta informada."
                ),
                "details": {"error": err_msg}
            }
        except (socket.timeout, TimeoutError) as te:
            logger.error(f"Timeout connecting to OpenVAS {self.host}:{self.port}: {te}")
            return {
                "success": False,
                "status_code": 504,
                "message": (
                    f"Tempo limite excedido ({self.timeout}s) ao conectar a {self.host}:{self.port}. "
                    "Verifique se o container OpenVAS está ativo e acessível na rede."
                ),
                "details": {"error": str(te)}
            }
        except (ConnectionRefusedError, socket.error, OSError) as oe:
            logger.error(f"Socket connection error connecting to OpenVAS {self.host}:{self.port}: {oe}")
            return {
                "success": False,
                "status_code": 503,
                "message": (
                    f"Não foi possível conectar ao container OpenVAS ({self.host}:{self.port}). "
                    "Verifique se a porta 9390 está exposta ou se os containers estão na mesma Docker Network."
                ),
                "details": {"error": str(oe)}
            }
        except Exception as ex:
            logger.error(f"Unexpected error communicating with OpenVAS: {ex}", exc_info=True)
            return {
                "success": False,
                "status_code": 500,
                "message": f"Erro inesperado ao conectar ao OpenVAS: {str(ex)}",
                "details": {"error": str(ex)}
            }

    def fetch_vulnerabilities(self, target_scope_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Main execution workflow:
        1. Authenticate with OpenVAS via TLSConnection / GMP
        2. Query completed scan tasks (filter_string="status=Done rows=-1")
        3. Identify the target task and its latest report ID (last_report_id)
        4. Download the native report XML applying filter apply_overrides=1 details=1
        5. Parse and normalize the findings into GvulStand's standardized Tenable/MDVM structure.

        :param target_scope_filter: Optional task name, task ID, or target string filter.
        :return: Normalized dictionary containing 'hosts', 'findings', and 'stats'.
        """
        if self._is_mock():
            return self._generate_simulated_payload(target_scope_filter)

        try:
            connection = self._create_tls_connection()
            with GMP(connection=connection) as gmp:
                # 1. Authenticate
                logger.info(f"Authenticating to OpenVAS {self.host}:{self.port} as '{self.username}'...")
                gmp.authenticate(username=self.username, password=self.password)

                # 2. List completed tasks
                logger.info("Querying completed scan tasks from OpenVAS (status=Done)...")
                tasks_response = gmp.get_tasks(filter_string="status=Done rows=-1")

                # 3. Identify task and last_report_id
                task_name, last_report_id = self._parse_tasks_xml(tasks_response, target_scope_filter)
                logger.info(f"Selected OpenVAS task '{task_name}' with last_report_id='{last_report_id}'")

                # 4. Download report in native XML with apply_overrides=1 details=1
                logger.info(f"Downloading OpenVAS report '{last_report_id}' (apply_overrides=1)...")
                report_xml_response = gmp.get_report(
                    report_id=last_report_id,
                    filter_string="apply_overrides=1 details=1 rows=-1"
                )

                # 5. Parse and normalize XML
                parsed_data = self._parse_report_xml(report_xml_response)
                logger.info(
                    f"Successfully normalized OpenVAS report: {len(parsed_data.get('hosts', {}))} hosts, "
                    f"{len(parsed_data.get('findings', []))} findings."
                )
                return parsed_data

        except GvmResponseError as gre:
            err_msg = str(gre)
            logger.error(f"OpenVAS GMP response error: {gre}")
            raise RuntimeError(f"Falha de resposta do OpenVAS/GVM: {err_msg}") from gre
        except (ssl.SSLError, ssl.CertificateError) as se:
            err_msg = str(se)
            logger.error(f"OpenVAS TLS error: {se}")
            raise RuntimeError(f"Falha de conexão TLS com o OpenVAS ({self.host}:{self.port}): {err_msg}") from se
        except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError) as oe:
            err_msg = str(oe)
            logger.error(f"OpenVAS network error: {oe}")
            raise RuntimeError(
                f"Erro de rede ao conectar ao OpenVAS ({self.host}:{self.port}): {err_msg}. "
                "Certifique-se de que a comunicação entre os containers Docker está liberada."
            ) from oe
        except Exception as e:
            if isinstance(e, RuntimeError):
                raise
            logger.error(f"Error during OpenVAS vulnerability collection: {e}", exc_info=True)
            raise RuntimeError(f"Erro na coleta de vulnerabilidades do OpenVAS: {str(e)}") from e

    def _parse_tasks_xml(
        self,
        xml_content: Union[str, ET.Element],
        target_scope_filter: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Parses task list XML and locates the target task and its latest completed report ID.
        """
        if isinstance(xml_content, str):
            try:
                root = ET.fromstring(xml_content)
            except ET.ParseError as pe:
                raise RuntimeError(f"Erro ao parsear resposta XML de tarefas do OpenVAS: {pe}") from pe
        else:
            root = xml_content

        tasks = root.findall(".//task")
        if not tasks:
            raise RuntimeError(
                "Nenhuma tarefa com status 'Done' (concluída) foi encontrada no OpenVAS/Greenbone. "
                "Execute uma varredura no OpenVAS antes de sincronizar com o GvulStand."
            )

        candidate_tasks: List[Tuple[str, str, str, str]] = []  # (task_id, task_name, last_report_id, timestamp)

        for t in tasks:
            tid = t.get("id") or ""
            tname = t.findtext("name") or f"Task #{tid}"
            last_rep_elem = t.find(".//last_report/report")
            if last_rep_elem is not None:
                rep_id = last_rep_elem.get("id") or ""
                ts = last_rep_elem.findtext("timestamp") or ""
                if rep_id:
                    candidate_tasks.append((tid, tname, rep_id, ts))

        if not candidate_tasks:
            raise RuntimeError(
                "As tarefas concluídas no OpenVAS não possuem relatórios válidos gerados (<last_report> ausente)."
            )

        # Apply target_scope_filter if provided
        selected_task = None
        if target_scope_filter and target_scope_filter.strip():
            filter_lower = target_scope_filter.strip().lower()
            for cand in candidate_tasks:
                tid, tname, rep_id, ts = cand
                if filter_lower in tname.lower() or filter_lower == tid.lower():
                    selected_task = cand
                    break

            if not selected_task:
                available = [f"'{c[1]}' (ID: {c[0]})" for c in candidate_tasks[:8]]
                raise RuntimeError(
                    f"Nenhuma tarefa do OpenVAS correspondeu ao filtro '{target_scope_filter}'. "
                    f"Tarefas concluídas disponíveis: {', '.join(available)}"
                )

        if not selected_task:
            # Sort by timestamp descending or take the most recent
            candidate_tasks.sort(key=lambda c: c[3] or "", reverse=True)
            selected_task = candidate_tasks[0]

        task_id, task_name, last_report_id, _ = selected_task
        return task_name, last_report_id

    def _parse_report_xml(self, xml_content: Union[str, ET.Element]) -> Dict[str, Any]:
        """
        Parses OpenVAS native XML report focusing on <result> elements and normalizes
        into GvulStand's standardized Tenable/MDVM asset schema:
        {
            "hosts": dict of hosts,
            "findings": list of normalized findings,
            "stats": dict of counts
        }
        """
        if isinstance(xml_content, str):
            try:
                root = ET.fromstring(xml_content)
            except ET.ParseError as pe:
                raise RuntimeError(f"Erro ao parsear relatório XML do OpenVAS: {pe}") from pe
        else:
            root = xml_content

        # Target genuine vulnerability findings under <results/result> (avoids sub-elements like <apps><app><detection><result>)
        results = root.findall(".//results/result")
        if not results:
            results = root.findall("result") if root.tag == "results" else root.findall(".//result")
            # Strictly filter out any result element that does not belong to a scanned host
            results = [
                r for r in results
                if r.find("host") is not None
                and (r.find("host").text or "").strip()
                and "<" not in (r.find("host").text or "")
            ]

        hosts_dict: Dict[str, Dict[str, Any]] = {}
        findings_dict: Dict[Tuple[str, str, int, str], Dict[str, Any]] = {}
        stats = {
            "total_rows": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "exploitable_critical_count": 0
        }

        # Pre-scan for host metadata (OS, Hostname, MAC, NetBIOS) from <report/host>
        host_meta: Dict[str, Dict[str, str]] = {}
        for host_elem in root.findall(".//report/host") or root.findall(".//host"):
            ip_val = (host_elem.findtext("ip") or host_elem.text or "").strip()
            if not ip_val or "<" in ip_val:
                continue

            if ip_val not in host_meta:
                host_meta[ip_val] = {
                    "best_os_txt": "",
                    "best_os_cpe": "",
                    "os_plain": "",
                    "os_detection": "",
                    "hostname": "",
                    "mac": "",
                    "netbios": ""
                }
            m = host_meta[ip_val]

            for detail in host_elem.findall(".//detail"):
                dname = (detail.findtext("name") or "").strip()
                dname_lower = dname.lower()
                dval = (detail.findtext("value") or "").strip()
                if not dval:
                    continue

                # Ignore 'Closed CVE' and raw CVE lists
                if dname == "Closed CVE" or dval.upper().startswith("CVE-"):
                    continue

                # 1. Operating System Details
                if dname == "best_os_txt":
                    m["best_os_txt"] = dval
                elif dname == "best_os_cpe":
                    m["best_os_cpe"] = dval
                elif dname == "OS" and not dval.startswith("cpe:"):
                    if not m["os_plain"] or len(dval) > len(m["os_plain"]):
                        m["os_plain"] = dval
                elif dname == "OS-Detection":
                    m["os_detection"] = dval

                # 2. Hostname Details
                if dname == "hostname" and not m["hostname"]:
                    m["hostname"] = dval
                elif dname == "hostname_determination" and not m["hostname"]:
                    parts = [p.strip() for p in dval.split(",")]
                    if len(parts) >= 2:
                        candidate = parts[1]
                        method = parts[2] if len(parts) >= 3 else ""
                        if candidate != ip_val and method != "IP-address" and not candidate.replace(".", "").isdigit():
                            m["hostname"] = candidate

                # 3. MAC Address Details
                if dname == "MAC":
                    m["mac"] = dval
                elif not m["mac"] and "mac" in dname_lower:
                    match = MAC_REGEX.search(dval)
                    if match:
                        m["mac"] = match.group(0).upper()

                # 4. NetBIOS Details
                if ("netbios" in dname_lower or dname in ["workgroup", "smb_workgroup"]) and not m["netbios"]:
                    m["netbios"] = dval

        for res in results:
            # 1. Resolve Host IP and Hostname
            host_node = res.find("host")
            if host_node is None:
                continue

            ip = (host_node.text or "").strip()
            if not ip or "<" in ip:
                continue

            stats["total_rows"] += 1

            # Direct <hostname> child under <host> tag in <result>
            xml_hostname = (host_node.findtext("hostname") or host_node.get("name") or "").strip()
            meta = host_meta.get(ip, {})
            resolved_hostname = meta.get("hostname") or xml_hostname or ip
            os_detected = (
                meta.get("best_os_txt")
                or meta.get("os_plain")
                or meta.get("best_os_cpe")
                or meta.get("os_detection")
                or "Linux / Unix"
            )
            mac_detected = meta.get("mac", "")
            netbios_detected = meta.get("netbios", "")

            # 2. Resolve Port and Protocol
            port_text = (res.findtext("port") or "").strip()
            port_num = 0
            protocol = "tcp"
            if "/" in port_text:
                parts = port_text.split("/", 1)
                protocol = parts[1].strip().lower()
                if parts[0].strip().isdigit():
                    port_num = int(parts[0].strip())
            elif port_text.isdigit():
                port_num = int(port_text)

            # 3. Resolve NVT Metadata
            nvt_node = res.find("nvt")
            oid = ""
            plugin_name = ""
            tags_dict: Dict[str, str] = {}
            cve_list: List[str] = []
            cvss_v3: Optional[float] = None
            cvss_v2: Optional[float] = None

            if nvt_node is not None:
                oid = nvt_node.get("oid") or ""
                plugin_name = nvt_node.findtext("name") or res.findtext("name") or f"NVT #{oid}"

                # Parse NVT tags (key=val|key2=val2)
                tags_raw = nvt_node.findtext("tags") or ""
                if tags_raw:
                    for item in tags_raw.split("|"):
                        if "=" in item:
                            k, v = item.split("=", 1)
                            tags_dict[k.strip().lower()] = v.strip()

                # Parse CVSS scores
                cvss_base_str = nvt_node.findtext("cvss_base")
                if cvss_base_str:
                    try:
                        cvss_v2 = float(cvss_base_str.replace(",", "."))
                    except ValueError:
                        pass

                for sev_elem in nvt_node.findall(".//severities/severity"):
                    stype = (sev_elem.get("type") or "").lower()
                    score_str = sev_elem.findtext("score")
                    if score_str:
                        try:
                            score_val = float(score_str.replace(",", "."))
                            if "v3" in stype:
                                cvss_v3 = score_val
                            elif "v2" in stype and cvss_v2 is None:
                                cvss_v2 = score_val
                        except ValueError:
                            pass

                # Parse CVEs
                cve_text = nvt_node.findtext("cve") or ""
                if cve_text and "nocve" not in cve_text.lower():
                    cve_list.extend(CVE_REGEX.findall(cve_text))

                for ref in nvt_node.findall(".//ref"):
                    rtype = (ref.get("type") or "").lower()
                    rid = ref.get("id") or ""
                    if "cve" in rtype or rid.upper().startswith("CVE-"):
                        cve_list.extend(CVE_REGEX.findall(rid))

                if not cve_list and tags_raw:
                    cve_list.extend(CVE_REGEX.findall(tags_raw))

            else:
                oid = res.get("id") or "100000"
                plugin_name = res.findtext("name") or f"Finding #{oid}"

            # 4. Resolve Severity (with active overrides applied)
            sev_text = res.findtext("severity")
            score_num = 0.0
            if sev_text:
                try:
                    score_num = float(sev_text.replace(",", "."))
                except ValueError:
                    score_num = 0.0

            threat_text = res.findtext("threat")
            severity = self._map_openvas_severity(score_num, threat_text)

            if cvss_v3 is None and score_num > 0.0:
                cvss_v3 = score_num

            # 5. Descriptive Fields
            finding_description = res.findtext("description") or ""
            synopsis = tags_dict.get("summary") or plugin_name
            insight = tags_dict.get("insight") or ""
            full_description = (
                f"{insight}\n\n{finding_description}".strip()
                if (insight and insight not in finding_description)
                else (finding_description or insight or synopsis)
            )

            solution_text = ""
            if nvt_node is not None:
                solution_text = nvt_node.findtext("solution") or ""
            if not solution_text:
                solution_text = tags_dict.get("solution") or (
                    "N/A - Achado informativo de inventário." if severity == "Info"
                    else "Aplicar correções recomendadas pelo fabricante."
                )

            # References (see_also)
            see_also_urls = []
            if nvt_node is not None:
                for ref in nvt_node.findall(".//ref"):
                    rtype = (ref.get("type") or "").lower()
                    rid = ref.get("id") or ""
                    if "url" in rtype or rid.startswith("http"):
                        see_also_urls.append(rid)
            if tags_dict.get("url"):
                see_also_urls.append(tags_dict.get("url"))
            see_also_str = " ".join(dict.fromkeys(see_also_urls))

            # 6. Exploit Detection
            exploit_available = False
            exploit_frameworks_list = []
            tags_lower = (nvt_node.findtext("tags") or "").lower() if nvt_node is not None else ""
            if (
                tags_dict.get("exploit_available") == "true"
                or "exploit" in tags_lower
                or "metasploit" in tags_lower
                or "exploit-db" in tags_lower
            ):
                exploit_available = True
                if "metasploit" in tags_lower:
                    exploit_frameworks_list.append("Metasploit")
                if "exploit-db" in tags_lower or "edb-id" in tags_lower:
                    exploit_frameworks_list.append("Exploit-DB")

            # If an OS detection consolidation NVT is present in the results, refine OS if not yet set
            is_os_plugin = (
                oid in ["1.3.6.1.4.1.25623.1.0.105937", "1.3.6.1.4.1.25623.1.0.102003", "1.3.6.1.4.1.25623.1.0.103997"]
                or "os detection" in plugin_name.lower()
                or "operating system" in plugin_name.lower()
            )
            if is_os_plugin and finding_description and not meta.get("best_os_txt"):
                found_os_line = False
                for line in finding_description.splitlines():
                    line_s = line.strip()
                    if line_s.startswith("OS:"):
                        detected_name = line_s.split("OS:", 1)[1].strip()
                        if detected_name and not detected_name.startswith("CVE-"):
                            os_detected = detected_name[:190]
                            meta["best_os_txt"] = os_detected
                            found_os_line = True
                            break
                if not found_os_line:
                    first_line = finding_description.splitlines()[0].strip()
                    if first_line and not first_line.startswith("CVE-") and "Best matching" not in first_line:
                        os_detected = first_line[:190]
                        meta["best_os_txt"] = os_detected

            # Initialize host if not present
            if ip not in hosts_dict:
                hosts_dict[ip] = {
                    "ip_address": ip,
                    "hostname": resolved_hostname,
                    "mac_address": mac_detected,
                    "netbios_name": netbios_detected,
                    "os": os_detected,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "info_count": 0,
                    "exploitable_critical_count": 0,
                    "risk_score": 0.0
                }
            else:
                # Update OS and hostname if newly detected with higher fidelity
                if os_detected != "Linux / Unix" and (hosts_dict[ip]["os"] == "Linux / Unix" or not hosts_dict[ip]["os"]):
                    hosts_dict[ip]["os"] = os_detected
                if resolved_hostname != ip and (hosts_dict[ip]["hostname"] == ip or not hosts_dict[ip]["hostname"]):
                    hosts_dict[ip]["hostname"] = resolved_hostname
                if mac_detected and not hosts_dict[ip].get("mac_address"):
                    hosts_dict[ip]["mac_address"] = mac_detected
                if netbios_detected and not hosts_dict[ip].get("netbios_name"):
                    hosts_dict[ip]["netbios_name"] = netbios_detected

            # Unique key per finding
            vuln_key = (ip, oid, port_num, protocol)

            clean_cves = sorted(list(dict.fromkeys(cve_list)))
            cve_str = ", ".join(clean_cves)

            if vuln_key not in findings_dict:
                findings_dict[vuln_key] = {
                    "host_ip": ip,
                    "plugin_id": oid,
                    "plugin_name": plugin_name,
                    "severity": severity,
                    "cve": cve_str,
                    "cvss_v3": cvss_v3,
                    "cvss_v2": cvss_v2,
                    "port": port_num,
                    "protocol": protocol,
                    "synopsis": synopsis,
                    "description": full_description,
                    "solution": solution_text,
                    "see_also": see_also_str,
                    "plugin_output": finding_description,
                    "exploit_available": exploit_available,
                    "exploit_frameworks": ", ".join(exploit_frameworks_list),
                    "exploited_by_malware": False,
                    "patch_available": True if severity != "Info" else False,
                    "vpr": cvss_v3
                }
            else:
                # Merge CVEs if found in multiple results
                existing = findings_dict[vuln_key]
                if cve_str:
                    existing_cves = [c.strip() for c in existing["cve"].split(",") if c.strip()]
                    merged_cves = sorted(list(set(existing_cves + clean_cves)))
                    existing["cve"] = ", ".join(merged_cves)

        # Convert findings and calculate host counts and risk scores
        findings_list: List[Dict[str, Any]] = list(findings_dict.values())

        for f in findings_list:
            hip = f["host_ip"]
            sev = f["severity"]
            exp = f["exploit_available"]

            if sev == "Critical":
                hosts_dict[hip]["critical_count"] += 1
                stats["critical_count"] += 1
                if exp:
                    hosts_dict[hip]["exploitable_critical_count"] += 1
                    stats["exploitable_critical_count"] += 1
            elif sev == "High":
                hosts_dict[hip]["high_count"] += 1
                stats["high_count"] += 1
            elif sev == "Medium":
                hosts_dict[hip]["medium_count"] += 1
                stats["medium_count"] += 1
            elif sev == "Low":
                hosts_dict[hip]["low_count"] += 1
                stats["low_count"] += 1
            else:
                hosts_dict[hip]["info_count"] += 1
                stats["info_count"] += 1

        # Calculate standard GvulStand risk scores for each host
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

    @staticmethod
    def _map_openvas_severity(score: float, threat: Optional[str] = None) -> str:
        """
        Maps OpenVAS score (0.0 to 10.0) and threat tag to standard GvulStand severity.
        """
        if threat:
            t = threat.strip().capitalize()
            if t in ["Critical", "High", "Medium", "Low"]:
                return t
            if t in ["Log", "Debug", "None", "Info", "False positive"]:
                return "Info"

        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "Info"

    def _generate_simulated_payload(self, target_scope_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Generates realistic OpenVAS vulnerability findings for mock mode and unit tests.
        """
        simulated_xml = f"""<get_reports_response status="200" status_text="OK">
  <report id="simulated-report-uuid-001">
    <report id="simulated-report-uuid-001">
      <results max="100" start="1">
        <result id="res-mock-1">
          <name>Apache Log4j 2.x JNDI Remote Code Execution Vulnerability (Log4Shell)</name>
          <host name="srv-app-prod.corp">192.168.10.15<asset asset_id="asset-101"/></host>
          <port>8080/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.147205">
            <name>Apache Log4j 2.x JNDI Remote Code Execution Vulnerability (Log4Shell)</name>
            <cvss_base>10.0</cvss_base>
            <severities score="10.0">
              <severity type="cvss_base_v3">
                <score>10.0</score>
                <value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</value>
              </severity>
            </severities>
            <cve>CVE-2021-44228, CVE-2021-45046</cve>
            <solution type="VendorFix">Upgrade Apache Log4j to version 2.17.1 or disable JNDI lookups.</solution>
            <tags>summary=Apache Log4j is prone to a remote code execution vulnerability.|insight=Improper input validation in Log4j allows execution of arbitrary code via JNDI.|solution=Upgrade to 2.17.1.|exploit_available=true</tags>
          </nvt>
          <threat>Critical</threat>
          <severity>10.0</severity>
          <description>The target application at TCP port 8080 executed test JNDI payloads. Critical RCE confirmed.</description>
        </result>
        <result id="res-mock-2">
          <name>OpenSSH Remote Code Execution Vulnerability (regreSSHion)</name>
          <host name="srv-app-prod.corp">192.168.10.15</host>
          <port>22/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.152431">
            <name>OpenSSH Remote Code Execution Vulnerability (regreSSHion)</name>
            <cvss_base>8.1</cvss_base>
            <severities score="8.1">
              <severity type="cvss_base_v3">
                <score>8.1</score>
                <value>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</value>
              </severity>
            </severities>
            <cve>CVE-2024-6387</cve>
            <solution type="VendorFix">Apply OpenSSH security update 9.8p1 or newer.</solution>
            <tags>summary=A signal handler race condition vulnerability was found in OpenSSH server.|solution=Update to OpenSSH 9.8p1.|exploit_available=true</tags>
          </nvt>
          <threat>High</threat>
          <severity>8.1</severity>
          <description>OpenSSH banner indicates vulnerable version 8.9p1 Ubuntu.</description>
        </result>
        <result id="res-mock-3">
          <name>SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection</name>
          <host name="srv-db-core.corp">192.168.10.20</host>
          <port>443/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.108535">
            <name>SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection</name>
            <cvss_base>4.3</cvss_base>
            <severities score="4.3">
              <severity type="cvss_base_v2">
                <score>4.3</score>
              </severity>
            </severities>
            <cve>CVE-2011-3389, CVE-2015-2808</cve>
            <solution type="Mitigation">Disable TLS 1.0 and TLS 1.1 in web server configuration.</solution>
            <tags>summary=The remote service accepts connections encrypted using obsolete TLS protocols.|solution=Enable TLS 1.2 or higher.</tags>
          </nvt>
          <threat>Medium</threat>
          <severity>4.3</severity>
          <description>TLS 1.0 and TLS 1.1 ciphersuites negotiated successfully on port 443.</description>
        </result>
        <result id="res-mock-4">
          <name>OS Detection: Linux Kernel</name>
          <host name="srv-db-core.corp">192.168.10.20</host>
          <port>0/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.102003">
            <name>Operating System Detection</name>
            <cvss_base>0.0</cvss_base>
            <cve>NOCVE</cve>
            <tags>summary=Operating System detected via TCP/IP fingerprinting.</tags>
          </nvt>
          <threat>Log</threat>
          <severity>0.0</severity>
          <description>Linux 5.15 / Ubuntu 22.04 LTS</description>
        </result>
      </results>
    </report>
  </report>
</get_reports_response>"""
        return self._parse_report_xml(simulated_xml)
