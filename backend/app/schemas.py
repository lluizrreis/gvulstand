from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

# --- Auth & User Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str
    user: Dict[str, Any]

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

# --- Group Permission Schemas ---
class UserGroupPermissionBase(BaseModel):
    asset_group_id: int
    can_treat: bool = True
    can_import: bool = True
    can_author: bool = True

class UserGroupPermissionIn(UserGroupPermissionBase):
    pass

class UserGroupPermissionOut(UserGroupPermissionBase):
    id: Optional[int] = None
    asset_group_name: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class UserBase(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    role: str = "analyst"
    is_active: bool = True
    auth_type: str = "local" # 'local' or 'ldap'
    sam_account_name: Optional[str] = None

class UserCreate(UserBase):
    password: Optional[str] = None
    allowed_groups: Optional[List[UserGroupPermissionIn]] = None

class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    auth_type: Optional[str] = None
    sam_account_name: Optional[str] = None
    allowed_groups: Optional[List[UserGroupPermissionIn]] = None

class UserOut(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime
    allowed_groups: List[UserGroupPermissionOut] = []
    allowed_group_ids: List[int] = []

    model_config = ConfigDict(from_attributes=True)

# --- LDAP Integration Schemas ---
class LdapConfigBase(BaseModel):
    is_enabled: bool = False
    server_host: Optional[str] = None
    server_port: int = 389
    use_ssl: bool = False
    use_starttls: bool = False
    bind_user: Optional[str] = None
    base_dn: Optional[str] = None
    user_search_filter: str = "(&(objectClass=user)(sAMAccountName={username}))"
    sam_attribute: str = "sAMAccountName"
    name_attribute: str = "displayName"
    email_attribute: str = "mail"
    connection_timeout: int = 5

class LdapConfigUpdate(LdapConfigBase):
    bind_password: Optional[str] = None

class LdapConfigOut(LdapConfigBase):
    id: int
    is_password_configured: bool = False
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class LdapTestRequest(BaseModel):
    server_host: str
    server_port: int = 389
    use_ssl: bool = False
    use_starttls: bool = False
    bind_user: str
    bind_password: Optional[str] = None
    base_dn: Optional[str] = None
    connection_timeout: int = 5

class LdapTestResponse(BaseModel):
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None

class LdapValidateUserResponse(BaseModel):
    valid: bool
    sam_account_name: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    distinguished_name: Optional[str] = None
    message: Optional[str] = None

# --- Asset Group Schemas ---
class AssetGroupBase(BaseModel):
    name: str
    description: Optional[str] = None
    network_range: Optional[str] = None
    owner: Optional[str] = None
    sla_critical_days: int = 7
    sla_high_days: int = 15
    sla_medium_days: int = 30
    sla_low_days: int = 60
    parent_id: Optional[int] = None

class AssetGroupCreate(AssetGroupBase):
    pass

class AssetGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    network_range: Optional[str] = None
    owner: Optional[str] = None
    sla_critical_days: Optional[int] = None
    sla_high_days: Optional[int] = None
    sla_medium_days: Optional[int] = None
    sla_low_days: Optional[int] = None
    parent_id: Optional[int] = None

class AssetGroupOut(AssetGroupBase):
    id: int
    created_at: datetime
    updated_at: datetime
    total_scans: Optional[int] = 0
    total_hosts: Optional[int] = 0
    total_vulnerabilities: Optional[int] = 0
    critical_count: Optional[int] = 0
    high_count: Optional[int] = 0
    parent_name: Optional[str] = None
    subgroups_count: Optional[int] = 0
    level: Optional[int] = 1
    hierarchy_path: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# --- Scan Schemas ---
class ScanOut(BaseModel):
    id: int
    asset_group_id: int
    asset_group_name: Optional[str] = None
    scan_name: str
    scan_type: str
    filename: str
    file_size_bytes: int
    total_hosts: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    exploitable_critical_count: int
    scan_date: datetime
    created_at: datetime
    notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# --- Host Schemas ---
class HostOut(BaseModel):
    id: int
    scan_id: int
    asset_group_id: int
    asset_group_name: Optional[str] = None
    ip_address: str
    hostname: Optional[str] = None
    netbios_name: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    exploitable_critical_count: int
    risk_score: float
    active_action_plan_id: Optional[int] = None
    active_action_plan_title: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class InventoryStatsOut(BaseModel):
    total_hosts: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_vulns: int = 0
    avg_risk_score: float = 0.0
    max_risk_score: float = 0.0
    hosts_with_critical: int = 0
    hosts_with_exploits: int = 0

class PaginatedInventoryOut(BaseModel):
    items: List[HostOut]
    total: int
    page: int
    page_size: int
    total_pages: int
    stats: Optional[InventoryStatsOut] = None


# --- Vulnerability Schemas ---
class VulnerabilityOut(BaseModel):
    id: int
    scan_id: int
    host_id: int
    host_ip: Optional[str] = None
    host_name: Optional[str] = None
    asset_group_id: int
    asset_group_name: Optional[str] = None
    plugin_id: str
    plugin_name: str
    cve: Optional[str] = None
    cve_list: List[str] = []
    cve_count: int = 0
    cvss_v3: Optional[float] = None
    cvss_v2: Optional[float] = None
    severity: str
    port: int
    protocol: str
    synopsis: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    see_also: Optional[str] = None
    plugin_output: Optional[str] = None
    exploit_available: bool
    exploit_frameworks: Optional[str] = None
    exploited_by_malware: Optional[bool] = False
    vpr: Optional[float] = None
    patch_available: Optional[bool] = False
    plugin_type: Optional[str] = None
    treatment_status: str
    treatment_notes: Optional[str] = None
    treated_by_username: Optional[str] = None
    treated_at: Optional[datetime] = None
    treated_at_formatted: Optional[str] = None
    first_found: Optional[datetime] = None
    last_found: Optional[datetime] = None
    aging_days: Optional[int] = None
    is_ignored_in_indicators: bool = False
    active_action_plan_id: Optional[int] = None
    active_action_plan_title: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class VulnerabilityStatusUpdate(BaseModel):
    treatment_status: str
    treatment_notes: str  # Obrigatório — justificativa de auditoria ISO 27001

class BulkVulnerabilityTreatmentUpdate(BaseModel):
    vulnerability_ids: List[int]
    treatment_status: str
    treatment_notes: str  # Obrigatório — justificativa de auditoria ISO 27001

class BulkTreatmentResponse(BaseModel):
    updated_count: int
    message: str

class TreatmentHistoryOut(BaseModel):
    id: int
    vulnerability_id: int
    treatment_status: str
    treatment_notes: str
    changed_by_username: str
    changed_at: datetime
    changed_at_formatted: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class PaginatedVulnerabilitiesOut(BaseModel):
    items: List[VulnerabilityOut]
    total: int
    page: int
    page_size: int
    total_pages: int

# --- Top 100 Critical Schema ---
class TopCriticalVuln(BaseModel):
    plugin_id: str
    plugin_name: str
    cve: Optional[str] = None
    cve_list: List[str] = []
    cve_count: int = 0
    cvss_v3: Optional[float] = None
    severity: str
    affected_hosts_count: int
    exploit_available: bool
    exploit_frameworks: Optional[str] = None
    solution: Optional[str] = None
    synopsis: Optional[str] = None
    sample_hosts: List[str] = []

# --- Plugin Solution & Affected Hosts Schema ---
class AffectedHostItem(BaseModel):
    vuln_id: int
    host_id: int
    ip_address: str
    hostname: Optional[str] = None
    asset_group_id: int
    asset_group_name: str
    port: int
    protocol: str
    aging_days: int
    first_found: Optional[datetime] = None
    treatment_status: str

class PluginSolutionOut(BaseModel):
    plugin_id: str
    plugin_name: str
    severity: str
    cvss_v3: Optional[float] = None
    cvss_v2: Optional[float] = None
    cve: Optional[str] = None
    cve_list: List[str] = []
    cve_count: int = 0
    exploit_available: bool
    exploit_frameworks: Optional[str] = None
    synopsis: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    see_also: Optional[str] = None
    plugin_output: Optional[str] = None
    total_affected_hosts: int
    affected_hosts: List[AffectedHostItem] = []

# --- Top 20 Hosts with Exploitable Criticals ---
class TopExploitableHost(BaseModel):
    host_id: int
    ip_address: str
    hostname: Optional[str] = None
    asset_group_name: Optional[str] = None
    os: Optional[str] = None
    exploitable_critical_count: int
    critical_count: int
    high_count: int
    medium_count: int
    risk_score: float
    exploits_list: List[str] = []

# --- Dashboard Overview Stats (ISO 27000 & ISO 9000 & Tenable Widgets) ---
class DashboardStats(BaseModel):
    total_scans: int
    total_asset_groups: int
    total_unique_hosts: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    exploitable_total_count: int
    iso27001_risk_score: float # Global risk index
    posture_score: Optional[int] = 100 # Normalized Security Posture (10-100)
    iso9001_remediation_efficiency: Optional[float] = None # % of resolved issues overall
    severity_breakdown: Dict[str, int]
    aging_breakdown: Dict[str, int] = {}
    vpr_breakdown: Dict[str, int] = {}
    sla_progress: Dict[str, Dict[str, int]] = {}
    age_sla_matrix: Dict[str, Dict[str, int]] = {}
    exploitable_types: Dict[str, int] = {}
    scan_health: Dict[str, int] = {}
    patch_advisory: Dict[str, int] = {}
    cve_counts: Dict[str, int] = {}
    treatment_breakdown: Dict[str, Dict[str, int]] = {}
    action_plans_summary: Optional[Dict[str, Any]] = None
    asset_group_distribution: List[Dict[str, Any]]
    recent_scans: List[ScanOut]
    trend_data: Optional[Dict[str, Any]] = None

# --- Comparative Diff Schemas (Before vs After) ---
class DiffItem(BaseModel):
    plugin_id: str
    plugin_name: str
    cve: Optional[str] = None
    cve_list: List[str] = []
    cve_count: int = 0
    severity: str
    cvss_v3: Optional[float] = None
    host_ip: str
    host_name: Optional[str] = None
    port: int
    protocol: str
    status: str # 'REMEDIATED' (Green), 'PERSISTING' (Orange), 'NEW' (Red)
    exploit_available: bool
    solution: Optional[str] = None

class ComparativeReport(BaseModel):
    asset_group_id: int
    asset_group_name: str
    baseline_scan: ScanOut
    retest_scan: ScanOut
    remediation_rate_percent: float # ISO 9001 metric: % of baseline vulns eliminated
    risk_reduction_percent: float
    total_before: int
    total_after: int
    remediated_count: int
    persisting_count: int
    new_count: int
    severity_before: Dict[str, int]
    severity_after: Dict[str, int]
    critical_before: int
    critical_after: int
    exploitable_before: int
    exploitable_after: int
    remediated_items: List[DiffItem]
    persisting_items: List[DiffItem]
    new_items: List[DiffItem]

# --- Scan Diagnostics & Troubleshooting Schemas ---
class ScanDiagnosticItem(BaseModel):
    id: int
    scan_id: int
    scan_name: str
    host_id: int
    host_ip: str
    host_name: Optional[str] = None
    asset_group_id: int
    asset_group_name: str
    plugin_id: str
    plugin_name: str
    category: str
    error_title: str
    error_description: str
    recommended_action: str
    plugin_output: Optional[str] = None
    port: int
    protocol: str
    created_at: datetime

class ScanDiagnosticsResponse(BaseModel):
    total_error_items: int
    total_affected_hosts: int
    auth_errors_count: int
    connection_errors_count: int
    permission_errors_count: int
    incomplete_scan_count: int
    items: List[ScanDiagnosticItem]


# --- Executive Summary Report Schemas ---
class ReportMetadata(BaseModel):
    title: str
    period: str
    emission_date: str
    scope_name: str
    scope_group_id: Optional[int] = None
    team: str
    classification: str
    generated_by: Optional[str] = None
    scan_ids: List[int] = []
    scan_names: List[str] = []
    notes: Optional[str] = None

class ReportOSItem(BaseModel):
    os_name: str
    count: int
    percentage: float
    is_eol: bool
    eol_status: str

class ReportInventory(BaseModel):
    total_discovered_hosts: int
    active_hosts: int
    inactive_hosts: int
    active_percentage: float
    os_distribution: List[ReportOSItem]
    eol_count: int
    eol_percentage: float
    eol_systems_list: List[str]
    attack_surface_exposure_pct: float = 0.0

class ReportRiskSummary(BaseModel):
    organization_risk_score: float
    risk_level: str
    risk_trend_direction: str # "down", "up", "stable", "baseline"
    risk_trend_percentage: float
    risk_trend_text: str
    previous_risk_score: Optional[float] = None
    total_occurrences: int
    unique_vulnerabilities: int
    repetition_ratio: float
    attack_surface_exposure_pct: float = 0.0
    hosts_with_critical_or_exploits: int = 0
    critical_density: float = 0.0
    executive_summary_statement: str = ""

class ReportSeverityDistribution(BaseModel):
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    actionable_total: int
    critical_percent: float
    high_percent: float
    medium_percent: float
    low_percent: float
    info_percent: float
    exploitable_count: int
    exploitable_percent: float

class ReportTopHost(BaseModel):
    rank: int
    host_id: int
    ip_address: str
    hostname: Optional[str] = None
    asset_group_name: str
    os: Optional[str] = None
    critical_count: int
    high_count: int
    exploitable_count: int
    risk_score: float

class ReportTopVuln(BaseModel):
    rank: int
    plugin_id: str
    plugin_name: str
    cve: Optional[str] = None
    severity: str
    cvss_v3: Optional[float] = None
    affected_hosts_count: int
    affected_hosts_percent: float
    solution: Optional[str] = None

class ReportHighlights(BaseModel):
    top_hosts: List[ReportTopHost]
    top_vulnerabilities: List[ReportTopVuln]

class ReportRemediationSLA(BaseModel):
    overall_mttr_days: float
    mttr_by_severity: Dict[str, float]
    sla_compliance_rate: float
    sla_meeting_count: int
    sla_not_meeting_count: int
    sla_by_severity: Dict[str, Dict[str, Any]]
    recurring_count: int
    new_count: int
    remediated_count: int
    recurring_percent: float
    new_percent: float

class ExecutiveSummaryReport(BaseModel):
    metadata: ReportMetadata
    inventory: ReportInventory
    risk_summary: ReportRiskSummary
    severity_distribution: ReportSeverityDistribution
    highlights_top5: ReportHighlights
    remediation_sla: ReportRemediationSLA

class ReportTemplateOut(BaseModel):
    id: str
    name: str
    status: str
    description: str
    icon: str
    badge: str


# --- Technical Detailed Report Schemas ---
class TechnicalVulnerabilityItem(BaseModel):
    id: int
    plugin_id: str
    plugin_name: str
    cve: Optional[str] = None
    cve_list: List[str] = []
    severity: str
    cvss_v3: Optional[float] = None
    cvss_v2: Optional[float] = None
    port: int
    protocol: str
    solution: Optional[str] = None
    synopsis: Optional[str] = None
    description: Optional[str] = None
    plugin_output: Optional[str] = None
    exploit_available: bool = False
    exploit_frameworks: Optional[str] = None
    treatment_status: str = "Open"


class TechnicalHostDossier(BaseModel):
    host_id: int
    ip_address: str
    hostname: Optional[str] = None
    netbios_name: Optional[str] = None
    asset_group_id: int
    asset_group_name: str
    os: Optional[str] = None
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int = 0
    exploits_count: int
    risk_score: float
    total_actionable_vulns: int
    vulnerabilities: List[TechnicalVulnerabilityItem] = []


class TechnicalReportPortStat(BaseModel):
    port: int
    protocol: str
    count: int


class TechnicalReportSummary(BaseModel):
    total_hosts: int
    total_actionable_vulns: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    exploitable_count: int
    avg_risk_score: float
    max_risk_score: float
    top_ports: List[TechnicalReportPortStat] = []


class TechnicalReportResponse(BaseModel):
    metadata: ReportMetadata
    summary: TechnicalReportSummary
    hosts: List[TechnicalHostDossier]


# --- SLA Audit & ISO 27001 Compliance Report Schemas ---

class SlaGroupLimits(BaseModel):
    group_id: int
    group_name: str
    sla_critical_days: int
    sla_high_days: int
    sla_medium_days: int
    sla_low_days: int


class SlaAgingBucket(BaseModel):
    range_label: str  # "0-30 dias", "31-60 dias", "61-90 dias", "> 90 dias (Passivos Críticos)"
    total_count: int
    within_sla_count: int
    breached_sla_count: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    critical_breached_count: int = 0
    high_breached_count: int = 0
    medium_breached_count: int = 0
    low_breached_count: int = 0


class SlaSeverityCompliance(BaseModel):
    severity: str
    sla_limit_days: int
    total_count: int
    within_sla_count: int
    breached_sla_count: int
    compliance_rate_percent: float
    avg_age_days: float
    max_age_days: int


class SlaAuditAdherence(BaseModel):
    sla_limits_by_group: List[SlaGroupLimits] = []
    overall_compliance_rate_percent: float
    total_actionable: int
    total_within_sla: int
    total_breached_sla: int
    critical_passives_over_90_days: int
    high_passives_over_90_days: int
    aging_matrix: List[SlaAgingBucket] = []
    severity_compliance: List[SlaSeverityCompliance] = []


class Iso9001PdcaMetrics(BaseModel):
    remediation_efficiency_rate_percent: Optional[float] = None
    remediation_efficiency_display: str
    total_remediated: int
    total_actionable: int
    has_retest_data: bool = False
    resolution_rate_percent: Optional[float] = None
    resolution_rate_display: str
    baseline_scan_name: Optional[str] = None
    retest_scan_name: Optional[str] = None
    baseline_vulns_count: int = 0
    retest_vulns_count: int = 0
    retest_remediated_count: int = 0
    retest_persisting_count: int = 0
    retest_new_count: int = 0
    net_risk_reduction_percent: Optional[float] = None
    net_risk_reduction_display: str
    risk_before: Optional[float] = None
    risk_after: Optional[float] = None
    pdca_status_statement: str


class AcceptedRiskAuditItem(BaseModel):
    id: int
    plugin_id: str
    plugin_name: str
    severity: str
    host_ip: str
    hostname: Optional[str] = None
    asset_group_name: str
    treated_by_username: str
    treated_at: Optional[datetime] = None
    treated_at_formatted: str
    treatment_notes: str
    cve: Optional[str] = None
    cvss_v3: Optional[float] = None
    port: int = 0
    protocol: str = "tcp"


class AcceptedRiskSummary(BaseModel):
    total_accepted_risks: int
    critical_accepted: int
    high_accepted: int
    medium_accepted: int
    low_accepted: int
    accepted_risk_ratio_percent: float
    items: List[AcceptedRiskAuditItem] = []


class AuditorStatement(BaseModel):
    iso27001_control_8_8_status: str
    iso9001_pdca_status: str
    summary_findings: str
    auditor_recommendations: List[str] = []
    signed_by: str
    signed_role: str


class SlaAuditReportResponse(BaseModel):
    metadata: ReportMetadata
    sla_adherence: SlaAuditAdherence
    iso9001_pdca: Iso9001PdcaMetrics
    accepted_risks_trail: AcceptedRiskSummary
    auditor_statement: AuditorStatement


# --- System Parameters Schemas ---
class TimezoneOption(BaseModel):
    id: str
    label: str
    offset: str
    is_brazil: bool = False
    name: Optional[str] = None
    offset_formatted: Optional[str] = None
    utc_offset_str: Optional[str] = None


class SystemParametersOut(BaseModel):
    id: int = 1
    timezone: str = "America/Sao_Paulo"
    timezone_label: str = "América/São Paulo (UTC-03:00 - Brasília)"
    sla_critical_days: int = 7
    sla_high_days: int = 15
    sla_medium_days: int = 30
    sla_low_days: int = 60
    ignored_vulnerability_ids: str = ""
    ignored_ids_list: List[str] = []
    ignored_vulnerabilities_count: int = 0
    ignored_plugins_count: int = 0
    updated_at: Optional[datetime] = None
    updated_at_formatted: Optional[str] = None
    updated_by_username: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SystemParametersUpdate(BaseModel):
    timezone: str = "America/Sao_Paulo"
    sla_critical_days: int = Field(default=7, ge=1, le=365)
    sla_high_days: int = Field(default=15, ge=1, le=365)
    sla_medium_days: int = Field(default=30, ge=1, le=365)
    sla_low_days: int = Field(default=60, ge=1, le=365)
    ignored_vulnerability_ids: str = ""


class IgnoredVulnPreviewRequest(BaseModel):
    ignored_ids: Optional[str] = None


class IgnoredVulnPreviewItem(BaseModel):
    plugin_id: str
    plugin_name: str
    severity: str
    findings_count: int = 0
    matching_findings_count: int = 0
    affected_hosts_count: int = 0
    impacted_hosts_count: int = 0
    sample_cve: Optional[str] = None
    sample_solution: Optional[str] = None


class IgnoredVulnPreviewOut(BaseModel):
    total_matching_rules: int = 0
    total_ignored_plugins: int = 0
    total_findings_affected: int = 0
    total_findings_impacted: int = 0
    total_affected_hosts: int = 0
    total_unique_hosts_impacted: int = 0
    items: List[IgnoredVulnPreviewItem] = []


# ====================================================
# --- Action Plan & Task Schemas (GvulStand Action Plans) ---
# ====================================================

class ActionTaskVulnerabilityOut(BaseModel):
    id: int
    action_task_id: int
    vulnerability_id: int
    plugin_id: Optional[str] = None
    plugin_name: Optional[str] = None
    severity: Optional[str] = None
    cve: Optional[str] = None
    host_ip: Optional[str] = None
    host_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ActionTaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    order_index: int = 0
    status: str = "TODO"  # 'TODO', 'DOING', 'REVIEW', 'DONE', 'BLOCKED'
    assigned_user_id: Optional[int] = None
    start_date: Optional[datetime] = None
    due_date: Optional[datetime] = None


class ActionTaskCreate(ActionTaskBase):
    vulnerability_ids: Optional[List[int]] = None


class ActionTaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    order_index: Optional[int] = None
    status: Optional[str] = None  # 'TODO', 'DOING', 'REVIEW', 'DONE', 'BLOCKED'
    assigned_user_id: Optional[int] = None
    start_date: Optional[datetime] = None
    due_date: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    vulnerability_ids: Optional[List[int]] = None
    sync_vuln_treatment: bool = False


class ActionTaskOut(ActionTaskBase):
    id: int
    action_plan_id: int
    assigned_user_name: Optional[str] = None
    completed_at: Optional[datetime] = None
    is_overdue: bool = False
    vulnerabilities_count: int = 0
    vulnerability_links: List[ActionTaskVulnerabilityOut] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# --- Tag Schemas ---
class TagBase(BaseModel):
    name: str
    color_hex: str = "#6366f1"
    color: Optional[str] = None

    def model_post_init(self, __context):
        if self.color and (not self.color_hex or self.color_hex == "#6366f1"):
            self.color_hex = self.color
        elif self.color_hex and not self.color:
            self.color = self.color_hex

class TagCreate(TagBase):
    pass

class TagOut(TagBase):
    id: int
    created_at: datetime
    usage_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class ActionPlanBase(BaseModel):
    title: str
    description: Optional[str] = None
    asset_group_id: Optional[int] = None
    scope_type: str = "CUSTOM"  # 'HOST', 'VULNERABILITY', 'GROUP', 'MATRIX_NN', 'CUSTOM'
    target_host_id: Optional[int] = None
    target_host_ip: Optional[str] = None
    target_plugin_id: Optional[str] = None
    priority: str = "MEDIUM"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    status: str = "PLANNED"  # 'DRAFT', 'PLANNED', 'IN_PROGRESS', 'BLOCKED', 'COMPLETED', 'CANCELLED'
    owner_user_id: Optional[int] = None
    due_date: Optional[datetime] = None
    tags: List[str] = []
    scope_host_ips: List[str] = []
    scope_plugin_ids: List[str] = []


class ActionPlanCreate(ActionPlanBase):
    initial_tasks: Optional[List[ActionTaskCreate]] = None
    auto_link_vulnerabilities: bool = True
    tags: Optional[List[str]] = None
    scope_host_ips: Optional[List[str]] = None
    scope_plugin_ids: Optional[List[str]] = None


class ActionPlanUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    asset_group_id: Optional[int] = None
    scope_type: Optional[str] = None
    target_host_id: Optional[int] = None
    target_host_ip: Optional[str] = None
    target_plugin_id: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    owner_user_id: Optional[int] = None
    due_date: Optional[datetime] = None
    tags: Optional[List[str]] = None
    scope_host_ips: Optional[List[str]] = None
    scope_plugin_ids: Optional[List[str]] = None


class ActionPlanOut(ActionPlanBase):
    id: int
    asset_group_name: Optional[str] = None
    target_host_ip: Optional[str] = None
    target_host_name: Optional[str] = None
    owner_user_name: Optional[str] = None
    created_by_username: str
    total_tasks: int = 0
    completed_tasks: int = 0
    progress_percent: float = 0.0
    is_overdue: bool = False
    tags: List[str] = []
    scope_host_ips: List[str] = []
    scope_plugin_ids: List[str] = []
    tasks: List[ActionTaskOut] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ActionPlanPreviewImpactIn(BaseModel):
    scope_type: str = "CUSTOM"  # 'HOST', 'VULNERABILITY', 'GROUP', 'MATRIX_NN', 'CUSTOM'
    asset_group_id: Optional[int] = None
    target_host_id: Optional[int] = None
    target_host_ip: Optional[str] = None
    target_plugin_id: Optional[str] = None
    scope_host_ips: Optional[List[str]] = None
    scope_plugin_ids: Optional[List[str]] = None
    plan_id: Optional[int] = None


class ActionPlanPreviewImpactOut(BaseModel):
    total_affected_vulns: int = 0
    total_affected_hosts: int = 0
    total_vulnerabilities: int = 0
    unique_hosts_count: int = 0
    unique_plugins_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    severity_distribution: Dict[str, int] = {}
    already_in_plan_count: int = 0
    unassigned_count: int = 0
    is_relational_valid: bool = True
    unmatched_hosts: List[str] = []
    unmatched_plugins: List[str] = []
    validation_message: Optional[str] = None


class ActionPlanStatsOut(BaseModel):
    total_plans: int = 0
    planned_count: int = 0
    in_progress_count: int = 0
    completed_count: int = 0
    blocked_count: int = 0
    overdue_count: int = 0
    total_tasks: int = 0
    completed_tasks: int = 0
    overall_progress_percent: float = 0.0


class ActionPlanAssigneeOut(BaseModel):
    id: int
    username: str
    full_name: Optional[str] = None
    role: str

    model_config = ConfigDict(from_attributes=True)


class ActionPlanWizardHostOut(BaseModel):
    id: Optional[int] = None
    ip: str
    hostname: str = ""
    os: Optional[str] = ""
    asset_group_id: Optional[int] = None
    asset_group_name: str = "Global"
    vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class ActionPlanWizardVulnOut(BaseModel):
    plugin_id: str
    plugin_name: str
    severity: str = "Medium"
    cve: str = ""
    affected_hosts_count: int = 0


# --- Scanner Integration Schemas (Tenable & Microsoft Defender) ---
class ScannerIntegrationBase(BaseModel):
    asset_group_id: int
    name: str
    scanner_type: str = "tenable_io"  # 'tenable_io', 'tenable_sc', 'tenable_nessus_pro', 'ms_defender'
    is_enabled: bool = True
    api_endpoint: Optional[str] = None
    verify_ssl: bool = True
    auth_type: str = "api_keys"  # 'api_keys', 'oauth_client_credentials'
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    target_scope_filter: Optional[str] = None
    schedule_type: str = "manual"  # 'manual', 'interval', 'daily', 'weekly'
    interval_hours: int = 24
    schedule_time: Optional[str] = "02:00"
    schedule_days: Optional[str] = "1,2,3,4,5"


class ScannerIntegrationCreate(ScannerIntegrationBase):
    use_credentials_from_id: Optional[int] = None


class ScannerIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    scanner_type: Optional[str] = None
    is_enabled: Optional[bool] = None
    api_endpoint: Optional[str] = None
    verify_ssl: Optional[bool] = None
    auth_type: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    target_scope_filter: Optional[str] = None
    schedule_type: Optional[str] = None
    interval_hours: Optional[int] = None
    schedule_time: Optional[str] = None
    schedule_days: Optional[str] = None
    use_credentials_from_id: Optional[int] = None


class ScannerIntegrationOut(BaseModel):
    id: int
    asset_group_id: int
    asset_group_name: Optional[str] = None
    name: str
    scanner_type: str
    scanner_type_label: str = ""
    is_enabled: bool
    api_endpoint: Optional[str] = None
    verify_ssl: bool
    auth_type: str
    access_key_masked: Optional[str] = None
    has_secret_key: bool = False
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    has_client_secret: bool = False
    target_scope_filter: Optional[str] = None
    schedule_type: str
    schedule_type_label: str = ""
    interval_hours: int
    schedule_time: Optional[str] = None
    schedule_days: Optional[str] = None
    last_sync_status: str
    last_sync_at: Optional[datetime] = None
    last_sync_at_formatted: Optional[str] = None
    last_sync_message: Optional[str] = None
    last_synced_scan_id: Optional[int] = None
    vulnerabilities_imported_count: int = 0
    hosts_imported_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SavedCredentialOption(BaseModel):
    id: int
    name: str
    scanner_type: str
    scanner_type_label: str = ""
    api_endpoint: Optional[str] = None
    account_identifier: Optional[str] = None
    tenant_id: Optional[str] = None
    has_secret: bool = True
    verify_ssl: bool = True
    asset_group_name: Optional[str] = None


class ScannerIntegrationTestRequest(BaseModel):
    scanner_type: str
    api_endpoint: Optional[str] = None
    verify_ssl: bool = True
    auth_type: str = "api_keys"
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    use_credentials_from_id: Optional[int] = None


class ScannerIntegrationTestResponse(BaseModel):
    success: bool
    status_code: int
    message: str
    details: Optional[Dict[str, Any]] = None


class ScannerSyncResponse(BaseModel):
    success: bool
    status: str
    message: str
    scan_id: Optional[int] = None
    hosts_count: int = 0
    vulnerabilities_count: int = 0
    duration_seconds: float = 0.0


# --- Import Job Queue Schemas ---
class ImportJobOut(BaseModel):
    id: int
    job_type: str
    job_type_label: str = ""
    status: str
    status_label: str = ""
    progress_percent: int = 0
    progress_message: Optional[str] = None
    asset_group_id: int
    asset_group_name: Optional[str] = None
    created_by_username: str
    integration_id: Optional[int] = None
    scan_id: Optional[int] = None
    filename: Optional[str] = None
    file_size_bytes: int = 0
    scan_name: Optional[str] = None
    scan_type: str = "baseline"
    hosts_count: int = 0
    findings_count: int = 0
    result_summary: Optional[str] = None
    error_message: Optional[str] = None
    duration_seconds: float = 0.0
    queued_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ImportJobEnqueueResponse(BaseModel):
    job_id: int
    status: str
    message: str
    job_type: str = "csv_upload"
    asset_group_id: int


class ImportJobCancelResponse(BaseModel):
    success: bool
    message: str







