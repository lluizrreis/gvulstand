from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), default="analyst", nullable=False) # admin, analyst, auditor
    is_active = Column(Boolean, default=True, nullable=False)
    auth_type = Column(String(20), default="local", nullable=False) # 'local' or 'ldap'
    sam_account_name = Column(String(100), index=True, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    asset_group_permissions = relationship("UserAssetGroup", back_populates="user", cascade="all, delete-orphan")

class AssetGroup(Base):
    __tablename__ = "asset_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    network_range = Column(String(255), nullable=True)
    owner = Column(String(100), nullable=True)
    sla_critical_days = Column(Integer, default=7, nullable=False)
    sla_high_days = Column(Integer, default=15, nullable=False)
    sla_medium_days = Column(Integer, default=30, nullable=False)
    sla_low_days = Column(Integer, default=60, nullable=False)
    parent_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    parent = relationship("AssetGroup", remote_side=[id], backref="subgroups")
    scans = relationship("Scan", back_populates="asset_group", cascade="all, delete-orphan")
    hosts = relationship("Host", back_populates="asset_group", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="asset_group", cascade="all, delete-orphan")
    user_permissions = relationship("UserAssetGroup", back_populates="asset_group", cascade="all, delete-orphan")
    scanner_integrations = relationship("ScannerIntegration", back_populates="asset_group", cascade="all, delete-orphan")
    import_jobs = relationship("ImportJob", back_populates="asset_group", cascade="all, delete-orphan")

class UserAssetGroup(Base):
    __tablename__ = "user_asset_groups"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True)

    can_treat = Column(Boolean, default=True, nullable=False)   # Permissão de Tratamento de Vulnerabilidades (ISO 27001)
    can_import = Column(Boolean, default=True, nullable=False)  # Permissão de Importação de Scans Nessus
    can_author = Column(Boolean, default=True, nullable=False)  # Permissão de Emissão e Autoria de Relatórios

    created_at = Column(DateTime, default=utc_now, nullable=False)

    user = relationship("User", back_populates="asset_group_permissions")
    asset_group = relationship("AssetGroup", back_populates="user_permissions")

    __table_args__ = (
        Index("ix_user_asset_group_unique", "user_id", "asset_group_id", unique=True),
    )

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    asset_group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_name = Column(String(150), nullable=False)
    scan_type = Column(String(50), default="baseline", nullable=False) # 'baseline' (Antes) or 'retest' (Depois/Pós-Tratativa)
    filename = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, default=0)
    
    total_hosts = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    exploitable_critical_count = Column(Integer, default=0)
    
    scan_date = Column(DateTime, default=utc_now, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    notes = Column(Text, nullable=True)

    asset_group = relationship("AssetGroup", back_populates="scans")
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    
    ip_address = Column(String(100), index=True, nullable=False)
    hostname = Column(String(255), nullable=True)
    netbios_name = Column(String(255), nullable=True)
    mac_address = Column(Text, nullable=True)
    os = Column(String(500), nullable=True)
    
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    exploitable_critical_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)

    scan = relationship("Scan", back_populates="hosts")
    asset_group = relationship("AssetGroup", back_populates="hosts")
    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_hosts_scan_ip", "scan_id", "ip_address"),
    )

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    
    plugin_id = Column(String(50), index=True, nullable=False)
    plugin_name = Column(String(500), nullable=False)
    cve = Column(Text, nullable=True)
    cvss_v3 = Column(Float, nullable=True)
    cvss_v2 = Column(Float, nullable=True)
    severity = Column(String(20), index=True, nullable=False) # Critical, High, Medium, Low, Info/None
    
    port = Column(Integer, default=0)
    protocol = Column(String(50), default="tcp")
    
    synopsis = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    solution = Column(Text, nullable=True)
    see_also = Column(Text, nullable=True)
    plugin_output = Column(Text, nullable=True)
    
    exploit_available = Column(Boolean, default=False, index=True)
    exploit_frameworks = Column(String(500), nullable=True)
    exploited_by_malware = Column(Boolean, default=False)
    stig_severity = Column(String(50), nullable=True)
    risk_factor = Column(String(50), nullable=True)
    vpr = Column(Float, nullable=True)
    patch_available = Column(Boolean, default=False)
    plugin_type = Column(String(50), nullable=True)
    
    # Aging & Detection timestamps
    first_found = Column(DateTime, nullable=True)
    last_found = Column(DateTime, nullable=True)
    
    # ISO 27001 Treatment Lifecycle & Audit Trail (Quem e Quando)
    treatment_status = Column(String(30), default="Open", nullable=False) # Open, In_Remediation, Accepted_Risk, Remediated
    treatment_notes = Column(Text, nullable=True)
    treated_by_username = Column(String(100), nullable=True)
    treated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("Scan", back_populates="vulnerabilities")
    host = relationship("Host", back_populates="vulnerabilities")
    asset_group = relationship("AssetGroup", back_populates="vulnerabilities")
    treatment_history = relationship(
        "VulnerabilityTreatmentHistory",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
        order_by="VulnerabilityTreatmentHistory.changed_at.desc()"
    )

    __table_args__ = (
        Index("ix_vuln_scan_severity", "scan_id", "severity"),
        Index("ix_vuln_exploit_crit", "severity", "exploit_available"),
    )

class VulnerabilityTreatmentHistory(Base):
    """
    Histórico de auditoria de todas as alterações de tratamento de uma vulnerabilidade (ISO 27001).
    Registra cada mudança de status com: quem alterou, quando e a justificativa/nota de auditoria.
    """
    __tablename__ = "vulnerability_treatment_history"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)

    # Snapshot do estado após a alteração
    treatment_status = Column(String(30), nullable=False)    # Open, In_Remediation, Accepted_Risk, Remediated
    treatment_notes = Column(Text, nullable=False)           # Nota obrigatória de auditoria/justificativa

    # Audit trail: quem fez e quando
    changed_by_username = Column(String(100), nullable=False)
    changed_at = Column(DateTime, default=utc_now, nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="treatment_history")

    __table_args__ = (
        Index("ix_treatment_history_vuln_id", "vulnerability_id", "changed_at"),
    )


class LdapConfig(Base):
    __tablename__ = "ldap_config"

    id = Column(Integer, primary_key=True, default=1)
    is_enabled = Column(Boolean, default=False, nullable=False)
    server_host = Column(String(255), nullable=True)
    server_port = Column(Integer, default=389, nullable=False)
    use_ssl = Column(Boolean, default=False, nullable=False)
    use_starttls = Column(Boolean, default=False, nullable=False)
    bind_user = Column(String(255), nullable=True)
    bind_password = Column(String(255), nullable=True)
    base_dn = Column(String(255), nullable=True)
    user_search_filter = Column(String(255), default="(&(objectClass=user)(sAMAccountName={username}))", nullable=False)
    sam_attribute = Column(String(50), default="sAMAccountName", nullable=False)
    name_attribute = Column(String(50), default="displayName", nullable=False)
    email_attribute = Column(String(50), default="mail", nullable=False)
    connection_timeout = Column(Integer, default=5, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class SystemParameters(Base):
    """
    Parametrizações pontuais globais do sistema:
    1. Fuso horário operacional para atualização e registro das informações salvas
    2. Prazos padrão de SLA por severidade (Críticas, Altas, Médias e Baixas)
    3. IDs das vulnerabilidades automaticamente ignoradas nos indicadores (Classificação de Falso-Positivo)
    """
    __tablename__ = "system_parameters"

    id = Column(Integer, primary_key=True, default=1)
    timezone = Column(String(50), default="America/Sao_Paulo", nullable=False)

    # SLA padrão global (em dias)
    sla_critical_days = Column(Integer, default=7, nullable=False)
    sla_high_days = Column(Integer, default=15, nullable=False)
    sla_medium_days = Column(Integer, default=30, nullable=False)
    sla_low_days = Column(Integer, default=60, nullable=False)

    # IDs de vulnerabilidades ignoradas nos indicadores (Falsos-Positivos)
    # Lista delimitada por vírgula, ponto e vírgula, espaço ou nova linha
    ignored_vulnerability_ids = Column(Text, default="", nullable=False)

    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    updated_by_username = Column(String(100), nullable=True)


class ActionPlan(Base):
    """
    Representa o Plano de Ação ou Projeto de Remediação (GvulStand Action Plans).
    Permite agrupar esforços de correção por Host, por Vulnerabilidade (Plugin/CVE),
    por Grupo de Ativos ou Customizado, atendendo ISO 27001 (Controle 8.8) e PDCA ISO 9001.
    """
    __tablename__ = "action_plans"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    asset_group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="SET NULL"), nullable=True, index=True)
    scope_type = Column(String(50), default="CUSTOM", nullable=False) # 'HOST', 'VULNERABILITY', 'GROUP', 'CUSTOM'
    target_host_id = Column(Integer, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True, index=True)
    target_plugin_id = Column(String(50), nullable=True, index=True)
    priority = Column(String(30), default="MEDIUM", nullable=False) # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    status = Column(String(30), default="PLANNED", nullable=False) # 'DRAFT', 'PLANNED', 'IN_PROGRESS', 'BLOCKED', 'COMPLETED', 'CANCELLED'
    created_by_username = Column(String(100), nullable=False)
    owner_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    due_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    asset_group = relationship("AssetGroup")
    target_host = relationship("Host")
    owner_user = relationship("User", foreign_keys=[owner_user_id])
    tasks = relationship("ActionTask", back_populates="action_plan", cascade="all, delete-orphan", order_by="ActionTask.order_index")
    tag_links = relationship("ActionPlanTagLink", back_populates="action_plan", cascade="all, delete-orphan")
    scope_hosts = relationship("ActionPlanHost", back_populates="action_plan", cascade="all, delete-orphan")
    scope_plugins = relationship("ActionPlanPlugin", back_populates="action_plan", cascade="all, delete-orphan")


class ActionTask(Base):
    """
    Etapa ou Tarefa pertencente a um Plano de Ação de Remediação.
    Possui responsável direto, prazo e status (TODO, DOING, REVIEW, DONE, BLOCKED).
    """
    __tablename__ = "action_tasks"

    id = Column(Integer, primary_key=True, index=True)
    action_plan_id = Column(Integer, ForeignKey("action_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    order_index = Column(Integer, default=0, nullable=False)
    status = Column(String(30), default="TODO", nullable=False) # 'TODO', 'DOING', 'REVIEW', 'DONE', 'BLOCKED'
    assigned_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    start_date = Column(DateTime, nullable=True)
    due_date = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    action_plan = relationship("ActionPlan", back_populates="tasks")
    assigned_user = relationship("User", foreign_keys=[assigned_user_id])
    vulnerability_links = relationship("ActionTaskVulnerabilityLink", back_populates="task", cascade="all, delete-orphan")


class ActionTaskVulnerabilityLink(Base):
    """
    Tabela associativa ligando etapas/tarefas de remediação a vulnerabilidades concretas.
    Permite rastreabilidade cruzada e sincronização de tratativas.
    """
    __tablename__ = "action_task_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    action_task_id = Column(Integer, ForeignKey("action_tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)

    task = relationship("ActionTask", back_populates="vulnerability_links")
    vulnerability = relationship("Vulnerability")

    __table_args__ = (
        Index("ix_task_vuln_unique", "action_task_id", "vulnerability_id", unique=True),
    )


class Tag(Base):
    """
    Etiqueta/Tag para categorização transversal e governança de Planos de Ação (ex: SOX, PCI-DSS, Urgente, RedTeam).
    """
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, index=True, nullable=False)
    color_hex = Column(String(10), default="#6366f1", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    action_plan_links = relationship("ActionPlanTagLink", back_populates="tag", cascade="all, delete-orphan")


class ActionPlanTagLink(Base):
    """
    Associação N:N entre Planos de Ação e Tags.
    """
    __tablename__ = "action_plan_tags"

    id = Column(Integer, primary_key=True, index=True)
    action_plan_id = Column(Integer, ForeignKey("action_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    tag_id = Column(Integer, ForeignKey("tags.id", ondelete="CASCADE"), nullable=False, index=True)

    action_plan = relationship("ActionPlan", back_populates="tag_links")
    tag = relationship("Tag", back_populates="action_plan_links")

    __table_args__ = (
        Index("ix_plan_tag_unique", "action_plan_id", "tag_id", unique=True),
    )


class ActionPlanHost(Base):
    """
    Associação de múltiplos hosts em planos com escopo matricial N:N (MATRIX_NN).
    """
    __tablename__ = "action_plan_hosts"

    id = Column(Integer, primary_key=True, index=True)
    action_plan_id = Column(Integer, ForeignKey("action_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True, index=True)
    host_ip = Column(String(100), nullable=False, index=True)

    action_plan = relationship("ActionPlan", back_populates="scope_hosts")
    host = relationship("Host")

    __table_args__ = (
        Index("ix_plan_host_unique", "action_plan_id", "host_ip", unique=True),
    )


class ActionPlanPlugin(Base):
    """
    Associação de múltiplos plugins/vulnerabilidades em planos com escopo matricial N:N (MATRIX_NN).
    """
    __tablename__ = "action_plan_plugins"

    id = Column(Integer, primary_key=True, index=True)
    action_plan_id = Column(Integer, ForeignKey("action_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    plugin_id = Column(String(50), nullable=False, index=True)
    cve = Column(Text, nullable=True)

    action_plan = relationship("ActionPlan", back_populates="scope_plugins")

    __table_args__ = (
        Index("ix_plan_plugin_unique", "action_plan_id", "plugin_id", unique=True),
    )


class ScannerIntegration(Base):
    """
    Configuração de integração com scanners de vulnerabilidades via API
    (Tenable.io, Tenable.sc, Nessus Professional e Microsoft Defender for Endpoint / MDVM).
    Permite agendamento periódico de importação por Grupo de Ativos.
    """
    __tablename__ = "scanner_integrations"

    id = Column(Integer, primary_key=True, index=True)
    asset_group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(150), nullable=False)
    scanner_type = Column(String(50), nullable=False)  # 'tenable_io', 'tenable_sc', 'tenable_nessus_pro', 'ms_defender'
    is_enabled = Column(Boolean, default=True, nullable=False)

    # API Connection Settings
    api_endpoint = Column(String(255), nullable=True)  # ex: https://cloud.tenable.com ou https://api.securitycenter.microsoft.com
    verify_ssl = Column(Boolean, default=True, nullable=False)
    auth_type = Column(String(50), default="api_keys", nullable=False)  # 'api_keys', 'oauth_client_credentials'

    # Tenable / OpenVAS API Credentials (cifrados com Fernet)
    access_key = Column(Text, nullable=True)
    secret_key = Column(Text, nullable=True)

    # Microsoft Defender Credentials (Entra ID)
    tenant_id = Column(String(100), nullable=True)
    client_id = Column(String(100), nullable=True)
    client_secret = Column(Text, nullable=True)

    def get_decrypted_access_key(self) -> Optional[str]:
        from app.crypto_utils import safe_decrypt_secret
        return safe_decrypt_secret(self.access_key)

    def get_decrypted_secret_key(self) -> Optional[str]:
        from app.crypto_utils import safe_decrypt_secret
        return safe_decrypt_secret(self.secret_key)

    def get_decrypted_client_secret(self) -> Optional[str]:
        from app.crypto_utils import safe_decrypt_secret
        return safe_decrypt_secret(self.client_secret)

    # Filtering / Scope (ex: tag específica no Tenable ou machine group no Defender)
    target_scope_filter = Column(Text, nullable=True)

    # Scheduling
    schedule_type = Column(String(30), default="manual", nullable=False)  # 'manual', 'interval', 'daily', 'weekly'
    interval_hours = Column(Integer, default=24, nullable=False)
    schedule_time = Column(String(10), default="02:00", nullable=True)   # HH:MM (24h)
    schedule_days = Column(String(50), default="1,2,3,4,5", nullable=True)  # Dias da semana (1=Segunda, 7=Domingo)

    # Execution & Telemetry
    last_sync_status = Column(String(30), default="idle", nullable=False)  # 'idle', 'running', 'success', 'failed'
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_message = Column(Text, nullable=True)
    last_synced_scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    vulnerabilities_imported_count = Column(Integer, default=0, nullable=False)
    hosts_imported_count = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    asset_group = relationship("AssetGroup", back_populates="scanner_integrations")
    last_synced_scan = relationship("Scan")


class ImportJob(Base):
    """
    Fila de Trabalhos e Histórico de Importações (Opção A: Job Queue Nativa).
    Gerencia uploads assíncronos de CSV do Nessus e sincronizações via API (Tenable/Defender).
    Garante controle de concorrência, execução em ordem (FIFO) e telemetria de progresso em tempo real.
    """
    __tablename__ = "import_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_type = Column(String(50), nullable=False, index=True)  # 'csv_upload', 'api_sync'
    status = Column(String(30), default="queued", nullable=False, index=True)  # 'queued', 'running', 'completed', 'failed', 'cancelled'
    progress_percent = Column(Integer, default=0, nullable=False)
    progress_message = Column(Text, nullable=True)

    asset_group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by_username = Column(String(100), nullable=False)

    integration_id = Column(Integer, ForeignKey("scanner_integrations.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)

    # Parâmetros de importação CSV
    filename = Column(String(255), nullable=True)
    file_path = Column(String(500), nullable=True)
    file_size_bytes = Column(Integer, default=0)
    scan_name = Column(String(150), nullable=True)
    scan_type = Column(String(50), default="baseline", nullable=False)
    scan_date = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    # Métricas de execução
    hosts_count = Column(Integer, default=0, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    result_summary = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    duration_seconds = Column(Float, default=0.0, nullable=False)

    queued_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    asset_group = relationship("AssetGroup", back_populates="import_jobs")
    created_by_user = relationship("User")
    integration = relationship("ScannerIntegration")
    scan = relationship("Scan")

    __table_args__ = (
        Index("ix_import_jobs_status_queued", "status", "queued_at"),
    )


