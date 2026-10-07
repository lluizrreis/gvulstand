from sqlalchemy import create_engine, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Connect args for SQLite vs MariaDB/MySQL
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from app import models
    from app.auth import get_password_hash
    
    # Create all tables if they don't exist
    Base.metadata.create_all(bind=engine)

    # Check and migrate schema if parent_id is missing in asset_groups
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        if "asset_groups" in inspector.get_table_names():
            columns = [col["name"] for col in inspector.get_columns("asset_groups")]
            if "parent_id" not in columns:
                logger.info("Migrating schema: adding parent_id column to asset_groups table...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE asset_groups ADD COLUMN parent_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL"))
                    conn.commit()
                logger.info("Column parent_id successfully added to asset_groups.")

        if "vulnerabilities" in inspector.get_table_names():
            vuln_cols = [col["name"] for col in inspector.get_columns("vulnerabilities")]
            missing_vuln_cols = {
                "exploited_by_malware": "BOOLEAN DEFAULT FALSE",
                "stig_severity": "VARCHAR(50)",
                "risk_factor": "VARCHAR(50)",
                "vpr": "FLOAT",
                "patch_available": "BOOLEAN DEFAULT FALSE",
                "plugin_type": "VARCHAR(50)",
                "first_found": "TIMESTAMP",
                "last_found": "TIMESTAMP",
                "treated_by_username": "VARCHAR(100)",
                "treated_at": "TIMESTAMP"
            }
            with engine.connect() as conn:
                for col_name, col_type in missing_vuln_cols.items():
                    if col_name not in vuln_cols:
                        logger.info(f"Migrating schema: adding {col_name} column to vulnerabilities table...")
                        conn.execute(text(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}"))
                conn.commit()
        if "users" in inspector.get_table_names():
            user_cols = [col["name"] for col in inspector.get_columns("users")]
            with engine.connect() as conn:
                if "auth_type" not in user_cols:
                    logger.info("Migrating schema: adding auth_type column to users table...")
                    conn.execute(text("ALTER TABLE users ADD COLUMN auth_type VARCHAR(20) DEFAULT 'local'"))
                    conn.commit()
                if "sam_account_name" not in user_cols:
                    logger.info("Migrating schema: adding sam_account_name column to users table...")
                    conn.execute(text("ALTER TABLE users ADD COLUMN sam_account_name VARCHAR(100)"))
                    conn.commit()
        if "scanner_integrations" in inspector.get_table_names():
            with engine.connect() as conn:
                try:
                    conn.execute(text("ALTER TABLE scanner_integrations ALTER COLUMN access_key TYPE TEXT"))
                    conn.execute(text("ALTER TABLE scanner_integrations ALTER COLUMN secret_key TYPE TEXT"))
                    conn.execute(text("ALTER TABLE scanner_integrations ALTER COLUMN client_secret TYPE TEXT"))
                    conn.commit()
                except Exception as e:
                    logger.debug(f"scanner_integrations column type alter: {e}")
    except Exception as e:
        logger.warning(f"Note on migration check: {e}")
    
    db: Session = SessionLocal()
    try:
        # Check and migrate plaintext credentials in scanner_integrations to Fernet encryption
        try:
            from app.crypto_utils import is_encrypted, encrypt_secret
            integrations = db.query(models.ScannerIntegration).all()
            migrated_count = 0
            for integ in integrations:
                modified = False
                if integ.access_key and not is_encrypted(integ.access_key):
                    integ.access_key = encrypt_secret(integ.access_key.strip())
                    modified = True
                if integ.secret_key and not is_encrypted(integ.secret_key):
                    integ.secret_key = encrypt_secret(integ.secret_key.strip())
                    modified = True
                if integ.client_secret and not is_encrypted(integ.client_secret):
                    integ.client_secret = encrypt_secret(integ.client_secret.strip())
                    modified = True
                if modified:
                    migrated_count += 1
            if migrated_count > 0:
                db.commit()
                logger.info(f"Criptografadas com sucesso as credenciais em {migrated_count} integração(ões) de scanner.")
        except Exception as mig_err:
            logger.warning(f"Erro ao verificar/migrar credenciais de scanners para Fernet: {mig_err}")
        # Check and initialize default LDAP config
        ldap_cfg = db.query(models.LdapConfig).filter(models.LdapConfig.id == 1).first()
        if not ldap_cfg:
            logger.info("Initializing default LDAP configuration (disabled)...")
            ldap_cfg = models.LdapConfig(
                id=1,
                is_enabled=False,
                server_host="",
                server_port=389,
                use_ssl=False,
                use_starttls=False,
                bind_user="",
                bind_password="",
                base_dn="",
                user_search_filter="(&(objectClass=user)(sAMAccountName={username}))",
                sam_attribute="sAMAccountName",
                name_attribute="displayName",
                email_attribute="mail",
                connection_timeout=5
            )
            db.add(ldap_cfg)
            db.commit()

        # Check and initialize default System Parameters
        sys_params = db.query(models.SystemParameters).filter(models.SystemParameters.id == 1).first()
        if not sys_params:
            logger.info("Initializing default System Parameters...")
            sys_params = models.SystemParameters(
                id=1,
                timezone="America/Sao_Paulo",
                sla_critical_days=settings.DEFAULT_SLA_CRITICAL_DAYS,
                sla_high_days=settings.DEFAULT_SLA_HIGH_DAYS,
                sla_medium_days=settings.DEFAULT_SLA_MEDIUM_DAYS,
                sla_low_days=settings.DEFAULT_SLA_LOW_DAYS,
                ignored_vulnerability_ids="",
                updated_by_username="Sistema"
            )
            db.add(sys_params)
            db.commit()
            logger.info("Default System Parameters initialized successfully.")
        # Check if Admin user exists
        admin_user = db.query(models.User).filter(models.User.username == settings.DEFAULT_ADMIN_USERNAME).first()
        if not admin_user:
            logger.info(f"Creating default admin user: {settings.DEFAULT_ADMIN_USERNAME}")
            admin_user = models.User(
                username=settings.DEFAULT_ADMIN_USERNAME,
                email=settings.DEFAULT_ADMIN_EMAIL,
                full_name="Administrador do Sistema",
                hashed_password=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
                role="admin",
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            logger.info("Default admin user created successfully.")

        # Check if Analyst user exists
        analyst_user = db.query(models.User).filter(func.lower(models.User.username) == "analista").first()
        if not analyst_user:
            logger.info("Creating default analyst user: analista")
            analyst_user = models.User(
                username="analista",
                email="analista@gvulstand.local",
                full_name="Analista de Segurança",
                hashed_password=get_password_hash("analista"),
                role="analyst",
                is_active=True
            )
            db.add(analyst_user)
            db.commit()
            logger.info("Default analyst user created successfully.")

        # Check if Auditor user exists
        auditor_user = db.query(models.User).filter(func.lower(models.User.username) == "auditor").first()
        if not auditor_user:
            logger.info("Creating default auditor user: auditor")
            auditor_user = models.User(
                username="auditor",
                email="auditor@gvulstand.local",
                full_name="Auditor ISO 27001 / 9001",
                hashed_password=get_password_hash("auditor"),
                role="auditor",
                is_active=True
            )
            db.add(auditor_user)
            db.commit()
            logger.info("Default auditor user created successfully.")
            
        # Create default Asset Groups if empty
        if db.query(models.AssetGroup).count() == 0:
            default_groups = [
                models.AssetGroup(
                    name="Datacenter Core & Servidores",
                    description="Servidores de infraestrutura central, banco de dados e virtualizadores",
                    network_range="10.10.0.0/24, 10.10.1.0/24",
                    owner="Equipe de Infraestrutura",
                    sla_critical_days=7,
                    sla_high_days=15,
                    sla_medium_days=30,
                    sla_low_days=60
                ),
                models.AssetGroup(
                    name="DMZ / Web Applications",
                    description="Aplicações expostas à Internet, portais, APIs e balanceadores",
                    network_range="172.16.10.0/24",
                    owner="Equipe de Segurança & Web",
                    sla_critical_days=3,
                    sla_high_days=7,
                    sla_medium_days=20,
                    sla_low_days=45
                ),
                models.AssetGroup(
                    name="Rede Corporativa / Endpoints",
                    description="Estações de trabalho, notebooks e dispositivos de usuários finais",
                    network_range="192.168.1.0/24, 192.168.2.0/24",
                    owner="Suporte de TI",
                    sla_critical_days=15,
                    sla_high_days=30,
                    sla_medium_days=60,
                    sla_low_days=90
                )
            ]
            db.add_all(default_groups)
            db.commit()
            logger.info("Default asset groups created.")

        # Clean up any jobs that were orphaned in 'running' state due to container restart
        try:
            orphaned_jobs = db.query(models.ImportJob).filter(models.ImportJob.status == "running").all()
            for oj in orphaned_jobs:
                oj.status = "failed"
                oj.progress_message = "Processamento interrompido por reinicialização do servidor/container."
                oj.error_message = "Servidor reiniciado enquanto a tarefa estava em execução."
                oj.completed_at = models.utc_now()
            if orphaned_jobs:
                db.commit()
                logger.info(f"Limpeza de inicialização: {len(orphaned_jobs)} tarefas órfãs marcadas como falhas.")
        except Exception as job_clean_err:
            logger.warning(f"Aviso ao verificar jobs órfãos: {job_clean_err}")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")
        db.rollback()
    finally:
        db.close()
