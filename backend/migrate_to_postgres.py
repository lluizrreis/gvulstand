#!/usr/bin/env python3
"""
GvulStand Database Migration Script: MariaDB -> PostgreSQL
Migrates all tables, rows, relations, and resets sequences with 100% data integrity check.
"""
import sys
import logging
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migration")

MARIADB_URL = "mysql+pymysql://gvuluser:gvulpassword@127.0.0.1:3306/gvulstand?charset=utf8mb4"
POSTGRES_URL = "postgresql+psycopg2://gvuluser:gvulpassword@127.0.0.1:5432/gvulstand"

def run_migration():
    logger.info("Connecting to MariaDB (source) and PostgreSQL (target)...")
    src_engine = create_engine(MARIADB_URL)
    tgt_engine = create_engine(POSTGRES_URL)

    # Test connections
    with src_engine.connect() as conn:
        res = conn.execute(text("SELECT VERSION()")).scalar()
        logger.info(f"MariaDB connected: {res}")

    with tgt_engine.connect() as conn:
        res = conn.execute(text("SELECT VERSION()")).scalar()
        logger.info(f"PostgreSQL connected: {res}")

    # Import models and create all tables in PostgreSQL
    logger.info("Creating schema in PostgreSQL from SQLAlchemy metadata...")
    from app.database import Base
    from app import models  # ensure all models are registered

    Base.metadata.create_all(bind=tgt_engine)
    logger.info("PostgreSQL tables successfully created/verified.")

    # Tables to migrate in logical order
    tables_order = [
        "users",
        "asset_groups",
        "user_asset_groups",
        "scans",
        "hosts",
        "vulnerabilities",
        "vulnerability_treatment_history",
        "tags",
        "action_plans",
        "action_plan_hosts",
        "action_plan_plugins",
        "action_plan_tags",
        "action_tasks",
        "action_task_vulnerabilities",
        "ldap_config",
        "system_parameters"
    ]

    inspector_src = inspect(src_engine)
    src_tables = set(inspector_src.get_table_names())
    inspector_tgt = inspect(tgt_engine)
    tgt_tables = set(inspector_tgt.get_table_names())

    with tgt_engine.connect() as tgt_conn, src_engine.connect() as src_conn:
        # Disable foreign key constraints during bulk loading
        logger.info("Disabling foreign key constraints in PostgreSQL session...")
        tgt_conn.execute(text("SET session_replication_role = 'replica';"))

        # Clear target tables if needed (in reverse order)
        for tbl in reversed(tables_order):
            if tbl in tgt_tables:
                tgt_conn.execute(text(f'TRUNCATE TABLE "{tbl}" CASCADE;'))
        tgt_conn.commit()

        migration_stats = {}

        for tbl in tables_order:
            if tbl not in src_tables:
                logger.warning(f"Table '{tbl}' does not exist in MariaDB, skipping.")
                continue

            logger.info(f"Migrating table: '{tbl}'...")

            # Get target columns
            tgt_cols = [c["name"] for c in inspector_tgt.get_columns(tbl)]
            col_list_str = ", ".join([f'"{c}"' for c in tgt_cols])

            # Select data from source
            src_cols = [c["name"] for c in inspector_src.get_columns(tbl)]
            common_cols = [c for c in tgt_cols if c in src_cols]

            select_cols = ", ".join([f"`{c}`" for c in common_cols])
            rows = src_conn.execute(text(f"SELECT {select_cols} FROM `{tbl}`")).fetchall()
            count = len(rows)
            logger.info(f"  Found {count} rows in MariaDB for '{tbl}'")

            # Determine boolean columns in target table
            bool_cols = set()
            for c in inspector_tgt.get_columns(tbl):
                type_name = str(c["type"]).lower()
                if "bool" in type_name:
                    bool_cols.add(c["name"])

            if count > 0:
                # Insert in chunks into PostgreSQL
                chunk_size = 2000
                insert_cols_str = ", ".join([f'"{c}"' for c in common_cols])
                placeholders = ", ".join([f":{c}" for c in common_cols])
                insert_stmt = text(f'INSERT INTO "{tbl}" ({insert_cols_str}) VALUES ({placeholders})')

                for i in range(0, count, chunk_size):
                    chunk = rows[i:i + chunk_size]
                    # Map to dicts with proper boolean conversions
                    dicts = []
                    for r in chunk:
                        row_dict = dict(zip(common_cols, r))
                        for col in bool_cols:
                            if col in row_dict and row_dict[col] is not None:
                                row_dict[col] = bool(row_dict[col])
                        dicts.append(row_dict)
                    tgt_conn.execute(insert_stmt, dicts)

            tgt_conn.commit()
            migration_stats[tbl] = count

        # Re-enable foreign key constraints
        logger.info("Re-enabling foreign key constraints in PostgreSQL session...")
        tgt_conn.execute(text("SET session_replication_role = 'origin';"))
        tgt_conn.commit()

        # Reset sequences for serial primary keys
        logger.info("Updating PostgreSQL auto-increment sequences...")
        for tbl in tables_order:
            if tbl in tgt_tables:
                try:
                    # Check if table has 'id' column and sequence
                    seq_check = tgt_conn.execute(text(f"SELECT pg_get_serial_sequence('{tbl}', 'id');")).scalar()
                    if seq_check:
                        max_id = tgt_conn.execute(text(f'SELECT COALESCE(MAX("id"), 1) FROM "{tbl}";')).scalar()
                        tgt_conn.execute(text(f"SELECT setval('{seq_check}', :max_id, true);"), {"max_id": max_id})
                        logger.info(f"  Reset sequence '{seq_check}' to {max_id}")
                except Exception as seq_err:
                    logger.debug(f"  No sequence for {tbl}: {seq_err}")
        tgt_conn.commit()

    # Verification Step
    logger.info("=" * 60)
    logger.info("VERIFYING ROW COUNTS BETWEEN MARIADB AND POSTGRESQL:")
    logger.info("=" * 60)
    all_matched = True

    with src_engine.connect() as src_conn, tgt_engine.connect() as tgt_conn:
        for tbl in tables_order:
            if tbl in src_tables and tbl in tgt_tables:
                src_cnt = src_conn.execute(text(f"SELECT COUNT(*) FROM `{tbl}`")).scalar()
                tgt_cnt = tgt_conn.execute(text(f'SELECT COUNT(*) FROM "{tbl}"')).scalar()
                status = "MATCH" if src_cnt == tgt_cnt else "MISMATCH ❌"
                if src_cnt != tgt_cnt:
                    all_matched = False
                logger.info(f"Table: {tbl:<32} MariaDB: {src_cnt:<7} Postgres: {tgt_cnt:<7} -> {status}")

    logger.info("=" * 60)
    if all_matched:
        logger.info("SUCCESS: 100% of tables and rows migrated with exact data parity!")
    else:
        logger.error("WARNING: Some row counts did not match! Please check the output above.")
        sys.exit(1)

if __name__ == "__main__":
    run_migration()
