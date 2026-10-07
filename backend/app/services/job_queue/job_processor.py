"""
GvulStand Native Job Processor (Opção A)
Executa tarefas de importação de CSV do Nessus e Sincronização de APIs em segundo plano,
com controle de concorrência, telemetria de progresso em tempo real e atualização de planos de ação.
"""
import os
import time
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import text

from app import models
from app.database import SessionLocal
from app.config import settings
from app.services.parser_nessus import parse_nessus_csv

logger = logging.getLogger("job_queue.processor")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def claim_next_queued_job(db: Session) -> Optional[int]:
    """
    Seleciona e aloca com segurança atômica a próxima tarefa pendente na fila (FIFO).
    No PostgreSQL utiliza 'FOR UPDATE SKIP LOCKED' para evitar qualquer condição de corrida entre workers.
    Retorna o job_id alocado ou None se não houver tarefas.
    """
    try:
        query = db.query(models.ImportJob).filter(models.ImportJob.status == "queued").order_by(models.ImportJob.queued_at.asc())
        if db.bind and getattr(db.bind.dialect, "name", "") == "postgresql":
            query = query.with_for_update(skip_locked=True)

        job = query.first()
        if not job:
            return None

        job.status = "running"
        job.started_at = utc_now()
        job.progress_percent = 5
        job.progress_message = "Alocado para processamento em segundo plano..."
        db.commit()
        return job.id
    except Exception as e:
        db.rollback()
        logger.error(f"Erro ao alocar próxima tarefa na fila: {e}", exc_info=True)
        return None


def execute_csv_import_job(db: Session, job: models.ImportJob) -> None:
    """
    Executa o parsing e inserção de dados de um arquivo CSV de scan Nessus.
    """
    start_time = time.time()
    logger.info(f"[Job #{job.id}] Iniciando importação CSV: {job.filename} (Grupo #{job.asset_group_id})")

    if not job.file_path or not os.path.isfile(job.file_path):
        raise FileNotFoundError(f"Arquivo de scan não encontrado no caminho: {job.file_path}")

    # 1. Leitura e Decodificação
    job.progress_percent = 10
    job.progress_message = "Lendo e decodificando arquivo CSV..."
    db.commit()

    with open(job.file_path, "rb") as f:
        content_bytes = f.read()

    file_size = len(content_bytes)
    job.file_size_bytes = file_size

    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content_str = content_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                content_str = content_bytes.decode("latin-1")
            except UnicodeDecodeError:
                content_str = content_bytes.decode("cp1252", errors="replace")

    # 2. Parsing do CSV Nessus
    job.progress_percent = 25
    job.progress_message = "Estruturando e validando colunas do Nessus CSV..."
    db.commit()

    parsed_data = parse_nessus_csv(content_str)
    hosts_data = parsed_data.get("hosts", {})
    findings_data = parsed_data.get("findings", [])
    stats = parsed_data.get("stats", {})

    total_hosts = len(hosts_data)
    total_findings = len(findings_data)

    job.progress_percent = 40
    job.progress_message = f"Mapeados {total_hosts} hosts e {total_findings} achados. Criando registro do Scan..."
    db.commit()

    # 3. Data do Scan
    parsed_scan_date = job.scan_date or utc_now()

    # 4. Criação do Registro de Scan
    scan = models.Scan(
        asset_group_id=job.asset_group_id,
        scan_name=job.scan_name or f"Scan Importado #{job.id}",
        scan_type=job.scan_type if job.scan_type in ["baseline", "retest"] else "baseline",
        filename=job.filename or os.path.basename(job.file_path),
        file_size_bytes=file_size,
        total_hosts=total_hosts,
        total_findings=total_findings,
        critical_count=stats.get("critical_count", 0),
        high_count=stats.get("high_count", 0),
        medium_count=stats.get("medium_count", 0),
        low_count=stats.get("low_count", 0),
        info_count=stats.get("info_count", 0),
        exploitable_critical_count=stats.get("exploitable_critical_count", 0),
        scan_date=parsed_scan_date,
        notes=job.notes
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    job.scan_id = scan.id
    db.commit()

    # 5. Criação dos Registros de Hosts
    job.progress_percent = 55
    job.progress_message = f"Persistindo inventário de {total_hosts} hosts..."
    db.commit()

    ip_to_host_id: Dict[str, int] = {}
    for ip, h_info in hosts_data.items():
        host = models.Host(
            scan_id=scan.id,
            asset_group_id=job.asset_group_id,
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

    # 6. Criação e Inserção em Lotes das Vulnerabilidades
    job.progress_percent = 70
    job.progress_message = f"Inserindo {total_findings} vulnerabilidades no banco de dados..."
    db.commit()

    vuln_objects = []
    for f in findings_data:
        host_id = ip_to_host_id.get(f.get("host_ip"))
        if not host_id:
            continue
        vuln = models.Vulnerability(
            scan_id=scan.id,
            host_id=host_id,
            asset_group_id=job.asset_group_id,
            plugin_id=str(f.get("plugin_id") or "0"),
            plugin_name=f.get("plugin_name") or "Vulnerabilidade sem título",
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
            vpr=f.get("vpr"),
            patch_available=f.get("patch_available", False),
            plugin_type=f.get("plugin_type", "remote"),
            treatment_status=f.get("treatment_status", "Open"),
            first_found=f.get("first_found"),
            last_found=f.get("last_found")
        )
        vuln_objects.append(vuln)

    # Inserção em lotes de 500
    chunk_size = 500
    total_chunks = max(1, (len(vuln_objects) + chunk_size - 1) // chunk_size)
    for idx, i in enumerate(range(0, len(vuln_objects), chunk_size)):
        chunk = vuln_objects[i:i + chunk_size]
        db.bulk_save_objects(chunk)
        # Atualiza progresso proporcional de 70% a 88%
        pct = 70 + int((idx + 1) / total_chunks * 18)
        job.progress_percent = min(88, pct)
        db.commit()

    db.commit()
    db.refresh(scan)

    # 7. Post-Import Hook: Sincronização com Planos de Ação (ISO 27001 / ISO 9001 PDCA)
    job.progress_percent = 90
    job.progress_message = "Sincronizando planos de ação e governança ISO 27001..."
    db.commit()

    try:
        from app.api.routes_action_plans import sync_action_plans_on_scan_import
        sync_action_plans_on_scan_import(
            db=db,
            scan=scan,
            current_username=job.created_by_username
        )
    except Exception as hook_err:
        logger.warning(f"[Job #{job.id}] Aviso na sincronização de planos de ação: {hook_err}", exc_info=True)

    duration = round(time.time() - start_time, 2)
    job.status = "completed"
    job.progress_percent = 100
    job.progress_message = (
        f"Importação concluída com sucesso em {duration}s: "
        f"{total_hosts} hosts e {total_findings} vulnerabilidades processadas."
    )
    job.hosts_count = total_hosts
    job.findings_count = total_findings
    job.completed_at = utc_now()
    job.duration_seconds = duration
    job.result_summary = json.dumps({
        "scan_id": scan.id,
        "hosts": total_hosts,
        "findings": total_findings,
        "critical": stats.get("critical_count", 0),
        "high": stats.get("high_count", 0),
        "medium": stats.get("medium_count", 0),
        "low": stats.get("low_count", 0)
    })
    db.commit()
    logger.info(f"[Job #{job.id}] Finalizado com SUCESSO em {duration}s. Scan ID: {scan.id}")


def execute_api_sync_job(db: Session, job: models.ImportJob) -> None:
    """
    Executa a sincronização de vulnerabilidades via API (Tenable / Defender).
    """
    start_time = time.time()
    logger.info(f"[Job #{job.id}] Iniciando sincronização API para integração #{job.integration_id}")

    if not job.integration_id:
        raise ValueError("ID de integração não informado para tarefa de API.")

    job.progress_percent = 20
    job.progress_message = "Conectando ao scanner externo via API..."
    db.commit()

    from app.services.integrations.sync_engine import run_scanner_sync
    res = run_scanner_sync(db, job.integration_id)

    duration = round(time.time() - start_time, 2)
    if res.get("success"):
        job.status = "completed"
        job.progress_percent = 100
        job.progress_message = res.get("message", "Sincronização via API finalizada com sucesso.")
        job.scan_id = res.get("scan_id")
        job.hosts_count = res.get("hosts_count", 0)
        job.findings_count = res.get("vulnerabilities_count", 0)
        job.completed_at = utc_now()
        job.duration_seconds = duration
        job.result_summary = json.dumps(res)
        db.commit()
        logger.info(f"[Job #{job.id}] Sincronização API concluída com SUCESSO em {duration}s.")
    else:
        job.status = "failed"
        job.progress_percent = 100
        err_msg = res.get("message", "Falha na sincronização via API.")
        job.progress_message = f"Falha na sincronização: {err_msg}"
        job.error_message = err_msg
        job.completed_at = utc_now()
        job.duration_seconds = duration
        job.result_summary = json.dumps(res)
        db.commit()
        logger.error(f"[Job #{job.id}] Sincronização API FALHOU: {err_msg}")


def process_job_by_id(job_id: int) -> bool:
    """
    Processa uma tarefa específica por ID dentro de uma sessão isolada.
    Garante tratamento de exceção seguro e atualização do status final.
    """
    db = SessionLocal()
    try:
        job = db.query(models.ImportJob).filter(models.ImportJob.id == job_id).first()
        if not job:
            logger.warning(f"Tarefa #{job_id} não encontrada para processamento.")
            return False

        if job.job_type == "csv_upload":
            execute_csv_import_job(db, job)
        elif job.job_type == "api_sync":
            execute_api_sync_job(db, job)
        else:
            raise ValueError(f"Tipo de tarefa desconhecido: {job.job_type}")

        return True
    except Exception as e:
        logger.error(f"[Job #{job_id}] Exceção não tratada durante execução: {e}", exc_info=True)
        try:
            db.rollback()
            job = db.query(models.ImportJob).filter(models.ImportJob.id == job_id).first()
            if job:
                job.status = "failed"
                job.progress_percent = 100
                job.progress_message = f"Erro no processamento: {str(e)}"
                job.error_message = str(e)
                job.completed_at = utc_now()
                if job.started_at:
                    job.duration_seconds = round((job.completed_at - job.started_at).total_seconds(), 2)
                db.commit()
        except Exception as rollback_err:
            logger.error(f"Erro ao salvar status de falha do job #{job_id}: {rollback_err}")
        return False
    finally:
        db.close()


def process_next_queued_job() -> bool:
    """
    Verifica se há trabalhos na fila. Se houver, aloca o próximo e processa.
    Retorna True se processou um trabalho, False se a fila estava vazia.
    """
    db = SessionLocal()
    job_id = None
    try:
        job_id = claim_next_queued_job(db)
    finally:
        db.close()

    if not job_id:
        return False

    process_job_by_id(job_id)
    return True
