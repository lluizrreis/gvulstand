"""
GvulStand Background Job Queue Worker (Opção A)
Gerencia o loop de execução assíncrona para consumo da fila de importações.
"""
import asyncio
import logging
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app import models
from .job_processor import process_next_queued_job

logger = logging.getLogger("job_queue.worker")

# Evento assíncrono para acordar o worker imediatamente quando um novo trabalho é enfileirado
_wake_event: Optional[asyncio.Event] = None


def get_wake_event() -> asyncio.Event:
    global _wake_event
    if _wake_event is None:
        _wake_event = asyncio.Event()
    return _wake_event


def notify_new_job():
    """Acorda o worker imediatamente para processar a nova tarefa da fila."""
    try:
        ev = get_wake_event()
        ev.set()
    except Exception as e:
        logger.debug(f"Não foi possível sinalizar wake_event do worker: {e}")


async def job_queue_worker():
    """
    Loop assíncrono do Worker de Fila de Trabalhos.
    Executa continuamente enquanto o FastAPI estiver ativo.
    """
    logger.info("GvulStand Job Queue Worker inicializado com sucesso.")
    ev = get_wake_event()

    while True:
        try:
            # Aguarda sinal de novo job ou verifica a cada 3 segundos
            try:
                await asyncio.wait_for(ev.wait(), timeout=3.0)
                ev.clear()
            except asyncio.TimeoutError:
                pass

            # Drena a fila sequencialmente até que não haja mais jobs pendentes
            while True:
                # Executa o processamento do próximo job de forma síncrona em threadpool para não travar o event loop do asyncio
                has_more = await asyncio.to_thread(process_next_queued_job)
                if not has_more:
                    break

        except asyncio.CancelledError:
            logger.info("GvulStand Job Queue Worker encerrando graciosamente...")
            break
        except Exception as e:
            logger.error(f"Erro no loop do Job Queue Worker: {e}", exc_info=True)
            await asyncio.sleep(2.0)


def enqueue_csv_job(
    db: Session,
    asset_group_id: int,
    filename: str,
    file_path: str,
    file_size_bytes: int,
    current_user: models.User,
    scan_name: Optional[str] = None,
    scan_type: str = "baseline",
    scan_date: Optional[datetime] = None,
    notes: Optional[str] = None
) -> models.ImportJob:
    """
    Enfileira uma tarefa de importação de CSV do Nessus.
    """
    job = models.ImportJob(
        job_type="csv_upload",
        status="queued",
        progress_percent=0,
        progress_message="Na fila de processamento...",
        asset_group_id=asset_group_id,
        created_by_user_id=current_user.id,
        created_by_username=current_user.username,
        filename=filename,
        file_path=file_path,
        file_size_bytes=file_size_bytes,
        scan_name=scan_name or filename,
        scan_type=scan_type,
        scan_date=scan_date,
        notes=notes,
        queued_at=datetime.now(timezone.utc)
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    notify_new_job()
    return job


def enqueue_api_sync_job(
    db: Session,
    integration: models.ScannerIntegration,
    current_user: models.User
) -> models.ImportJob:
    """
    Enfileira uma tarefa de sincronização de scanner via API.
    """
    job = models.ImportJob(
        job_type="api_sync",
        status="queued",
        progress_percent=0,
        progress_message=f"Na fila para sincronização com {integration.name}...",
        asset_group_id=integration.asset_group_id,
        created_by_user_id=current_user.id,
        created_by_username=current_user.username,
        integration_id=integration.id,
        scan_name=f"[API Sync] {integration.name}",
        scan_type="baseline",
        queued_at=datetime.now(timezone.utc)
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    notify_new_job()
    return job
