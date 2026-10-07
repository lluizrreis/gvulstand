"""
API Routes para Gestão de Fila de Trabalhos e Histórico de Importações (Opção A)
"""
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, require_analyst_or_admin, check_user_group_access, get_user_allowed_group_ids
from app.services.job_queue import notify_new_job

router = APIRouter(prefix="/jobs", tags=["Fila & Histórico de Importações"])


def format_job_out(job: models.ImportJob) -> schemas.ImportJobOut:
    type_labels = {
        "csv_upload": "Upload CSV Nessus",
        "api_sync": "Sincronização API Scanner"
    }
    status_labels = {
        "queued": "Na Fila",
        "running": "Processando",
        "completed": "Concluído",
        "failed": "Falha",
        "cancelled": "Cancelado"
    }

    group_name = job.asset_group.name if job.asset_group else "Global"

    return schemas.ImportJobOut(
        id=job.id,
        job_type=job.job_type,
        job_type_label=type_labels.get(job.job_type, job.job_type),
        status=job.status,
        status_label=status_labels.get(job.status, job.status),
        progress_percent=job.progress_percent,
        progress_message=job.progress_message,
        asset_group_id=job.asset_group_id,
        asset_group_name=group_name,
        created_by_username=job.created_by_username,
        integration_id=job.integration_id,
        scan_id=job.scan_id,
        filename=job.filename,
        file_size_bytes=job.file_size_bytes,
        scan_name=job.scan_name,
        scan_type=job.scan_type,
        hosts_count=job.hosts_count,
        findings_count=job.findings_count,
        result_summary=job.result_summary,
        error_message=job.error_message,
        duration_seconds=job.duration_seconds,
        queued_at=job.queued_at,
        started_at=job.started_at,
        completed_at=job.completed_at
    )


@router.get("", response_model=List[schemas.ImportJobOut])
def list_jobs(
    asset_group_id: Optional[int] = None,
    status: Optional[str] = None,
    job_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Lista o histórico e estado atual de tarefas da fila de importação.
    """
    query = db.query(models.ImportJob)

    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    if allowed_ids is not None:
        if asset_group_id:
            check_user_group_access(db, current_user, asset_group_id, action="view")
        else:
            query = query.filter(models.ImportJob.asset_group_id.in_(allowed_ids))

    if asset_group_id:
        query = query.filter(models.ImportJob.asset_group_id == asset_group_id)
    if status:
        query = query.filter(models.ImportJob.status == status)
    if job_type:
        query = query.filter(models.ImportJob.job_type == job_type)

    jobs = query.order_by(models.ImportJob.queued_at.desc(), models.ImportJob.id.desc()).offset(offset).limit(limit).all()
    return [format_job_out(j) for j in jobs]


@router.get("/active", response_model=List[schemas.ImportJobOut])
def list_active_jobs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna tarefas ativas no momento (na fila ou em execução).
    Utilizado para monitoramento e polling contínuo no frontend.
    """
    query = db.query(models.ImportJob).filter(models.ImportJob.status.in_(["queued", "running"]))

    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    if allowed_ids is not None:
        query = query.filter(models.ImportJob.asset_group_id.in_(allowed_ids))

    active_jobs = query.order_by(models.ImportJob.queued_at.asc()).all()
    return [format_job_out(j) for j in active_jobs]


@router.get("/{job_id}", response_model=schemas.ImportJobOut)
def get_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Consulta o status e o progresso em tempo real de uma tarefa específica.
    """
    job = db.query(models.ImportJob).filter(models.ImportJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada.")

    check_user_group_access(db, current_user, job.asset_group_id, action="view")
    return format_job_out(job)


@router.post("/{job_id}/cancel", response_model=schemas.ImportJobCancelResponse)
def cancel_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Cancela uma tarefa que ainda esteja aguardando na fila.
    """
    job = db.query(models.ImportJob).filter(models.ImportJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada.")

    check_user_group_access(db, current_user, job.asset_group_id, action="import")

    if job.status == "running":
        raise HTTPException(
            status_code=400,
            detail="A tarefa já está em execução e não pode ser cancelada diretamente."
        )

    if job.status in ["completed", "failed", "cancelled"]:
        raise HTTPException(
            status_code=400,
            detail=f"A tarefa já se encontra finalizada com status '{job.status}'."
        )

    job.status = "cancelled"
    job.progress_message = f"Cancelado manualmente pelo usuário {current_user.username}."
    job.completed_at = datetime.now(timezone.utc)
    db.commit()

    return schemas.ImportJobCancelResponse(
        success=True,
        message=f"Tarefa #{job_id} cancelada com sucesso."
    )


@router.post("/{job_id}/retry", response_model=schemas.ImportJobOut)
def retry_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Reenfileira uma tarefa que falhou.
    """
    job = db.query(models.ImportJob).filter(models.ImportJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada.")

    check_user_group_access(db, current_user, job.asset_group_id, action="import")

    if job.status not in ["failed", "cancelled"]:
        raise HTTPException(
            status_code=400,
            detail="Apenas tarefas que falharam ou foram canceladas podem ser reenfileiradas."
        )

    job.status = "queued"
    job.progress_percent = 0
    job.progress_message = f"Reenfileirado pelo usuário {current_user.username}..."
    job.error_message = None
    job.queued_at = datetime.now(timezone.utc)
    job.started_at = None
    job.completed_at = None
    db.commit()
    db.refresh(job)

    notify_new_job()
    return format_job_out(job)
