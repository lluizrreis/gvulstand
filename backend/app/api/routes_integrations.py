"""
API Routes for Scanner Integrations (Tenable & Microsoft Defender)
Supports configuration management, credential testing, immediate sync triggering,
and periodic scheduling per Asset Group.
"""
from typing import List, Optional, Union
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas
from app.auth import get_current_user
from app.crypto_utils import safe_encrypt_secret, safe_decrypt_secret, is_encrypted
from app.services.integrations.sync_engine import run_scanner_sync, test_scanner_connection

router = APIRouter()

type_labels = {
    "tenable_io": "Tenable.io (Vulnerability Management)",
    "tenable_sc": "Tenable.sc (SecurityCenter)",
    "tenable_nessus_pro": "Tenable Nessus Professional",
    "ms_defender": "Microsoft Defender for Endpoint (MDVM)",
    "openvas": "OpenVAS / Greenbone Community Edition (GVM)",
    "greenbone_gvm": "Greenbone Community Edition (GVM)"
}


def mask_key(val: Optional[str]) -> Optional[str]:
    if not val:
        return None
    val = val.strip()
    if len(val) <= 6:
        return "******"
    return f"{val[:3]}...{val[-3:]}"


def format_integration_out(integ: models.ScannerIntegration) -> schemas.ScannerIntegrationOut:
    sched_labels = {
        "manual": "Manual (Sob Demanda)",
        "interval": f"A cada {integ.interval_hours} horas",
        "daily": f"Diário às {integ.schedule_time or '02:00'}",
        "weekly": f"Semanal às {integ.schedule_time or '02:00'}"
    }

    last_sync_formatted = None
    if integ.last_sync_at:
        last_sync_formatted = integ.last_sync_at.strftime("%d/%m/%Y %H:%M:%S")

    group_name = integ.asset_group.name if integ.asset_group else "Grupo Desconhecido"

    # Decodifica access_key para exibição/mascaramento adequado
    decrypted_acc = safe_decrypt_secret(integ.access_key)
    if integ.scanner_type in ["openvas", "greenbone_gvm"]:
        access_key_display = decrypted_acc or integ.client_id
    else:
        access_key_display = mask_key(decrypted_acc)

    return schemas.ScannerIntegrationOut(
        id=integ.id,
        asset_group_id=integ.asset_group_id,
        asset_group_name=group_name,
        name=integ.name,
        scanner_type=integ.scanner_type,
        scanner_type_label=type_labels.get(integ.scanner_type, integ.scanner_type),
        is_enabled=integ.is_enabled,
        api_endpoint=integ.api_endpoint,
        verify_ssl=integ.verify_ssl,
        auth_type=integ.auth_type,
        access_key_masked=access_key_display,
        has_secret_key=bool(integ.secret_key),
        tenant_id=integ.tenant_id,
        client_id=integ.client_id,
        has_client_secret=bool(integ.client_secret),
        target_scope_filter=integ.target_scope_filter,
        schedule_type=integ.schedule_type,
        schedule_type_label=sched_labels.get(integ.schedule_type, integ.schedule_type),
        interval_hours=integ.interval_hours or 24,
        schedule_time=integ.schedule_time,
        schedule_days=integ.schedule_days,
        last_sync_status=integ.last_sync_status or "idle",
        last_sync_at=integ.last_sync_at,
        last_sync_at_formatted=last_sync_formatted,
        last_sync_message=integ.last_sync_message,
        last_synced_scan_id=integ.last_synced_scan_id,
        vulnerabilities_imported_count=integ.vulnerabilities_imported_count or 0,
        hosts_imported_count=integ.hosts_imported_count or 0,
        created_at=integ.created_at,
        updated_at=integ.updated_at
    )


@router.get("", response_model=List[schemas.ScannerIntegrationOut])
def list_integrations(
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Lista todas as integrações de scanners configuradas.
    Permite filtrar por asset_group_id.
    """
    query = db.query(models.ScannerIntegration)
    if asset_group_id:
        query = query.filter(models.ScannerIntegration.asset_group_id == asset_group_id)

    # If non-admin user, filter by allowed groups
    if current_user.role != "admin":
        allowed_gids = [
            perm.asset_group_id for perm in current_user.asset_group_permissions
        ]
        query = query.filter(models.ScannerIntegration.asset_group_id.in_(allowed_gids))

    integrations = query.order_by(models.ScannerIntegration.id.asc()).all()
    return [format_integration_out(i) for i in integrations]


@router.get("/saved-credentials", response_model=List[schemas.SavedCredentialOption])
def list_saved_credentials(
    scanner_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Lista perfis de credenciais de scanners salvas disponíveis para reutilização
    em novos cadastros sem necessidade de reinserir senhas e chaves a cada novo cadastro.
    """
    query = db.query(models.ScannerIntegration)
    if current_user.role != "admin":
        allowed_gids = [perm.asset_group_id for perm in current_user.asset_group_permissions]
        query = query.filter(models.ScannerIntegration.asset_group_id.in_(allowed_gids))

    if scanner_type:
        if scanner_type.startswith("tenable"):
            query = query.filter(models.ScannerIntegration.scanner_type.like("tenable%"))
        else:
            query = query.filter(models.ScannerIntegration.scanner_type == scanner_type)

    integrations = query.order_by(models.ScannerIntegration.updated_at.desc()).all()
    options: List[schemas.SavedCredentialOption] = []
    seen_fingerprints = set()

    for i in integrations:
        has_cred = bool(i.access_key or i.secret_key or i.client_secret or i.client_id)
        if not has_cred:
            continue

        decrypted_acc = safe_decrypt_secret(i.access_key)
        if i.scanner_type in ["openvas", "greenbone_gvm"]:
            acc_id = decrypted_acc or i.client_id or "admin"
        elif "defender" in (i.scanner_type or "").lower():
            acc_id = i.client_id or "App ID"
        else:
            acc_id = mask_key(decrypted_acc)

        fp = f"{i.name.strip().lower()}:{i.scanner_type}:{i.api_endpoint}:{acc_id}"
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)

        options.append(schemas.SavedCredentialOption(
            id=i.id,
            name=i.name,
            scanner_type=i.scanner_type,
            scanner_type_label=type_labels.get(i.scanner_type, i.scanner_type),
            api_endpoint=i.api_endpoint,
            account_identifier=acc_id,
            tenant_id=i.tenant_id,
            has_secret=bool(i.secret_key or i.client_secret),
            verify_ssl=i.verify_ssl,
            asset_group_name=i.asset_group.name if i.asset_group else None
        ))
    return options


@router.get("/{integration_id}", response_model=schemas.ScannerIntegrationOut)
def get_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Obtém detalhes de uma integração de scanner.
    """
    integ = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integration_id).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integração não encontrada.")

    return format_integration_out(integ)


@router.post("", response_model=schemas.ScannerIntegrationOut, status_code=status.HTTP_201_CREATED)
def create_integration(
    payload: schemas.ScannerIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Cadastra uma nova integração de scanner para um Grupo de Ativos.
    Permite reutilizar credenciais cifradas de outra integração já cadastrada via use_credentials_from_id.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Apenas administradores e analistas podem configurar integrações.")

    group = db.query(models.AssetGroup).filter(models.AssetGroup.id == payload.asset_group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Grupo de Ativos de destino não encontrado.")

    # Se informado ID de integração de origem para reutilização de credenciais
    if payload.use_credentials_from_id:
        source_integ = db.query(models.ScannerIntegration).filter(
            models.ScannerIntegration.id == payload.use_credentials_from_id
        ).first()
        if not source_integ:
            raise HTTPException(status_code=404, detail="Integração de origem das credenciais não encontrada.")
        if current_user.role != "admin":
            allowed_gids = [perm.asset_group_id for perm in current_user.asset_group_permissions]
            if source_integ.asset_group_id not in allowed_gids:
                raise HTTPException(status_code=403, detail="Acesso não autorizado às credenciais da integração de origem.")

        access_key = safe_encrypt_secret(payload.access_key.strip()) if payload.access_key else source_integ.access_key
        secret_key = safe_encrypt_secret(payload.secret_key.strip()) if payload.secret_key else source_integ.secret_key
        tenant_id = payload.tenant_id.strip() if payload.tenant_id else source_integ.tenant_id
        client_id = payload.client_id.strip() if payload.client_id else source_integ.client_id
        client_secret = safe_encrypt_secret(payload.client_secret.strip()) if payload.client_secret else source_integ.client_secret
        api_endpoint = (payload.api_endpoint.strip() if payload.api_endpoint else None) or source_integ.api_endpoint
    else:
        access_key = safe_encrypt_secret(payload.access_key.strip()) if payload.access_key else None
        secret_key = safe_encrypt_secret(payload.secret_key.strip()) if payload.secret_key else None
        tenant_id = payload.tenant_id.strip() if payload.tenant_id else None
        client_id = payload.client_id.strip() if payload.client_id else None
        client_secret = safe_encrypt_secret(payload.client_secret.strip()) if payload.client_secret else None
        api_endpoint = payload.api_endpoint.strip() if payload.api_endpoint else None

    integ = models.ScannerIntegration(
        asset_group_id=payload.asset_group_id,
        name=payload.name.strip(),
        scanner_type=payload.scanner_type,
        is_enabled=payload.is_enabled,
        api_endpoint=api_endpoint,
        verify_ssl=payload.verify_ssl,
        auth_type=payload.auth_type,
        access_key=access_key,
        secret_key=secret_key,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        target_scope_filter=payload.target_scope_filter.strip() if payload.target_scope_filter else None,
        schedule_type=payload.schedule_type,
        interval_hours=payload.interval_hours,
        schedule_time=payload.schedule_time,
        schedule_days=payload.schedule_days
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)

    return format_integration_out(integ)


@router.put("/{integration_id}", response_model=schemas.ScannerIntegrationOut)
def update_integration(
    integration_id: int,
    payload: schemas.ScannerIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Atualiza uma integração de scanner existente.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Apenas administradores e analistas podem alterar integrações.")

    integ = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integration_id).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integração não encontrada.")

    # Se solicitado copiar credenciais de outra integração
    if payload.use_credentials_from_id:
        source_integ = db.query(models.ScannerIntegration).filter(
            models.ScannerIntegration.id == payload.use_credentials_from_id
        ).first()
        if not source_integ:
            raise HTTPException(status_code=404, detail="Integração de origem das credenciais não encontrada.")
        if current_user.role != "admin":
            allowed_gids = [perm.asset_group_id for perm in current_user.asset_group_permissions]
            if source_integ.asset_group_id not in allowed_gids:
                raise HTTPException(status_code=403, detail="Acesso não autorizado às credenciais de origem.")
        integ.access_key = source_integ.access_key
        integ.secret_key = source_integ.secret_key
        integ.tenant_id = source_integ.tenant_id
        integ.client_id = source_integ.client_id
        integ.client_secret = source_integ.client_secret

    update_data = payload.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        if field in ["use_credentials_from_id"]:
            continue
        if val is not None:
            if isinstance(val, str):
                val = val.strip()
            # Se for senha/segredo em branco, mantém o valor atual
            if field in ["secret_key", "client_secret"] and val == "":
                continue
            # Criptografa credenciais sensíveis
            if field in ["access_key", "secret_key", "client_secret"]:
                val = safe_encrypt_secret(val)
            setattr(integ, field, val)

    integ.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(integ)

    return format_integration_out(integ)


@router.delete("/{integration_id}", status_code=status.HTTP_200_OK)
def delete_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Remove uma configuração de integração de scanner.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores podem remover integrações.")

    integ = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integration_id).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integração não encontrada.")

    db.delete(integ)
    db.commit()
    return {"message": f"Integração #{integration_id} removida com sucesso."}


@router.post("/test-connection", response_model=schemas.ScannerIntegrationTestResponse)
def test_connection_transient(
    payload: schemas.ScannerIntegrationTestRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Testa credenciais e conectividade com o scanner antes de salvar a configuração.
    Suporta reutilização de credenciais de integração existente via use_credentials_from_id.
    """
    if payload.use_credentials_from_id:
        source_integ = db.query(models.ScannerIntegration).filter(
            models.ScannerIntegration.id == payload.use_credentials_from_id
        ).first()
        if not source_integ:
            raise HTTPException(status_code=404, detail="Integração de origem das credenciais não encontrada.")
        if current_user.role != "admin":
            allowed_gids = [perm.asset_group_id for perm in current_user.asset_group_permissions]
            if source_integ.asset_group_id not in allowed_gids:
                raise HTTPException(status_code=403, detail="Acesso não autorizado às credenciais de origem.")

        access_key = payload.access_key or safe_decrypt_secret(source_integ.access_key)
        secret_key = payload.secret_key or safe_decrypt_secret(source_integ.secret_key)
        tenant_id = payload.tenant_id or source_integ.tenant_id
        client_id = payload.client_id or source_integ.client_id
        client_secret = payload.client_secret or safe_decrypt_secret(source_integ.client_secret)
        api_endpoint = payload.api_endpoint or source_integ.api_endpoint
    else:
        access_key = payload.access_key
        secret_key = payload.secret_key
        tenant_id = payload.tenant_id
        client_id = payload.client_id
        client_secret = payload.client_secret
        api_endpoint = payload.api_endpoint

    res = test_scanner_connection(
        scanner_type=payload.scanner_type,
        api_endpoint=api_endpoint,
        verify_ssl=payload.verify_ssl,
        auth_type=payload.auth_type,
        access_key=access_key,
        secret_key=secret_key,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    return schemas.ScannerIntegrationTestResponse(**res)


@router.post("/{integration_id}/test-connection", response_model=schemas.ScannerIntegrationTestResponse)
def test_connection_saved(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Testa conectividade de uma integração já salva com credenciais descriptografadas.
    """
    integ = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integration_id).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integração não encontrada.")

    res = test_scanner_connection(
        scanner_type=integ.scanner_type,
        api_endpoint=integ.api_endpoint,
        verify_ssl=integ.verify_ssl,
        auth_type=integ.auth_type,
        access_key=safe_decrypt_secret(integ.access_key),
        secret_key=safe_decrypt_secret(integ.secret_key),
        tenant_id=integ.tenant_id,
        client_id=integ.client_id,
        client_secret=safe_decrypt_secret(integ.client_secret)
    )
    return schemas.ScannerIntegrationTestResponse(**res)


@router.post("/{integration_id}/sync-now", response_model=Union[schemas.ScannerSyncResponse, schemas.ImportJobEnqueueResponse])
def sync_now(
    integration_id: int,
    background: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Dispara a sincronização de vulnerabilidades com a API do scanner.
    Suporta execução assíncrona pela Fila de Trabalhos (background=True) ou síncrona.
    """
    integ = db.query(models.ScannerIntegration).filter(models.ScannerIntegration.id == integration_id).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integração não encontrada.")

    if integ.last_sync_status == "running":
        now = datetime.now(timezone.utc)
        elapsed = 0
        if integ.last_sync_at:
            last_dt = integ.last_sync_at if integ.last_sync_at.tzinfo else integ.last_sync_at.replace(tzinfo=timezone.utc)
            elapsed = (now - last_dt).total_seconds()
        if elapsed < 900 and integ.last_sync_at is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A integração '{integ.name}' já possui uma sincronização em andamento. Aguarde o término da execução atual."
            )

    if background:
        from app.services.job_queue import enqueue_api_sync_job
        job = enqueue_api_sync_job(db=db, integration=integ, current_user=current_user)
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "job_id": job.id,
                "status": "queued",
                "message": f"Sincronização com '{integ.name}' enfileirada com sucesso na fila de trabalhos.",
                "job_type": "api_sync",
                "asset_group_id": integ.asset_group_id
            }
        )

    res = run_scanner_sync(db, integration_id)
    if res.get("status") == "conflict":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=res.get("message")
        )
    return schemas.ScannerSyncResponse(**res)
