import os
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.config import settings
from app import models, schemas
from app.auth import get_current_user, require_admin, require_analyst_or_admin, check_user_group_access, get_user_allowed_group_ids
from app.services.parser_nessus import parse_nessus_csv

router = APIRouter(prefix="/scans", tags=["Importação & Gestão de Scans"])

@router.get("", response_model=List[schemas.ScanOut])
def list_scans(
    asset_group_id: Optional[int] = None,
    scan_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Lista todos os relatórios de scan importados."""
    query = db.query(models.Scan).join(models.AssetGroup, models.Scan.asset_group_id == models.AssetGroup.id)
    
    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    if allowed_ids is not None:
        if asset_group_id:
            check_user_group_access(db, current_user, asset_group_id, action="view")
        else:
            query = query.filter(models.Scan.asset_group_id.in_(allowed_ids))

    if asset_group_id:
        from app.services.asset_group_service import get_descendant_group_ids
        group_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
        query = query.filter(models.Scan.asset_group_id.in_(group_ids))
    if scan_type:
        query = query.filter(models.Scan.scan_type == scan_type)
    
    scans = query.order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).all()
    
    result = []
    for s in scans:
        out = schemas.ScanOut.model_validate(s)
        out.asset_group_name = s.asset_group.name if s.asset_group else ""
        result.append(out)
    return result

@router.post("/upload", response_model=schemas.ScanOut, status_code=status.HTTP_201_CREATED)
async def upload_nessus_scan(
    file: UploadFile = File(...),
    asset_group_id: int = Form(...),
    scan_name: str = Form(...),
    scan_type: Optional[str] = Form("baseline"), # 'baseline' or 'retest'
    scan_date: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Importa um relatório CSV do Nessus/Tenable associado a um Grupo de Ativos (Requer Analista ou Administrador).
    """
    check_user_group_access(db, current_user, asset_group_id, action="import")

    group = db.query(models.AssetGroup).filter(models.AssetGroup.id == asset_group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Grupo de ativos informado não existe.")

    if not file.filename.lower().endswith((".csv", ".txt")):
        raise HTTPException(status_code=400, detail="Apenas arquivos CSV são suportados.")

    # Read content
    try:
        content_bytes = await file.read()
        file_size = len(content_bytes)
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
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao ler arquivo: {str(e)}")

    # Parse Nessus CSV
    try:
        parsed_data = parse_nessus_csv(content_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro no processamento do arquivo Nessus: {str(e)}")

    hosts_data = parsed_data["hosts"]
    findings_data = parsed_data["findings"]
    stats = parsed_data["stats"]

    # Save uploaded file to disk
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{timestamp}_{file.filename}"
    file_path = os.path.join(settings.UPLOAD_FOLDER, safe_filename)
    with open(file_path, "wb") as f:
        f.write(content_bytes)

    # Parse scan_date if provided
    parsed_scan_date = datetime.now(timezone.utc)
    if scan_date:
        clean_date_str = scan_date.strip().replace("Z", "")
        for fmt in (
            "%Y-%m-%d",
            "%d/%m/%Y",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M",
        ):
            try:
                parsed_scan_date = datetime.strptime(clean_date_str, fmt)
                break
            except ValueError:
                pass

    # Create Scan Record
    scan = models.Scan(
        asset_group_id=asset_group_id,
        scan_name=scan_name,
        scan_type=scan_type if scan_type in ["baseline", "retest"] else "baseline",
        filename=safe_filename,
        file_size_bytes=file_size,
        total_hosts=len(hosts_data),
        total_findings=len(findings_data),
        critical_count=stats["critical_count"],
        high_count=stats["high_count"],
        medium_count=stats["medium_count"],
        low_count=stats["low_count"],
        info_count=stats["info_count"],
        exploitable_critical_count=stats["exploitable_critical_count"],
        scan_date=parsed_scan_date,
        notes=notes
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Create Host Records and map IP to Host ID
    ip_to_host_id = {}
    for ip, h_info in hosts_data.items():
        host = models.Host(
            scan_id=scan.id,
            asset_group_id=asset_group_id,
            ip_address=h_info["ip_address"],
            hostname=h_info["hostname"],
            mac_address=h_info["mac_address"],
            os=h_info["os"],
            critical_count=h_info["critical_count"],
            high_count=h_info["high_count"],
            medium_count=h_info["medium_count"],
            low_count=h_info["low_count"],
            info_count=h_info["info_count"],
            exploitable_critical_count=h_info["exploitable_critical_count"],
            risk_score=h_info["risk_score"]
        )
        db.add(host)
        db.flush()
        ip_to_host_id[ip] = host.id

    # Create Vulnerability Records
    vuln_objects = []
    for f in findings_data:
        host_id = ip_to_host_id.get(f["host_ip"])
        if not host_id:
            continue
        vuln = models.Vulnerability(
            scan_id=scan.id,
            host_id=host_id,
            asset_group_id=asset_group_id,
            plugin_id=f["plugin_id"],
            plugin_name=f["plugin_name"],
            cve=f["cve"],
            cvss_v3=f["cvss_v3"],
            cvss_v2=f["cvss_v2"],
            severity=f["severity"],
            port=f["port"],
            protocol=f["protocol"],
            synopsis=f["synopsis"],
            description=f["description"],
            solution=f["solution"],
            see_also=f["see_also"],
            plugin_output=f["plugin_output"],
            exploit_available=f["exploit_available"],
            exploit_frameworks=f["exploit_frameworks"],
            exploited_by_malware=f.get("exploited_by_malware", False),
            vpr=f.get("vpr"),
            patch_available=f.get("patch_available", False),
            plugin_type=f.get("plugin_type", "remote"),
            treatment_status=f["treatment_status"],
            first_found=f.get("first_found"),
            last_found=f.get("last_found")
        )
        vuln_objects.append(vuln)

    # Bulk insert findings in chunks
    chunk_size = 500
    for i in range(0, len(vuln_objects), chunk_size):
        db.bulk_save_objects(vuln_objects[i:i + chunk_size])

    db.commit()
    db.refresh(scan)

    # Post-Import Hook: Sincronização automática com Planos de Ação Ativos (ISO 27001 / ISO 9001 PDCA)
    try:
        from app.api.routes_action_plans import sync_action_plans_on_scan_import
        sync_action_plans_on_scan_import(
            db=db,
            scan=scan,
            current_username=current_user.username
        )
    except Exception as hook_err:
        import logging
        logging.getLogger(__name__).warning(f"Aviso no post-import hook de sincronização de planos: {hook_err}")

    out = schemas.ScanOut.model_validate(scan)
    out.asset_group_name = group.name
    return out

@router.get("/{scan_id}", response_model=schemas.ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Obtém os detalhes de um scan específico."""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado.")
    check_user_group_access(db, current_user, scan.asset_group_id, action="view")
    out = schemas.ScanOut.model_validate(scan)
    out.asset_group_name = scan.asset_group.name if scan.asset_group else ""
    return out

@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """Exclui um scan e todos os seus hosts e vulnerabilidades associados (Requer Administrador)."""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado.")

    db.delete(scan)
    db.commit()
    return {"message": "Scan e vulnerabilidades removidos com sucesso."}
