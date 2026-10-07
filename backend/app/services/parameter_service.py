import re
import zoneinfo
from datetime import datetime, timezone
from typing import List, Set, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_
from app import models, schemas
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Curated list of timezones with Portuguese friendly labels
CURATED_TIMEZONES = [
    # Brasil (Prioritários)
    {"id": "America/Sao_Paulo", "label": "América/São Paulo (UTC-03:00 - Brasília / Sul / Sudeste)", "is_brazil": True},
    {"id": "America/Manaus", "label": "América/Manaus (UTC-04:00 - Amazonas)", "is_brazil": True},
    {"id": "America/Belem", "label": "América/Belém (UTC-03:00 - Pará / Amapá)", "is_brazil": True},
    {"id": "America/Fortaleza", "label": "América/Fortaleza (UTC-03:00 - Ceará / Maranhão / Piauí)", "is_brazil": True},
    {"id": "America/Recife", "label": "América/Recife (UTC-03:00 - Pernambuco / Nordeste)", "is_brazil": True},
    {"id": "America/Cuiaba", "label": "América/Cuiabá (UTC-04:00 - Mato Grosso / Pantanal)", "is_brazil": True},
    {"id": "America/Campo_Grande", "label": "América/Campo Grande (UTC-04:00 - Mato Grosso do Sul)", "is_brazil": True},
    {"id": "America/Porto_Velho", "label": "América/Porto Velho (UTC-04:00 - Rondônia)", "is_brazil": True},
    {"id": "America/Rio_Branco", "label": "América/Rio Branco (UTC-05:00 - Acre)", "is_brazil": True},
    {"id": "America/Boa_Vista", "label": "América/Boa Vista (UTC-04:00 - Roraima)", "is_brazil": True},
    {"id": "America/Maceio", "label": "América/Maceió (UTC-03:00 - Alagoas / Sergipe)", "is_brazil": True},
    {"id": "America/Noronha", "label": "América/Noronha (UTC-02:00 - Fernando de Noronha)", "is_brazil": True},
    
    # Padrão Universal
    {"id": "UTC", "label": "UTC (Tempo Universal Coordenado, UTC+00:00)", "is_brazil": False},
    
    # América Latina
    {"id": "America/Buenos_Aires", "label": "América/Buenos Aires (Argentina, UTC-03:00)", "is_brazil": False},
    {"id": "America/Montevideo", "label": "América/Montevidéu (Uruguai, UTC-03:00)", "is_brazil": False},
    {"id": "America/Santiago", "label": "América/Santiago (Chile, UTC-03:00 / UTC-04:00)", "is_brazil": False},
    {"id": "America/Bogota", "label": "América/Bogotá (Colômbia, UTC-05:00)", "is_brazil": False},
    {"id": "America/Lima", "label": "América/Lima (Peru, UTC-05:00)", "is_brazil": False},
    {"id": "America/Mexico_City", "label": "América/Cidade do México (México, UTC-06:00)", "is_brazil": False},
    
    # América do Norte
    {"id": "America/New_York", "label": "América/Nova York (EST/EDT, UTC-05:00 / UTC-04:00)", "is_brazil": False},
    {"id": "America/Chicago", "label": "América/Chicago (CST/CDT, UTC-06:00 / UTC-05:00)", "is_brazil": False},
    {"id": "America/Denver", "label": "América/Denver (MST/MDT, UTC-07:00 / UTC-06:00)", "is_brazil": False},
    {"id": "America/Los_Angeles", "label": "América/Los Angeles (PST/PDT, UTC-08:00 / UTC-07:00)", "is_brazil": False},
    
    # Europa
    {"id": "Europe/London", "label": "Europa/Londres (GMT/BST, UTC+00:00 / UTC+01:00)", "is_brazil": False},
    {"id": "Europe/Lisbon", "label": "Europa/Lisboa (WET/WEST, UTC+00:00 / UTC+01:00)", "is_brazil": False},
    {"id": "Europe/Madrid", "label": "Europa/Madri (CET/CEST, UTC+01:00 / UTC+02:00)", "is_brazil": False},
    {"id": "Europe/Paris", "label": "Europa/Paris (CET/CEST, UTC+01:00 / UTC+02:00)", "is_brazil": False},
    {"id": "Europe/Berlin", "label": "Europa/Berlim (CET/CEST, UTC+01:00 / UTC+02:00)", "is_brazil": False},
    
    # Ásia e Oceania
    {"id": "Asia/Tokyo", "label": "Ásia/Tóquio (JST, UTC+09:00)", "is_brazil": False},
    {"id": "Asia/Shanghai", "label": "Ásia/Xangai (CST, UTC+08:00)", "is_brazil": False},
    {"id": "Asia/Singapore", "label": "Ásia/Cingapura (SGT, UTC+08:00)", "is_brazil": False},
    {"id": "Australia/Sydney", "label": "Austrália/Sydney (AEST/AEDT, UTC+10:00 / UTC+11:00)", "is_brazil": False},
]

def get_timezone_offset_str(tz_id: str) -> str:
    """Calcula o offset atual formatado como UTC±HH:MM para um ID de timezone."""
    try:
        tz = zoneinfo.ZoneInfo(tz_id)
        now_in_tz = datetime.now(tz)
        offset = now_in_tz.utcoffset()
        if offset is None:
            return "UTC"
        total_seconds = int(offset.total_seconds())
        sign = "+" if total_seconds >= 0 else "-"
        total_seconds = abs(total_seconds)
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"UTC{sign}{hours:02d}:{minutes:02d}"
    except Exception:
        return "UTC"

def get_available_timezones() -> List[Dict[str, Any]]:
    """
    Retorna lista completa e amigável de fusos horários disponíveis,
    priorizando os fusos brasileiros e internacionais mais utilizados.
    """
    result = []
    seen_ids = set()

    for item in CURATED_TIMEZONES:
        tz_id = item["id"]
        seen_ids.add(tz_id)
        offset = get_timezone_offset_str(tz_id)
        result.append({
            "id": tz_id,
            "label": item["label"],
            "offset": offset,
            "is_brazil": item.get("is_brazil", False)
        })

    # Adiciona outros fusos padrão disponíveis no sistema operacional
    try:
        available_all = sorted(list(zoneinfo.available_timezones()))
        for tz_id in available_all:
            if tz_id not in seen_ids and not tz_id.startswith("Etc/") and "/" in tz_id:
                offset = get_timezone_offset_str(tz_id)
                result.append({
                    "id": tz_id,
                    "label": f"{tz_id} ({offset})",
                    "offset": offset,
                    "is_brazil": False
                })
    except Exception as e:
        logger.warning(f"Erro ao listar todos os fusos horários: {e}")

    return result

def get_or_create_system_parameters(db: Session) -> models.SystemParameters:
    """Retorna ou cria o registro singleton de parâmetros do sistema (id=1)."""
    params = db.query(models.SystemParameters).filter(models.SystemParameters.id == 1).first()
    if not params:
        params = models.SystemParameters(
            id=1,
            timezone="America/Sao_Paulo",
            sla_critical_days=settings.DEFAULT_SLA_CRITICAL_DAYS,
            sla_high_days=settings.DEFAULT_SLA_HIGH_DAYS,
            sla_medium_days=settings.DEFAULT_SLA_MEDIUM_DAYS,
            sla_low_days=settings.DEFAULT_SLA_LOW_DAYS,
            ignored_vulnerability_ids="",
            updated_by_username="Sistema"
        )
        db.add(params)
        db.commit()
        db.refresh(params)
    return params

def parse_ignored_ids(raw_text: Optional[str]) -> List[str]:
    """
    Extrai lista limpa e sem duplicatas de IDs de vulnerabilidades/plugins informados.
    Suporta separação por vírgula, ponto e vírgula, espaços ou quebras de linha.
    """
    if not raw_text:
        return []
    tokens = re.split(r'[,;\s\n\r]+', raw_text.strip())
    seen = set()
    cleaned = []
    for t in tokens:
        item = t.strip()
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)
    return cleaned

def get_ignored_ids_set(db: Session) -> Set[str]:
    """Retorna conjunto de IDs/Plugins ignorados para filtragem rápida em consultas."""
    params = get_or_create_system_parameters(db)
    return set(parse_ignored_ids(params.ignored_vulnerability_ids))

def apply_indicator_exclusion(query, db: Session, model=models.Vulnerability):
    """
    Aplica exclusão automática de vulnerabilidades classificadas como Falso-Positivo
    nos indicadores (plugin_id e id numérico).
    """
    ignored_ids = get_ignored_ids_set(db)
    if not ignored_ids:
        return query

    int_ids = [int(i) for i in ignored_ids if i.isdigit()]
    
    # Exclui pelo plugin_id
    query = query.filter(~model.plugin_id.in_(list(ignored_ids)))
    
    # Se houver IDs inteiros válidos, também exclui por model.id
    if int_ids:
        query = query.filter(~model.id.in_(int_ids))

    return query

def get_system_timezone(db: Optional[Session] = None) -> str:
    """Retorna a string do fuso horário configurado no sistema."""
    if db is not None:
        try:
            params = get_or_create_system_parameters(db)
            return params.timezone or "America/Sao_Paulo"
        except Exception as e:
            logger.warning(f"Erro ao obter fuso horário do sistema do banco: {e}")
    return "America/Sao_Paulo"

def get_system_zoneinfo(db: Optional[Session] = None) -> zoneinfo.ZoneInfo:
    """Retorna o objeto ZoneInfo configurado no sistema."""
    tz_str = get_system_timezone(db)
    try:
        return zoneinfo.ZoneInfo(tz_str)
    except Exception:
        return zoneinfo.ZoneInfo("America/Sao_Paulo")

def to_system_tz(dt: Optional[datetime], db: Optional[Session] = None) -> Optional[datetime]:
    """
    Converte datetime (assumindo UTC se não possuir tzinfo) para datetime com tzinfo
    no fuso horário operacional configurado no sistema.
    """
    if not dt:
        return None
    try:
        sys_tz = get_system_zoneinfo(db)
        if dt.tzinfo is None:
            dt_utc = dt.replace(tzinfo=timezone.utc)
        else:
            dt_utc = dt
        return dt_utc.astimezone(sys_tz)
    except Exception as e:
        logger.warning(f"Erro ao converter datetime para fuso do sistema: {e}")
        return dt

def format_datetime_in_system_tz(
    dt: Optional[datetime],
    db: Optional[Session] = None,
    fmt: str = "%d/%m/%Y %H:%M:%S",
    include_offset: bool = True
) -> str:
    """
    Converte datetime (assumindo UTC se não possuir tzinfo) para o fuso horário
    configurado no sistema e formata como string amigável.
    """
    if not dt:
        return "-"
    try:
        sys_tz = get_system_zoneinfo(db)
        # Se for ingênuo (sem tzinfo), assume UTC
        if dt.tzinfo is None:
            dt_utc = dt.replace(tzinfo=timezone.utc)
        else:
            dt_utc = dt
        dt_local = dt_utc.astimezone(sys_tz)
        if include_offset:
            offset_str = get_timezone_offset_str(sys_tz.key)
            return f"{dt_local.strftime(fmt)} ({offset_str})"
        return dt_local.strftime(fmt)
    except Exception as e:
        logger.warning(f"Erro ao formatar data/hora no fuso do sistema: {e}")
        return dt.strftime(fmt) if hasattr(dt, 'strftime') else str(dt)

def get_effective_slas(db: Session, group: Optional[models.AssetGroup] = None) -> Dict[str, int]:
    """
    Retorna os limites de SLA vigentes (Crítica, Alta, Média, Baixa)
    utilizando a parametrização do grupo de ativos ou a política global do sistema.
    """
    params = get_or_create_system_parameters(db)
    default_crit = params.sla_critical_days or 7
    default_high = params.sla_high_days or 15
    default_med = params.sla_medium_days or 30
    default_low = params.sla_low_days or 60

    if group:
        return {
            "Critical": group.sla_critical_days if group.sla_critical_days else default_crit,
            "High": group.sla_high_days if group.sla_high_days else default_high,
            "Medium": group.sla_medium_days if group.sla_medium_days else default_med,
            "Low": group.sla_low_days if group.sla_low_days else default_low,
        }
    return {
        "Critical": default_crit,
        "High": default_high,
        "Medium": default_med,
        "Low": default_low,
    }
