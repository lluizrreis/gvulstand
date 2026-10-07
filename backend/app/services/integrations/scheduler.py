"""
GvulStand Scanner Scheduler
Evaluates scheduled scan syncs for enabled integrations (interval, daily, weekly)
and executes automated ingestion runs.
"""
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app import models
from .sync_engine import run_scanner_sync

logger = logging.getLogger("scheduler")


def should_run_integration(integration: models.ScannerIntegration, now: datetime) -> bool:
    """
    Evaluates whether the integration is due for automated sync execution.
    """
    if not integration.is_enabled:
        return False

    if integration.last_sync_status == "running":
        # Don't overlap concurrent runs
        return False

    stype = (integration.schedule_type or "manual").lower()
    if stype == "manual":
        return False

    last_sync = integration.last_sync_at
    if last_sync and last_sync.tzinfo is None:
        last_sync = last_sync.replace(tzinfo=timezone.utc)

    # 1. Interval Schedule (e.g. every X hours)
    if stype == "interval":
        interval_hrs = max(1, integration.interval_hours or 24)
        if not last_sync:
            return True
        elapsed_seconds = (now - last_sync).total_seconds()
        return elapsed_seconds >= (interval_hrs * 3600)

    # 2. Daily Schedule (at HH:MM)
    current_time_str = now.strftime("%H:%M")
    target_time_str = (integration.schedule_time or "02:00").strip()

    if stype == "daily":
        if not last_sync:
            return current_time_str >= target_time_str
        # Already ran today?
        if last_sync.date() == now.date():
            return False
        return current_time_str >= target_time_str

    # 3. Weekly Schedule (on specific weekdays at HH:MM)
    if stype == "weekly":
        current_weekday = str(now.isoweekday())  # 1=Monday, 7=Sunday
        allowed_days = [d.strip() for d in (integration.schedule_days or "1").split(",") if d.strip()]
        if current_weekday not in allowed_days:
            return False
        if not last_sync:
            return current_time_str >= target_time_str
        if last_sync.date() == now.date():
            return False
        return current_time_str >= target_time_str

    return False


def check_and_run_scheduled_syncs(db: Session) -> int:
    """
    Checks all integrations and executes due syncs. Returns count of triggered syncs.
    """
    now = datetime.now(timezone.utc)
    integrations = db.query(models.ScannerIntegration).filter(
        models.ScannerIntegration.is_enabled == True,
        models.ScannerIntegration.schedule_type.in_(["interval", "daily", "weekly"])
    ).all()

    triggered = 0
    for integ in integrations:
        try:
            if should_run_integration(integ, now):
                logger.info(f"Triggering scheduled sync for integration #{integ.id} ({integ.name})...")
                from app.services.job_queue import enqueue_api_sync_job
                admin_user = db.query(models.User).filter(models.User.role == "admin").first()
                if admin_user:
                    enqueue_api_sync_job(db, integ, admin_user)
                else:
                    run_scanner_sync(db, integ.id)
                triggered += 1
        except Exception as e:
            logger.error(f"Error executing scheduled sync for integration #{integ.id}: {e}", exc_info=True)

    return triggered
