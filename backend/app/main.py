import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.config import settings, BASE_DIR
from app.database import init_db
from app.api import (
    routes_auth,
    routes_users,
    routes_asset_groups,
    routes_scans,
    routes_dashboard,
    routes_comparative,
    routes_vulnerabilities,
    routes_ldap,
    routes_reports,
    routes_parameters,
    routes_action_plans,
    routes_integrations,
    routes_jobs
)
import asyncio
from app.database import SessionLocal
from app.services.integrations.scheduler import check_and_run_scheduled_syncs
from app.services.job_queue import job_queue_worker

async def background_scheduler():
    while True:
        try:
            await asyncio.sleep(60)
            db = SessionLocal()
            try:
                check_and_run_scheduled_syncs(db)
            finally:
                db.close()
        except asyncio.CancelledError:
            break
        except Exception:
            pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables and seed default admin user
    init_db()
    worker_task = asyncio.create_task(job_queue_worker())
    sched_task = asyncio.create_task(background_scheduler())
    yield
    worker_task.cancel()
    sched_task.cancel()
    try:
        await asyncio.gather(worker_task, sched_task, return_exceptions=True)
    except asyncio.CancelledError:
        pass

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Sistema Web de Gerenciamento de Vulnerabilidades com Importação Nessus CSV, Governança ISO 27000 e ISO 9000.",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
api_prefix = settings.API_V1_STR
app.include_router(routes_auth.router, prefix=api_prefix)
app.include_router(routes_users.router, prefix=api_prefix)
app.include_router(routes_ldap.router, prefix=api_prefix)
app.include_router(routes_asset_groups.router, prefix=api_prefix)
app.include_router(routes_scans.router, prefix=api_prefix)
app.include_router(routes_dashboard.router, prefix=api_prefix)
app.include_router(routes_comparative.router, prefix=api_prefix)
app.include_router(routes_vulnerabilities.router, prefix=api_prefix)
app.include_router(routes_reports.router, prefix=api_prefix)
app.include_router(routes_parameters.router, prefix=api_prefix)
app.include_router(routes_action_plans.router, prefix=api_prefix)
app.include_router(routes_action_plans.router, prefix="/api/v1")
app.include_router(routes_integrations.router, prefix=f"{api_prefix}/integrations", tags=["Integrations"])
app.include_router(routes_jobs.router, prefix=api_prefix)

@app.get(f"{api_prefix}/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION
    }

# Mount Frontend Static Directory
frontend_dir = BASE_DIR / "frontend" / "public"
frontend_dir.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str, request: Request):
    """Serves the Single Page Application or specific static files."""
    if full_path.startswith("api"):
        return {"detail": "Not Found"}
    
    file_path = frontend_dir / full_path
    if file_path.is_file():
        return FileResponse(file_path, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
    
    index_file = frontend_dir / "index.html"
    if index_file.is_file():
        return FileResponse(index_file, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
        
    return {"message": "GvulStand API is running. Frontend index.html not found yet."}
