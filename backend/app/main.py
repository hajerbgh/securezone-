from contextlib import asynccontextmanager
import logging
from sqlalchemy import text
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.api.v1.router import api_router
from app.db.session import engine, Base

logger = logging.getLogger(__name__)


async def _run_migrations():
    """
    Migrations incrémentales — chaque instruction dans sa propre transaction.
    Un échec (colonne/type déjà existant) n'annule pas les suivantes.
    """
    steps = [
        # Enum pour la criticité des assets
        # CREATE TYPE ne supporte pas IF NOT EXISTS → on attrape l'erreur si déjà présent
        ("assetcriticality enum",
         "CREATE TYPE assetcriticality AS ENUM ('low', 'medium', 'high', 'critical')"),

        # scan_jobs
        ("scan_jobs.exclude_ips",
         "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS exclude_ips JSON DEFAULT '[]'::json"),
        ("scan_jobs.port_range",
         "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS port_range VARCHAR(50)"),

        # assets
        ("assets.criticality",
         "ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality assetcriticality NOT NULL DEFAULT 'medium'"),

        # vulnerabilities
        ("vulnerabilities.first_seen",
         "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ"),
        ("vulnerabilities.last_seen",
         "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ"),
    ]

    # ALTER TYPE ADD VALUE ne peut pas s'exécuter dans une transaction → AUTOCOMMIT
    try:
        async with engine.connect() as conn:
            await conn.execution_options(isolation_level="AUTOCOMMIT")
            await conn.execute(text(
                "ALTER TYPE alertcategory ADD VALUE IF NOT EXISTS 'PHISHING'"
            ))
        logger.info("Migration OK : alertcategory += phishing")
    except Exception as e:
        logger.debug(f"Migration ignorée (alertcategory phishing) : {str(e)[:120]}")

    for label, sql in steps:
        # Chaque migration dans sa propre transaction indépendante
        try:
            async with engine.begin() as conn:
                await conn.execute(text(sql))
            logger.info(f"Migration OK : {label}")
        except Exception as e:
            err = str(e)[:120]
            logger.debug(f"Migration ignorée ({label}) — déjà appliquée ou incompatible : {err}")

    logger.info("Migrations DB terminées")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup : créer les tables puis appliquer les migrations incrémentales
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await _run_migrations()

    # Démarrer le scheduler de scans
    from app.services.vm.scheduler import scan_scheduler
    await scan_scheduler.start()

    yield

    # Shutdown
    from app.services.vm.scheduler import scan_scheduler
    await scan_scheduler.stop()
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Plateforme unifiée de sécurité — SIEM · VM · Compliance · IR",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/", include_in_schema=False)
async def root():
    return JSONResponse({
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "docs": "/docs",
    })


@app.get("/health", tags=["Monitoring"])
async def health_check():
    return {"status": "ok", "version": settings.APP_VERSION}
