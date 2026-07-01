from fastapi import APIRouter
from app.api.v1.endpoints import auth, assets, alerts, scans, vulnerabilities, compliance, siem, phishing, reports, chat, incidents

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router,            prefix="/auth")
api_router.include_router(assets.router,          prefix="/assets")
api_router.include_router(alerts.router,          prefix="/alerts")
api_router.include_router(scans.router,           prefix="/scans")
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities")
api_router.include_router(compliance.router,      prefix="/compliance")
api_router.include_router(siem.router,            prefix="/siem")
api_router.include_router(phishing.router,        prefix="/phishing")
api_router.include_router(reports.router,         prefix="/reports")
api_router.include_router(chat.router,            prefix="/chat")
api_router.include_router(incidents.router,       prefix="/incidents")
