"""
SOAR Executor — Exécution des actions automatisées de réponse aux incidents.

Chaque action reçoit l'incident et l'alerte source, et retourne un résultat
stocké dans PlaybookAction.execution_result.

Types d'actions supportées :
  trigger_scan        AUTO  — Déclenche un scan VM sur l'IP cible
  run_compliance      AUTO  — Lance une évaluation de conformité complète
  log_ioc             AUTO  — Enregistre l'IP/domaine comme IOC dans l'incident
  send_notification   AUTO  — Envoie une notification email à l'équipe SOC
  block_ip            MANUAL — Affiche la commande iptables à exécuter
  squid_blacklist     MANUAL — Affiche la config Squid à ajouter
  manual_task         MANUAL — Tâche manuelle à confirmer par l'analyste
"""

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident, PlaybookAction

logger = logging.getLogger(__name__)


class SOARExecutor:
    """
    Exécute les actions SOAR d'un incident.

    Pour les actions AUTO  : exécution immédiate, résultat stocké.
    Pour les actions MANUAL: retourne les instructions exactes à suivre,
                              l'analyste les applique puis confirme.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def execute(
        self,
        action: PlaybookAction,
        incident: Incident,
        alert=None,
    ) -> str:
        handler = getattr(self, f"_run_{action.action_type}", None)
        if handler is None:
            return f"Type d'action '{action.action_type}' non implémenté."

        try:
            result = await handler(action, incident, alert)
            if isinstance(result, dict):
                import json
                return json.dumps(result, ensure_ascii=False, indent=2)
            return str(result)
        except Exception as e:
            logger.error(f"SOAR action {action.action_type} échouée: {e}")
            return f"Erreur: {e}"

    # ─────────────────────────────────────────────
    # Actions AUTO
    # ─────────────────────────────────────────────

    async def _run_trigger_scan(self, action: PlaybookAction, incident: Incident, alert) -> dict:
        """Déclenche un scan VM sur l'IP cible de l'incident."""
        from app.models.vulnerability import ScanJob
        from app.services.vm.engine import VMEngine

        target_ip = self._get_target_ip(incident, alert)
        if not target_ip:
            return {"status": "skipped", "reason": "Aucune IP cible identifiée dans l'incident."}

        job = ScanJob(
            name=f"[IR #{incident.id}] Scan auto — {target_ip}",
            ip_ranges=[target_ip],
            exclude_ips=[],
            scanner_type="nmap",
            is_scheduled=False,
            status="pending",
        )
        self.db.add(job)
        await self.db.flush()
        await self.db.refresh(job)

        # Lancer en background (on schedule le job, le scheduler le ramasse)
        import asyncio
        from app.db.session import AsyncSessionLocal
        from app.api.v1.endpoints.scans import _run_scan_background

        asyncio.ensure_future(_run_scan_background(job.id))

        return {
            "status": "launched",
            "scan_job_id": job.id,
            "target": target_ip,
            "message": f"Scan VM lancé sur {target_ip} (Job #{job.id})",
        }

    async def _run_run_compliance(self, action: PlaybookAction, incident: Incident, alert) -> dict:
        """Lance une évaluation de conformité complète."""
        from app.services.compliance.engine import ComplianceEngine

        engine = ComplianceEngine(self.db)
        result = await engine.run_full_evaluation()
        return {
            "status": "completed",
            "assets_evaluated": result.get("assets_evaluated", 0),
            "total_checks": result.get("total_checks", 0),
        }

    async def _run_log_ioc(self, action: PlaybookAction, incident: Incident, alert) -> dict:
        """Enregistre les IOCs (IP source, domaine phishing) dans l'incident."""
        iocs = list(incident.ioc_list or [])
        added = []

        if alert:
            for ip in [alert.source_ip, alert.destination_ip]:
                if ip and ip not in iocs:
                    iocs.append(ip)
                    added.append(ip)

            # Extraire le domaine du titre pour les alertes phishing
            if alert.category and "phishing" in str(alert.category).lower():
                title = alert.title or ""
                for word in title.split():
                    if "." in word and "/" not in word and len(word) < 100:
                        domain = word.strip("[]():,")
                        if domain and domain not in iocs:
                            iocs.append(domain)
                            added.append(domain)

        incident.ioc_list = iocs
        return {
            "status": "ok",
            "iocs_added": added,
            "total_iocs": len(iocs),
        }

    async def _run_send_notification(self, action: PlaybookAction, incident: Incident, alert) -> dict:
        """Envoie une notification email à l'équipe SOC."""
        from app.core.config import settings
        import smtplib
        from email.mime.text import MIMEText

        body = (
            f"[SecureZone IR] Incident #{incident.id} — {incident.severity.upper()}\n\n"
            f"Titre : {incident.title}\n"
            f"Statut : {incident.status}\n"
            f"IOCs : {', '.join(incident.ioc_list or []) or 'aucun'}\n\n"
            f"Accédez au dashboard : http://localhost:5173/incidents\n"
        )

        if not settings.SMTP_HOST or not settings.SMTP_USER:
            return {
                "status": "skipped",
                "reason": "SMTP non configuré — notification simulée.",
                "would_send_to": settings.SMTP_FROM,
                "body": body,
            }

        try:
            msg = MIMEText(body)
            msg["Subject"] = f"[SECUREZONE] Incident #{incident.id} — {incident.title[:50]}"
            msg["From"] = settings.SMTP_FROM
            msg["To"] = settings.SMTP_USER
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=5) as s:
                if settings.SMTP_PASSWORD:
                    s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                s.send_message(msg)
            return {"status": "sent", "to": settings.SMTP_USER}
        except Exception as e:
            return {"status": "failed", "error": str(e), "body_preview": body[:200]}

    # ─────────────────────────────────────────────
    # Actions MANUAL — Retournent les instructions
    # ─────────────────────────────────────────────

    async def _run_block_ip(self, action: PlaybookAction, incident: Incident, alert) -> dict:
        """Fournit les commandes iptables pour bloquer l'IP source."""
        src_ip = self._get_source_ip(incident, alert)
        if not src_ip:
            return {"type": "manual", "status": "no_target", "message": "IP source non identifiée."}

        return {
            "type": "manual_command",
            "target_host": "Ubuntu — 192.168.8.130",
            "commands": [
                f"sudo iptables -A INPUT -s {src_ip} -j DROP",
                f"sudo iptables -A FORWARD -s {src_ip} -j DROP",
                f"sudo iptables-save | sudo tee /etc/iptables/rules.v4",
            ],
            "verify": f"sudo iptables -L INPUT -n | grep {src_ip}",
            "rollback": f"sudo iptables -D INPUT -s {src_ip} -j DROP",
            "message": f"Exécuter ces commandes sur le firewall Ubuntu pour bloquer {src_ip}.",
        }

    async def _run_squid_blacklist(self, action: PlaybookAction, incident: Incident, alert) -> dict:
        """Fournit les commandes pour blacklister le domaine dans Squid."""
        domain = self._get_phishing_domain(incident, alert)

        return {
            "type": "manual_command",
            "target_host": "Ubuntu Squid — 192.168.8.130",
            "commands": [
                f"echo '.{domain}' | sudo tee -a /etc/squid/blacklists.conf",
                "sudo systemctl reload squid",
            ],
            "verify": f"grep '{domain}' /etc/squid/blacklists.conf",
            "rollback": f"sudo sed -i '/.{domain}/d' /etc/squid/blacklists.conf && sudo systemctl reload squid",
            "message": f"Ajouter le domaine '{domain}' à la blacklist Squid pour bloquer les futures navigations.",
        }

    async def _run_manual_task(self, action: PlaybookAction, incident: Incident, alert) -> dict:
        return {
            "type": "manual",
            "message": action.description or "Tâche manuelle — confirmez son exécution dans l'interface.",
        }

    # ─────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────

    def _get_target_ip(self, incident: Incident, alert) -> Optional[str]:
        """IP cible = destination de l'attaque (l'asset à scanner)."""
        if alert and alert.destination_ip:
            return alert.destination_ip
        if incident.ioc_list:
            # Prendre la première IP (pas un domaine)
            for ioc in incident.ioc_list:
                if self._is_ip(ioc):
                    return ioc
        return None

    def _get_source_ip(self, incident: Incident, alert) -> Optional[str]:
        """IP source = l'attaquant."""
        if alert and alert.source_ip:
            return alert.source_ip
        if incident.ioc_list:
            for ioc in incident.ioc_list:
                if self._is_ip(ioc):
                    return ioc
        return None

    def _get_phishing_domain(self, incident: Incident, alert) -> str:
        """Domaine de phishing depuis les IOCs."""
        for ioc in (incident.ioc_list or []):
            if not self._is_ip(ioc) and "." in ioc:
                return ioc
        return "domain-inconnu.tld"

    @staticmethod
    def _is_ip(s: str) -> bool:
        parts = s.split(".")
        return len(parts) == 4 and all(p.isdigit() for p in parts)
