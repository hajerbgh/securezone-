"""
PolicyEvaluator — Moteur de règles du Compliance Engine.

Rôle dans SecureZone :
  Évalue une HardeningPolicy sur un Asset et retourne
  COMPLIANT, NON_COMPLIANT ou NOT_APPLICABLE.

Types de règles supportées :
  - port_closed      : vérifie qu'un port est fermé sur l'asset
  - port_open        : vérifie qu'un port est ouvert (service requis)
  - os_version       : vérifie la version minimale d'OS
  - patch_applied    : vérifie qu'une CVE est patchée (non présente)
  - service_disabled : vérifie qu'un service n'est pas en écoute
  - tag_required     : vérifie que l'asset a un tag donné
  - field_value      : vérifie une valeur arbitraire sur l'asset
  - vuln_score_max   : vérifie que le risk_score est sous un seuil

Chaque évaluation retourne un EvalResult avec :
  - status  : COMPLIANT | NON_COMPLIANT | NOT_APPLICABLE
  - actual  : la valeur constatée sur l'asset
  - expected: la valeur attendue par la policy
  - detail  : explication textuelle pour le rapport
"""

import logging
from dataclasses import dataclass
from typing import Any

from app.models.compliance import ComplianceStatus
from app.models.asset import Asset

logger = logging.getLogger(__name__)


@dataclass
class EvalResult:
    """Résultat d'évaluation d'une règle sur un asset."""
    status: ComplianceStatus
    actual_value: Any
    expected_value: Any
    detail: str


class PolicyEvaluator:
    """
    Évalue une politique de durcissement sur un asset.

    Usage :
        evaluator = PolicyEvaluator()
        result = evaluator.evaluate(asset, policy)
    """

    # Rule types that need alert statistics (loaded by engine, not from asset fields)
    _ALERT_RULES = {"no_active_alerts", "no_brute_force", "no_phishing_detection"}

    def evaluate(
        self,
        asset: Asset,
        rule_type: str,
        rule_config: dict,
        open_cves: list = None,
        alert_stats: dict = None,
    ) -> EvalResult:
        """
        Dispatch vers la bonne méthode selon le type de règle.

        Args:
            asset        : l'asset à évaluer
            rule_type    : type de règle (voir module docstring)
            rule_config  : paramètres de la règle (JSON stocké en DB)
            open_cves    : liste de CVE IDs ouverts sur l'asset (pour patch_applied)
            alert_stats  : stats d'alertes pour l'IP de l'asset (pour no_brute_force, etc.)

        Returns:
            EvalResult avec le verdict et les détails
        """
        handler = getattr(self, f"_eval_{rule_type}", None)
        if handler is None:
            logger.warning(f"Type de règle inconnu : {rule_type}")
            return EvalResult(
                status=ComplianceStatus.NOT_APPLICABLE,
                actual_value=None,
                expected_value=None,
                detail=f"Type de règle '{rule_type}' non supporté",
            )

        try:
            if rule_type == "patch_applied":
                return handler(asset, rule_config, open_cves)
            if rule_type in self._ALERT_RULES:
                return handler(asset, rule_config, alert_stats or {})
            return handler(asset, rule_config)
        except Exception as e:
            logger.error(f"Erreur évaluation {rule_type} sur {asset.ip_address}: {e}")
            return EvalResult(
                status=ComplianceStatus.NOT_APPLICABLE,
                actual_value=None,
                expected_value=None,
                detail=f"Erreur lors de l'évaluation : {e}",
            )

    # ─────────────────────────────────────────────
    # Règles de ports
    # ─────────────────────────────────────────────

    def _eval_port_closed(self, asset: Asset, config: dict) -> EvalResult:
        """
        Vérifie qu'un port dangereux est FERMÉ.

        Exemple config : {"port": 3389, "protocol": "tcp"}
        Cas d'usage ISO 27001 A.13.1.1 / DORA Art.9 :
          RDP (3389), Telnet (23), FTP (21) ne doivent pas être exposés.
        """
        port = config.get("port")
        protocol = config.get("protocol", "tcp")

        open_ports = asset.open_ports or []
        matching = [
            p for p in open_ports
            if p.get("port") == port and p.get("protocol", "tcp") == protocol
        ]

        if matching:
            service = matching[0].get("service", "inconnu")
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"port": port, "state": "open", "service": service},
                expected_value={"port": port, "state": "closed"},
                detail=(
                    f"Port {port}/{protocol} ouvert ({service}) — doit être fermé. "
                    f"Non-conformité ISO 27001 A.13.1 / DORA Art.9 : exposition de surface d'attaque."
                ),
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"port": port, "state": "closed"},
            expected_value={"port": port, "state": "closed"},
            detail=f"Port {port}/{protocol} correctement fermé.",
        )

    def _eval_port_open(self, asset: Asset, config: dict) -> EvalResult:
        """
        Vérifie qu'un service requis est ACTIF.

        Exemple config : {"port": 22, "protocol": "tcp", "service": "ssh"}
        Cas d'usage : accès administratif sécurisé requis sur tous les serveurs.
        """
        port = config.get("port")
        protocol = config.get("protocol", "tcp")
        expected_service = config.get("service", "")

        open_ports = asset.open_ports or []
        matching = [
            p for p in open_ports
            if p.get("port") == port and p.get("protocol", "tcp") == protocol
        ]

        if not matching:
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"port": port, "state": "closed"},
                expected_value={"port": port, "state": "open", "service": expected_service},
                detail=f"Port {port}/{protocol} ({expected_service}) doit être ouvert mais n'est pas détecté.",
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"port": port, "state": "open", "service": matching[0].get("service")},
            expected_value={"port": port, "state": "open"},
            detail=f"Port {port}/{protocol} ouvert — service {matching[0].get('service', '?')} actif.",
        )

    # ─────────────────────────────────────────────
    # Règles système
    # ─────────────────────────────────────────────

    def _eval_os_version(self, asset: Asset, config: dict) -> EvalResult:
        """
        Vérifie que l'OS détecté contient le pattern requis.

        Exemple config : {"pattern": "Ubuntu 22", "min_version": "22.04"}
        Cas d'usage : pas de Windows Server 2008 R2 en production.
        """
        if not asset.os_name:
            return EvalResult(
                status=ComplianceStatus.NOT_APPLICABLE,
                actual_value=None,
                expected_value=config.get("pattern"),
                detail="OS non détecté — scan en mode discovery uniquement, relancer en mode full.",
            )

        pattern = config.get("pattern", "").lower()
        forbidden = config.get("forbidden_patterns", [])

        os_lower = asset.os_name.lower()

        # Vérifier les patterns interdits
        for fp in forbidden:
            if fp.lower() in os_lower:
                return EvalResult(
                    status=ComplianceStatus.NON_COMPLIANT,
                    actual_value=asset.os_name,
                    expected_value=f"OS non interdit (pattern: {fp})",
                    detail=(
                        f"OS '{asset.os_name}' contient le pattern interdit '{fp}'. "
                        f"Cet OS est en fin de support et ne reçoit plus les correctifs de sécurité."
                    ),
                )

        # Vérifier le pattern requis
        if pattern and pattern not in os_lower:
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value=asset.os_name,
                expected_value=f"OS contenant '{config.get('pattern')}'",
                detail=f"OS '{asset.os_name}' ne correspond pas au pattern attendu '{config.get('pattern')}'.",
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value=asset.os_name,
            expected_value=config.get("pattern"),
            detail=f"OS '{asset.os_name}' conforme à la politique.",
        )

    def _eval_service_disabled(self, asset: Asset, config: dict) -> EvalResult:
        """
        Vérifie qu'un service spécifique n'est pas en écoute.

        Exemple config : {"service_name": "telnet", "ports": [23]}
        Cas d'usage CIS Control 4.8 : désactiver les services inutilisés.
        """
        service_name = config.get("service_name", "").lower()
        forbidden_ports = config.get("ports", [])

        open_ports = asset.open_ports or []
        active = [
            p for p in open_ports
            if (service_name and service_name in p.get("service", "").lower())
            or (p.get("port") in forbidden_ports)
        ]

        if active:
            ports_found = [p.get("port") for p in active]
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"service": service_name, "ports_found": ports_found},
                expected_value={"service": service_name, "state": "disabled"},
                detail=(
                    f"Service '{service_name}' détecté sur les ports {ports_found}. "
                    f"Ce service doit être désactivé (CIS Control 4.8 — réduction de la surface d'attaque)."
                ),
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"service": service_name, "state": "not_detected"},
            expected_value={"service": service_name, "state": "disabled"},
            detail=f"Service '{service_name}' non détecté — conforme.",
        )

    # ─────────────────────────────────────────────
    # Règles de vulnérabilités
    # ─────────────────────────────────────────────

    def _eval_patch_applied(self, asset: Asset, config: dict, open_cves: list[str] = None) -> EvalResult:
        """
        Vérifie qu'une CVE critique n'est plus présente sur l'asset.

        Exemple config : {"cve_id": "CVE-2019-0708", "description": "BlueKeep"}
        Cas d'usage DORA Art.9 : correctifs critiques sous 30 jours.

        Note : nécessite la liste des CVEs ouvertes passée en paramètre
               (chargée en amont par le ComplianceEngine).
        """
        cve_id = config.get("cve_id", "")
        description = config.get("description", cve_id)

        if open_cves is None:
            return EvalResult(
                status=ComplianceStatus.NOT_APPLICABLE,
                actual_value=None,
                expected_value={"cve_id": cve_id, "status": "patched"},
                detail="Données de vulnérabilités non disponibles — lancer un scan VM.",
            )

        if cve_id in open_cves:
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"cve_id": cve_id, "status": "open"},
                expected_value={"cve_id": cve_id, "status": "patched"},
                detail=(
                    f"CVE {cve_id} ({description}) toujours ouverte sur cet asset. "
                    f"DORA Art.9 : les correctifs critiques doivent être appliqués dans les 30 jours."
                ),
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"cve_id": cve_id, "status": "not_detected"},
            expected_value={"cve_id": cve_id, "status": "patched"},
            detail=f"CVE {cve_id} non détectée — considérée comme patchée.",
        )

    def _eval_vuln_score_max(self, asset: Asset, config: dict) -> EvalResult:
        """
        Vérifie que le risk_score de l'asset est sous un seuil.

        Exemple config : {"max_score": 7.0}
        Cas d'usage ISO 27001 A.12.6 : risque résiduel acceptable.
        """
        max_score = config.get("max_score", 7.0)
        actual_score = asset.risk_score or 0.0

        if actual_score > max_score:
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"risk_score": actual_score},
                expected_value={"max_risk_score": max_score},
                detail=(
                    f"Risk score {actual_score:.1f} dépasse le seuil autorisé {max_score}. "
                    f"Des vulnérabilités critiques non traitées maintiennent un risque élevé."
                ),
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"risk_score": actual_score},
            expected_value={"max_risk_score": max_score},
            detail=f"Risk score {actual_score:.1f} sous le seuil {max_score} — conforme.",
        )

    # ─────────────────────────────────────────────
    # Règles organisationnelles
    # ─────────────────────────────────────────────

    def _eval_tag_required(self, asset: Asset, config: dict) -> EvalResult:
        """
        Vérifie que l'asset possède un tag obligatoire.

        Exemple config : {"tag": "classified", "description": "Données sensibles"}
        Cas d'usage ISO 27001 A.8.2 : classification des actifs.
        """
        required_tag = config.get("tag", "")
        asset_tags = [t.lower() for t in (asset.tags or [])]

        if required_tag.lower() not in asset_tags:
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"tags": asset.tags},
                expected_value={"required_tag": required_tag},
                detail=(
                    f"Tag obligatoire '{required_tag}' absent. "
                    f"ISO 27001 A.8.2 : tous les actifs doivent être classifiés."
                ),
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"tags": asset.tags},
            expected_value={"required_tag": required_tag},
            detail=f"Tag '{required_tag}' présent — classification conforme.",
        )

    def _eval_field_value(self, asset: Asset, config: dict) -> EvalResult:
        """
        Vérifie la valeur d'un champ de l'asset.

        Exemple config : {"field": "department", "expected": "IT", "operator": "equals"}
        Opérateurs : equals, not_null, contains
        """
        field = config.get("field", "")
        expected = config.get("expected")
        operator = config.get("operator", "not_null")

        actual = getattr(asset, field, None)

        if operator == "not_null":
            if actual is None or actual == "":
                return EvalResult(
                    status=ComplianceStatus.NON_COMPLIANT,
                    actual_value={field: actual},
                    expected_value={field: "non vide"},
                    detail=f"Champ '{field}' non renseigné — inventaire incomplet.",
                )
        elif operator == "equals":
            if actual != expected:
                return EvalResult(
                    status=ComplianceStatus.NON_COMPLIANT,
                    actual_value={field: actual},
                    expected_value={field: expected},
                    detail=f"Champ '{field}' = '{actual}' au lieu de '{expected}'.",
                )
        elif operator == "contains":
            if expected not in str(actual or ""):
                return EvalResult(
                    status=ComplianceStatus.NON_COMPLIANT,
                    actual_value={field: actual},
                    expected_value={field: f"contient '{expected}'"},
                    detail=f"Champ '{field}' = '{actual}' ne contient pas '{expected}'.",
                )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={field: actual},
            expected_value={field: expected},
            detail=f"Champ '{field}' conforme.",
        )

    # ─────────────────────────────────────────────
    # Règles basées sur les alertes SIEM
    # (données injectées par ComplianceEngine._load_alert_stats)
    # ─────────────────────────────────────────────

    def _eval_no_active_alerts(self, asset: Asset, config: dict, alert_stats: dict) -> EvalResult:
        """
        Vérifie qu'aucune alerte active n'est ouverte sur cet asset.

        Exemple config : {"max_alerts": 0, "categories": ["brute_force", "port_scan"]}
        Cas d'usage ISO 27001 A.16.1.4 : les incidents détectés doivent être traités.
        """
        max_allowed = config.get("max_alerts", 0)
        filter_cats = config.get("categories", [])

        if filter_cats:
            total = sum(alert_stats.get(cat, 0) for cat in filter_cats)
        else:
            total = alert_stats.get("total", 0)

        if total > max_allowed:
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"open_alerts": total},
                expected_value={"max_alerts": max_allowed},
                detail=(
                    f"{total} alerte(s) ouverte(s) sur cet asset. "
                    f"ISO 27001 A.16.1.4 : les événements de sécurité doivent être évalués et clôturés."
                ),
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"open_alerts": total},
            expected_value={"max_alerts": max_allowed},
            detail="Aucune alerte ouverte — posture d'incident conforme.",
        )

    def _eval_no_brute_force(self, asset: Asset, config: dict, alert_stats: dict) -> EvalResult:
        """
        Vérifie qu'aucune tentative de brute force active ne vise cet asset.

        Exemple config : {"max_attempts": 0}
        Cas d'usage DORA Art.9 / CIS Control 4.1 : accès non autorisés détectés et bloqués.
        """
        max_allowed = config.get("max_attempts", 0)
        bf_count = alert_stats.get("brute_force", 0)

        if bf_count > max_allowed:
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"brute_force_alerts": bf_count},
                expected_value={"max_attempts": max_allowed},
                detail=(
                    f"{bf_count} alerte(s) de brute force active(s) détectée(s) sur cet asset. "
                    f"DORA Art.9 : les tentatives d'accès non autorisés doivent être bloquées et tracées."
                ),
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"brute_force_alerts": bf_count},
            expected_value={"max_attempts": max_allowed},
            detail="Aucune tentative de brute force active — conforme.",
        )

    def _eval_no_phishing_detection(self, asset: Asset, config: dict, alert_stats: dict) -> EvalResult:
        """
        Vérifie qu'aucune navigation vers un site de phishing n'a été détectée
        depuis cet asset (via le proxy Squid).

        Exemple config : {"max_detections": 0}
        Cas d'usage ISO 27001 A.7.2.2 : sensibilisation et formation à la sécurité.
        """
        max_allowed = config.get("max_detections", 0)
        ph_count = alert_stats.get("phishing", 0)

        if ph_count > max_allowed:
            return EvalResult(
                status=ComplianceStatus.NON_COMPLIANT,
                actual_value={"phishing_detections": ph_count},
                expected_value={"max_detections": max_allowed},
                detail=(
                    f"{ph_count} détection(s) de navigation phishing depuis cet asset. "
                    f"ISO 27001 A.7.2.2 : indicateur de sensibilisation insuffisante aux cybermenaces."
                ),
            )

        return EvalResult(
            status=ComplianceStatus.COMPLIANT,
            actual_value={"phishing_detections": ph_count},
            expected_value={"max_detections": max_allowed},
            detail="Aucune navigation phishing détectée depuis cet asset — conforme.",
        )
