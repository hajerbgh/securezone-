"""
ComplianceEngine — Orchestrateur du Compliance Engine.

Rôle dans SecureZone :
  1. Charge toutes les HardeningPolicies actives
  2. Pour chaque asset dans le scope, évalue chaque policy via PolicyEvaluator
  3. Persiste les ComplianceCheck en DB (upsert)
  4. Recalcule le compliance_score de chaque asset (0–100)
  5. Calcule les scores globaux par département et par framework

Formule du compliance_score d'un asset :
  score = (nb_compliant / nb_applicable) × 100
  - Les checks NOT_APPLICABLE ne comptent pas
  - Les exceptions accordées comptent comme COMPLIANT

Score global d'un département :
  moyenne pondérée des scores de ses assets
  (pondération par criticité : serveurs × 2, workstations × 1)
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset, AssetType
from app.models.compliance import (
    HardeningPolicy, ComplianceCheck, ComplianceStatus, PolicyFramework
)
from app.models.vulnerability import Vulnerability, VulnStatus
from app.services.compliance.evaluator import PolicyEvaluator

logger = logging.getLogger(__name__)

# Poids par type d'asset pour le calcul du score global
ASSET_WEIGHT = {
    AssetType.SERVER:      3.0,
    AssetType.FIREWALL:    3.0,
    AssetType.ROUTER:      2.0,
    AssetType.SWITCH:      2.0,
    AssetType.WORKSTATION: 1.0,
    AssetType.PRINTER:     0.5,
    AssetType.IOT:         0.5,
    AssetType.UNKNOWN:     1.0,
}


class ComplianceEngine:
    """
    Orchestrateur principal du Compliance Engine.

    Usage :
        engine = ComplianceEngine(db)
        report = await engine.run_full_evaluation()
        # → évalue tous les assets contre toutes les policies actives

        report = await engine.run_for_asset(asset_id=42)
        # → évalue un seul asset (après modification manuelle)
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.evaluator = PolicyEvaluator()

    # ─────────────────────────────────────────────
    # Points d'entrée
    # ─────────────────────────────────────────────

    async def run_full_evaluation(
        self,
        framework: Optional[PolicyFramework] = None,
        department: Optional[str] = None,
    ) -> dict:
        """
        Lance une évaluation complète sur tout le parc ou un sous-ensemble.

        Args:
            framework  : filtrer sur un framework (ISO27001, DORA, CIS, tous)
            department : filtrer sur un département

        Returns:
            dict avec les scores globaux et statistiques
        """
        logger.info(f"ComplianceEngine démarré | framework={framework} | department={department}")

        # Charger les policies actives
        policies = await self._load_policies(framework)
        if not policies:
            logger.warning("Aucune politique active trouvée")
            return {"status": "no_policies", "assets_evaluated": 0}

        # Charger les assets dans le scope
        assets = await self._load_assets(department)
        if not assets:
            logger.warning("Aucun asset dans le scope")
            return {"status": "no_assets", "assets_evaluated": 0}

        logger.info(f"{len(policies)} policies × {len(assets)} assets = {len(policies) * len(assets)} checks")

        # Pré-charger les CVEs ouvertes par asset (évite N+1 queries)
        cves_by_asset = await self._load_open_cves_by_asset()

        # Pré-charger les stats d'alertes SIEM par IP (pour règles alert-based)
        alert_stats_by_ip = await self._load_alert_stats()

        # Évaluer chaque combinaison asset × policy
        total_checks = 0
        for asset in assets:
            open_cves = cves_by_asset.get(asset.id, [])
            alert_data = alert_stats_by_ip.get(asset.ip_address, {"brute_force": 0, "phishing": 0, "total": 0})
            checks_count = await self._evaluate_asset(asset, policies, open_cves, alert_data)
            total_checks += checks_count

        await self.db.flush()

        # Recalculer les compliance_scores
        scores = await self._recalculate_all_scores(assets)

        summary = {
            "status":           "completed",
            "assets_evaluated": len(assets),
            "policies_applied": len(policies),
            "total_checks":     total_checks,
            "scores":           scores,
        }
        logger.info(f"ComplianceEngine terminé : {summary}")
        return summary

    async def run_for_asset(self, asset_id: int) -> dict:
        """Évalue un seul asset contre toutes les policies actives."""
        asset_result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
        asset = asset_result.scalar_one_or_none()
        if not asset:
            raise ValueError(f"Asset #{asset_id} introuvable")

        policies = await self._load_policies()
        open_cves = (await self._load_open_cves_by_asset()).get(asset_id, [])
        alert_data = (await self._load_alert_stats()).get(asset.ip_address, {"brute_force": 0, "phishing": 0, "total": 0})

        checks_count = await self._evaluate_asset(asset, policies, open_cves, alert_data)
        await self.db.flush()

        score = await self._recalculate_asset_score(asset)
        return {
            "asset_id":    asset_id,
            "checks_run":  checks_count,
            "score":       score,
        }

    # ─────────────────────────────────────────────
    # Évaluation d'un asset
    # ─────────────────────────────────────────────

    async def _evaluate_asset(
        self,
        asset: Asset,
        policies: list[HardeningPolicy],
        open_cves: list[str],
        alert_stats: dict = None,
    ) -> int:
        """Évalue toutes les policies applicables sur un asset."""
        count = 0

        for policy in policies:
            # Vérifier si la policy s'applique à cet asset
            if not self._policy_applies_to(policy, asset):
                continue

            # Évaluer la règle
            result = self.evaluator.evaluate(
                asset=asset,
                rule_type=policy.rule_type,
                rule_config=policy.rule_config,
                open_cves=open_cves,
                alert_stats=alert_stats or {},
            )

            # Upsert du ComplianceCheck en DB
            await self._upsert_check(asset, policy, result)
            count += 1

        return count

    def _policy_applies_to(self, policy: HardeningPolicy, asset: Asset) -> bool:
        """
        Vérifie si une policy s'applique à un asset donné.

        Une policy sans filtre (listes vides) s'applique à TOUS les assets.
        Si des filtres sont définis, l'asset doit satisfaire AU MOINS UN critère
        dans chaque filtre non vide.
        """
        # Filtre par tags
        if policy.applies_to_tags:
            asset_tags = set(asset.tags or [])
            if not asset_tags.intersection(set(policy.applies_to_tags)):
                return False

        # Filtre par type d'asset
        if policy.applies_to_asset_types:
            if asset.asset_type.value not in policy.applies_to_asset_types:
                return False

        # Filtre par département
        if policy.applies_to_departments:
            if asset.department not in policy.applies_to_departments:
                return False

        return True

    # ─────────────────────────────────────────────
    # Persistance des checks
    # ─────────────────────────────────────────────

    async def _upsert_check(
        self,
        asset: Asset,
        policy: HardeningPolicy,
        result,
    ) -> ComplianceCheck:
        """Crée ou met à jour un ComplianceCheck."""
        existing_result = await self.db.execute(
            select(ComplianceCheck).where(
                ComplianceCheck.asset_id == asset.id,
                ComplianceCheck.policy_id == policy.id,
            )
        )
        check = existing_result.scalar_one_or_none()

        if not check:
            check = ComplianceCheck(
                asset_id=asset.id,
                policy_id=policy.id,
            )
            self.db.add(check)

        # Ne pas écraser une exception accordée
        if check.exception_granted:
            check.status = ComplianceStatus.COMPLIANT
        else:
            check.status = result.status

        check.checked_at = datetime.now(timezone.utc)
        check.actual_value = result.actual_value
        check.expected_value = result.expected_value
        check.details = result.detail

        return check

    # ─────────────────────────────────────────────
    # Calcul des scores
    # ─────────────────────────────────────────────

    async def _recalculate_all_scores(self, assets: list[Asset]) -> dict:
        """
        Recalcule compliance_score pour chaque asset
        et retourne les scores agrégés.
        """
        scores_by_dept: dict[str, list[float]] = {}

        for asset in assets:
            score = await self._recalculate_asset_score(asset)
            dept = asset.department or "Non assigné"
            scores_by_dept.setdefault(dept, []).append(score)

        # Score global = moyenne pondérée
        all_scores = [a.compliance_score for a in assets if a.compliance_score is not None]
        global_score = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0

        dept_scores = {
            dept: round(sum(scores) / len(scores), 1)
            for dept, scores in scores_by_dept.items()
        }

        await self.db.flush()

        return {
            "global_score":       global_score,
            "scores_by_dept":     dept_scores,
            "total_assets":       len(assets),
            "avg_score":          global_score,
        }

    async def _recalculate_asset_score(self, asset: Asset) -> float:
        """
        Calcule le compliance_score d'un asset.

        Score = (nb_compliant / nb_applicable) × 100
        NOT_APPLICABLE exclus du calcul.
        Exceptions accordées comptent comme COMPLIANT.
        """
        checks_result = await self.db.execute(
            select(ComplianceCheck).where(ComplianceCheck.asset_id == asset.id)
        )
        checks = checks_result.scalars().all()

        # Exclure NOT_APPLICABLE et NOT_CHECKED
        applicable = [
            c for c in checks
            if c.status not in (ComplianceStatus.NOT_APPLICABLE, ComplianceStatus.NOT_CHECKED)
        ]

        if not applicable:
            asset.compliance_score = 0.0
            return 0.0

        compliant = sum(
            1 for c in applicable
            if c.status == ComplianceStatus.COMPLIANT
        )
        partial = sum(
            0.5 for c in applicable
            if c.status == ComplianceStatus.PARTIALLY_COMPLIANT
        )

        score = round(((compliant + partial) / len(applicable)) * 100, 1)
        asset.compliance_score = score
        return score

    # ─────────────────────────────────────────────
    # Helpers DB
    # ─────────────────────────────────────────────

    async def _load_policies(
        self,
        framework: Optional[PolicyFramework] = None,
    ) -> list[HardeningPolicy]:
        query = select(HardeningPolicy).where(HardeningPolicy.is_active == True)
        if framework:
            query = query.where(HardeningPolicy.framework == framework)
        result = await self.db.execute(query)
        return result.scalars().all()

    async def _load_assets(self, department: Optional[str] = None) -> list[Asset]:
        query = select(Asset)
        if department:
            query = query.where(Asset.department == department)
        result = await self.db.execute(query)
        return result.scalars().all()

    async def _load_alert_stats(self) -> dict[str, dict]:
        """
        Charge les stats d'alertes SIEM ouvertes, indexées par IP.

        Pour les attaques (brute force, port scan…) : destination_ip = l'asset victime.
        Pour le phishing : source_ip = l'asset qui a navigué vers l'URL de phishing.

        Retourne : {ip: {"brute_force": N, "phishing": N, "total": N}}
        """
        from app.models.alert import Alert, AlertCategory, AlertStatus

        result = await self.db.execute(
            select(Alert.destination_ip, Alert.source_ip, Alert.category).where(
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING])
            )
        )

        stats: dict[str, dict] = {}

        def _ensure(ip: str):
            if ip not in stats:
                stats[ip] = {"brute_force": 0, "phishing": 0, "total": 0}

        for dest_ip, src_ip, category in result:
            if category == AlertCategory.PHISHING:
                # Source = la machine qui a cliqué sur le lien phishing
                if src_ip:
                    _ensure(src_ip)
                    stats[src_ip]["phishing"] += 1
                    stats[src_ip]["total"] += 1
            else:
                # Destination = l'asset cible de l'attaque
                if dest_ip:
                    _ensure(dest_ip)
                    stats[dest_ip]["total"] += 1
                    if category == AlertCategory.BRUTE_FORCE:
                        stats[dest_ip]["brute_force"] += 1

        return stats

    async def _load_open_cves_by_asset(self) -> dict[int, list[str]]:
        """
        Pré-charge toutes les CVEs ouvertes groupées par asset_id.
        Évite de faire une requête par asset dans la boucle d'évaluation.
        """
        result = await self.db.execute(
            select(Vulnerability.asset_id, Vulnerability.cve_id).where(
                Vulnerability.status == VulnStatus.OPEN,
                Vulnerability.cve_id.isnot(None),
            )
        )
        cves_by_asset: dict[int, list[str]] = {}
        for asset_id, cve_id in result:
            cves_by_asset.setdefault(asset_id, []).append(cve_id)
        return cves_by_asset

    # ─────────────────────────────────────────────
    # Statistiques globales
    # ─────────────────────────────────────────────

    async def get_dashboard_stats(self) -> dict:
        """
        Retourne les KPIs du dashboard Compliance.
        Appel rapide — pas d'évaluation, juste lecture des scores existants.
        """
        from sqlalchemy import func

        # Score global moyen
        avg_score = await self.db.scalar(
            select(func.avg(Asset.compliance_score))
        ) or 0.0

        # Checks par statut
        for_status = {}
        for status in ComplianceStatus:
            count = await self.db.scalar(
                select(func.count(ComplianceCheck.id)).where(
                    ComplianceCheck.status == status
                )
            ) or 0
            for_status[status.value] = count

        # Assets non conformes (score < 70%)
        non_compliant_assets = await self.db.scalar(
            select(func.count(Asset.id)).where(Asset.compliance_score < 70)
        ) or 0

        # Top 5 policies les plus violées
        violations = await self.db.execute(
            select(
                HardeningPolicy.name,
                HardeningPolicy.framework,
                func.count(ComplianceCheck.id).label("violations")
            )
            .join(ComplianceCheck, ComplianceCheck.policy_id == HardeningPolicy.id)
            .where(ComplianceCheck.status == ComplianceStatus.NON_COMPLIANT)
            .group_by(HardeningPolicy.id, HardeningPolicy.name, HardeningPolicy.framework)
            .order_by(func.count(ComplianceCheck.id).desc())
            .limit(5)
        )
        top_violations = [
            {"policy": row[0], "framework": row[1], "violations": row[2]}
            for row in violations
        ]

        return {
            "global_score":          round(avg_score, 1),
            "non_compliant_assets":  non_compliant_assets,
            "checks_by_status":      for_status,
            "top_violated_policies": top_violations,
        }
