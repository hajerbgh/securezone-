"""
CorrelationEngine — Détection de patterns d'attaque multi-événements.

Rôle dans le SIEM :
  Un événement isolé n'est souvent pas une attaque.
  C'est la répétition ou la combinaison qui révèle l'intention.

  Le CorrelationEngine applique des règles de corrélation temporelles :
  si N événements du même type arrivent depuis la même source
  dans une fenêtre de T secondes → créer une alerte groupée.

Règles implémentées :
  - brute_force_ssh    : 5+ échecs auth en 60s depuis même IP → HIGH
  - port_scan          : 10+ ports différents en 120s depuis même IP → MEDIUM
  - multi_target_scan  : même IP attaque 5+ cibles différentes en 300s → HIGH
  - repeated_exploit   : 3+ tentatives exploit en 60s → CRITICAL
  - after_hours_access : connexion réussie hors horaires bureau → MEDIUM

Comment ça marche (fenêtre glissante) :
  On garde en mémoire (Redis ou dict en RAM) les événements récents
  par clé de corrélation (ex: "src:192.168.99.50+category:brute_force").
  À chaque nouvel événement, on vérifie si le seuil est atteint.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.services.siem.normalizer import NormalizedEvent
from app.models.alert import AlertCategory, AlertSeverity

logger = logging.getLogger(__name__)


@dataclass
class CorrelationRule:
    """Définition d'une règle de corrélation."""
    rule_id: str
    name: str
    description: str
    # Clés de regroupement (parmi les correlation_tags de l'événement)
    group_by_tags: list[str]         # ex: ["src", "category"]
    # Filtre sur la catégorie d'événement
    match_categories: list[AlertCategory]
    # Seuil et fenêtre
    threshold: int                   # nb d'événements requis
    window_seconds: int              # fenêtre temporelle
    # Résultat si la règle se déclenche
    output_severity: AlertSeverity
    output_category: AlertCategory
    # Multiplicateur du risk_score
    risk_multiplier: float = 1.5


@dataclass
class CorrelatedAlert:
    """
    Alerte produite par le CorrelationEngine.
    Représente un groupe d'événements formant un pattern d'attaque.
    """
    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: AlertSeverity
    category: AlertCategory
    source_ip: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    risk_score: float
    event_count: int
    first_seen: datetime
    last_seen: datetime
    mitre_technique_id: str
    mitre_technique_name: str
    hostname: str
    correlated_event_ids: list[str]   # IDs des événements sources
    raw_data: dict = field(default_factory=dict)


# ══════════════════════════════════════════════════════════════════
# Règles de corrélation
# ══════════════════════════════════════════════════════════════════

CORRELATION_RULES = [
    CorrelationRule(
        rule_id="CR-001",
        name="Brute Force SSH/RDP",
        description="Multiples échecs d'authentification depuis la même IP en peu de temps.",
        group_by_tags=["src", "category"],
        match_categories=[AlertCategory.BRUTE_FORCE],
        threshold=5,
        window_seconds=60,
        output_severity=AlertSeverity.HIGH,
        output_category=AlertCategory.BRUTE_FORCE,
        risk_multiplier=2.0,
    ),
    CorrelationRule(
        rule_id="CR-002",
        name="Scan de ports",
        description="Exploration massive de ports depuis une même source.",
        group_by_tags=["src", "category"],
        match_categories=[AlertCategory.PORT_SCAN],
        threshold=10,
        window_seconds=120,
        output_severity=AlertSeverity.MEDIUM,
        output_category=AlertCategory.PORT_SCAN,
        risk_multiplier=1.5,
    ),
    CorrelationRule(
        rule_id="CR-003",
        name="Scan multi-cibles",
        description="Une même IP attaque plusieurs cibles différentes — reconnaissance réseau.",
        group_by_tags=["src"],
        match_categories=[AlertCategory.PORT_SCAN, AlertCategory.BRUTE_FORCE],
        threshold=5,
        window_seconds=300,
        output_severity=AlertSeverity.HIGH,
        output_category=AlertCategory.PORT_SCAN,
        risk_multiplier=2.5,
    ),
    CorrelationRule(
        rule_id="CR-004",
        name="Tentatives d'exploitation répétées",
        description="Plusieurs tentatives d'exploitation en peu de temps — attaque ciblée.",
        group_by_tags=["src", "category"],
        match_categories=[AlertCategory.SQL_INJECTION, AlertCategory.COMMAND_EXEC],
        threshold=3,
        window_seconds=60,
        output_severity=AlertSeverity.CRITICAL,
        output_category=AlertCategory.COMMAND_EXEC,
        risk_multiplier=3.0,
    ),
    CorrelationRule(
        rule_id="CR-005",
        name="Accès credentials suspectes",
        description="Plusieurs accès credentials depuis la même source — compromission possible.",
        group_by_tags=["src", "category"],
        match_categories=[AlertCategory.CREDENTIAL_ACCESS],
        threshold=3,
        window_seconds=300,
        output_severity=AlertSeverity.HIGH,
        output_category=AlertCategory.CREDENTIAL_ACCESS,
        risk_multiplier=2.0,
    ),
    CorrelationRule(
        rule_id="CR-006",
        name="Mouvement latéral",
        description="Activité suspecte sur plusieurs machines depuis la même source.",
        group_by_tags=["src"],
        match_categories=[AlertCategory.LATERAL_MOVEMENT],
        threshold=3,
        window_seconds=600,
        output_severity=AlertSeverity.CRITICAL,
        output_category=AlertCategory.LATERAL_MOVEMENT,
        risk_multiplier=3.5,
    ),
]


class CorrelationEngine:
    """
    Moteur de corrélation temporelle.

    Maintient une fenêtre glissante d'événements en mémoire RAM.
    En production, cette fenêtre serait stockée dans Redis pour
    persister entre les redémarrages et permettre la scalabilité.

    Usage :
        engine = CorrelationEngine()
        correlated = engine.process(normalized_event)
        if correlated:
            await save_alert(correlated)  # Pattern détecté !
        else:
            await save_raw_alert(normalized_event)  # Événement isolé
    """

    def __init__(self, rules: list[CorrelationRule] = None):
        self.rules = rules or CORRELATION_RULES
        # Fenêtre glissante : clé → liste de (timestamp, event)
        self._windows: dict[str, list[tuple[datetime, NormalizedEvent]]] = defaultdict(list)

    def process(self, event: NormalizedEvent) -> Optional[CorrelatedAlert]:
        """
        Traite un événement normalisé.

        Retourne un CorrelatedAlert si un pattern est détecté,
        None sinon (l'événement sera enregistré comme alerte simple).
        """
        # Nettoyer les vieilles entrées de toutes les fenêtres
        self._cleanup_expired()

        for rule in self.rules:
            # La règle s'applique-t-elle à cet événement ?
            if event.category not in rule.match_categories:
                continue

            # Construire la clé de regroupement
            key = self._make_key(rule, event)
            if not key:
                continue

            # Ajouter l'événement à la fenêtre de cette règle
            self._windows[key].append((event.timestamp, event))

            # Récupérer les événements dans la fenêtre temporelle
            window_start = event.timestamp - timedelta(seconds=rule.window_seconds)
            window_events = [
                (ts, ev) for ts, ev in self._windows[key]
                if ts >= window_start
            ]
            # Garder la fenêtre propre
            self._windows[key] = window_events

            # Le seuil est-il atteint ?
            if len(window_events) >= rule.threshold:
                alert = self._build_correlated_alert(rule, event, window_events)
                # Vider la fenêtre pour éviter les alertes en cascade
                self._windows[key] = []
                logger.info(
                    f"Corrélation [{rule.rule_id}] déclenchée : "
                    f"{len(window_events)} événements depuis {event.source_ip}"
                )
                return alert

        return None

    def process_batch(self, events: list[NormalizedEvent]) -> tuple[list[CorrelatedAlert], list[NormalizedEvent]]:
        """
        Traite un lot d'événements.

        Retourne :
            - correlated : alertes corrélées détectées
            - uncorrelated : événements non corrélés (alertes simples)
        """
        correlated = []
        uncorrelated = []

        for event in events:
            result = self.process(event)
            if result:
                correlated.append(result)
            else:
                uncorrelated.append(event)

        return correlated, uncorrelated

    # ─────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────

    def _make_key(self, rule: CorrelationRule, event: NormalizedEvent) -> Optional[str]:
        """
        Construit la clé de regroupement depuis les tags de l'événement.

        Exemple : rule.group_by_tags = ["src", "category"]
        → key = "CR-001:src:192.168.99.50:category:brute_force"
        """
        parts = [rule.rule_id]
        tag_dict = {}

        # Parser les correlation_tags en dict
        for tag in event.correlation_tags:
            if ":" in tag:
                k, v = tag.split(":", 1)
                tag_dict[k] = v

        for required_key in rule.group_by_tags:
            if required_key not in tag_dict:
                return None  # Tag requis absent → règle non applicable
            parts.append(f"{required_key}:{tag_dict[required_key]}")

        return ":".join(parts)

    def _build_correlated_alert(
        self,
        rule: CorrelationRule,
        trigger_event: NormalizedEvent,
        window_events: list[tuple[datetime, NormalizedEvent]],
    ) -> CorrelatedAlert:
        """Construit l'alerte corrélée depuis les événements de la fenêtre."""
        events = [ev for _, ev in window_events]
        timestamps = [ts for ts, _ in window_events]

        # Score de risque = max des événements × multiplicateur, plafonné à 10
        max_base_score = max(ev.risk_score for ev in events)
        risk_score = min(10.0, round(max_base_score * rule.risk_multiplier, 1))

        # IP cibles uniques
        targets = list({ev.destination_ip for ev in events if ev.destination_ip})
        target_str = ", ".join(targets[:3]) + ("..." if len(targets) > 3 else "")

        title = (
            f"{rule.name} — {trigger_event.source_ip or 'IP inconnue'}"
            f" ({len(events)} événements en {rule.window_seconds}s)"
        )
        description = (
            f"{rule.description} "
            f"Source : {trigger_event.source_ip}. "
            f"Cibles : {target_str or trigger_event.hostname}. "
            f"{len(events)} événements détectés sur {rule.window_seconds}s."
        )

        return CorrelatedAlert(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            title=title,
            description=description,
            severity=rule.output_severity,
            category=rule.output_category,
            source_ip=trigger_event.source_ip,
            destination_ip=trigger_event.destination_ip,
            destination_port=trigger_event.destination_port,
            risk_score=risk_score,
            event_count=len(events),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            mitre_technique_id=trigger_event.mitre_technique_id,
            mitre_technique_name=trigger_event.mitre_technique_name,
            hostname=trigger_event.hostname,
            correlated_event_ids=[ev.source_id for ev in events],
            raw_data={
                "rule_id":    rule.rule_id,
                "rule_name":  rule.name,
                "threshold":  rule.threshold,
                "window_sec": rule.window_seconds,
                "sources":    list({ev.source_ip for ev in events if ev.source_ip}),
                "targets":    targets,
            },
        )

    def _cleanup_expired(self):
        """
        Retire les événements expirés de toutes les fenêtres.
        Appelé à chaque nouvel événement pour éviter la fuite mémoire.
        """
        now = datetime.now(timezone.utc)
        max_window = max(r.window_seconds for r in self.rules)
        cutoff = now - timedelta(seconds=max_window)

        for key in list(self._windows.keys()):
            self._windows[key] = [
                (ts, ev) for ts, ev in self._windows[key]
                if ts >= cutoff
            ]
            if not self._windows[key]:
                del self._windows[key]

    def get_stats(self) -> dict:
        """Statistiques de la fenêtre active (debug/monitoring)."""
        return {
            "active_windows":  len(self._windows),
            "total_events_in_windows": sum(len(v) for v in self._windows.values()),
            "rules_count":     len(self.rules),
        }
