"""
AnomalyDetector — Détection d'anomalies comportementales par ML.

Rôle dans le SIEM :
  Les règles de corrélation détectent les attaques connues.
  L'AnomalyDetector détecte les comportements INHABITUELS
  — même inconnus — en apprenant ce qui est "normal".

Algorithme : Isolation Forest (scikit-learn)
  L'Isolation Forest isole les points anormaux en les coupant
  avec des hyperplans aléatoires. Les points faciles à isoler
  (peu de coupures nécessaires) sont les anomalies.

  Avantage : pas besoin d'exemples d'attaques (non supervisé).
  Il apprend le "normal" et signale tout ce qui s'en écarte.

Features utilisées (vecteur numérique par alerte) :
  - Heure de la journée (0-23)
  - Jour de la semaine (0-6, 0=lundi)
  - Sévérité Wazuh (1-15)
  - Port de destination
  - Catégorie encodée numériquement
  - IP source en octets (4 features)
  - Indicateur "hors heures bureau" (0/1)

Phase d'apprentissage :
  Le modèle s'entraîne sur les 1000 derniers événements stockés.
  Il se ré-entraîne automatiquement toutes les 6 heures.

Score d'anomalie :
  Isolation Forest retourne un score entre -1 et 1.
  score < -0.1 → anomalie détectée (seuil configurable).
"""

import logging
import numpy as np
from datetime import datetime, timezone
from typing import Optional

from app.services.siem.normalizer import NormalizedEvent
from app.models.alert import AlertCategory, AlertSeverity

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn non disponible — AnomalyDetector en mode simulation")

# Mapping catégorie → entier pour la vectorisation
CATEGORY_ENCODING = {
    AlertCategory.BRUTE_FORCE:       1,
    AlertCategory.PORT_SCAN:         2,
    AlertCategory.SQL_INJECTION:     3,
    AlertCategory.COMMAND_EXEC:      4,
    AlertCategory.CREDENTIAL_ACCESS: 5,
    AlertCategory.LATERAL_MOVEMENT:  6,
    AlertCategory.EXFILTRATION:      7,
    AlertCategory.ANOMALY:           8,
    AlertCategory.VULNERABILITY:     9,
    AlertCategory.COMPLIANCE:        10,
    AlertCategory.OTHER:             0,
}

# Seuil du score Isolation Forest sous lequel on considère une anomalie
ANOMALY_THRESHOLD = -0.1

# Heures bureau (8h-18h en semaine)
BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 18


class AnomalyDetector:
    """
    Détecteur d'anomalies comportementales basé sur Isolation Forest.

    Cycle de vie :
        detector = AnomalyDetector()
        detector.train(historical_events)      # Apprendre le normal
        result = detector.score(new_event)     # Scorer un nouvel événement
        if result.is_anomaly:
            await create_alert(result)

    Le modèle se ré-entraîne automatiquement toutes les 6 heures
    via le SIEMEngine (appel à retrain_if_needed()).
    """

    def __init__(self, contamination: float = 0.05):
        """
        Args:
            contamination : proportion estimée d'anomalies dans le jeu
                            d'entraînement (5% par défaut)
        """
        self.contamination = contamination
        self._model: Optional[object] = None      # IsolationForest
        self._scaler: Optional[object] = None     # StandardScaler
        self._trained = False
        self._training_count = 0
        self._last_trained: Optional[datetime] = None

        # Buffer des événements récents pour l'entraînement
        self._training_buffer: list[NormalizedEvent] = []
        self.min_training_samples = 100           # Minimum pour entraîner

    # ─────────────────────────────────────────────
    # Interface principale
    # ─────────────────────────────────────────────

    def add_to_buffer(self, event: NormalizedEvent):
        """
        Ajoute un événement au buffer d'entraînement.
        Garde les 2000 derniers événements (fenêtre glissante).
        """
        self._training_buffer.append(event)
        if len(self._training_buffer) > 2000:
            self._training_buffer = self._training_buffer[-2000:]

    def train(self, events: list[NormalizedEvent] = None) -> bool:
        """
        Entraîne le modèle Isolation Forest.

        Args:
            events : liste d'événements historiques (None = utiliser le buffer)

        Returns:
            True si l'entraînement a réussi
        """
        if not SKLEARN_AVAILABLE:
            logger.info("AnomalyDetector : sklearn absent, entraînement simulé")
            self._trained = True
            return True

        training_data = events or self._training_buffer
        if len(training_data) < self.min_training_samples:
            logger.info(
                f"AnomalyDetector : {len(training_data)} événements insuffisants "
                f"(minimum {self.min_training_samples})"
            )
            return False

        try:
            X = np.array([self._vectorize(ev) for ev in training_data])

            # Normaliser les features (IsolationForest est sensible aux échelles)
            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)

            # Entraîner le modèle
            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=100,        # Nombre d'arbres
                max_samples="auto",
                random_state=42,
                n_jobs=-1,               # Utiliser tous les CPUs
            )
            self._model.fit(X_scaled)

            self._trained = True
            self._training_count = len(training_data)
            self._last_trained = datetime.now(timezone.utc)
            logger.info(
                f"AnomalyDetector entraîné sur {len(training_data)} événements"
            )
            return True

        except Exception as e:
            logger.error(f"Erreur entraînement AnomalyDetector : {e}")
            return False

    def score(self, event: NormalizedEvent) -> "AnomalyResult":
        """
        Score un événement et retourne le résultat de détection.

        Si le modèle n'est pas encore entraîné, retourne NOT_SCORED
        (l'événement sera traité normalement sans anomalie ML).
        """
        if not self._trained:
            return AnomalyResult(
                event=event,
                anomaly_score=0.0,
                is_anomaly=False,
                reason="Modèle non entraîné",
            )

        if not SKLEARN_AVAILABLE:
            return self._mock_score(event)

        try:
            X = np.array([self._vectorize(event)])
            X_scaled = self._scaler.transform(X)

            # score_samples retourne un score de décision (plus négatif = plus anormal)
            score = float(self._model.score_samples(X_scaled)[0])
            is_anomaly = score < ANOMALY_THRESHOLD

            reason = self._explain_anomaly(event, score) if is_anomaly else ""

            return AnomalyResult(
                event=event,
                anomaly_score=round(score, 3),
                is_anomaly=is_anomaly,
                reason=reason,
            )

        except Exception as e:
            logger.error(f"Erreur scoring AnomalyDetector : {e}")
            return AnomalyResult(event=event, anomaly_score=0.0, is_anomaly=False, reason=str(e))

    def retrain_if_needed(self, force: bool = False) -> bool:
        """
        Ré-entraîne si 6h se sont écoulées ou si force=True.
        Appelé régulièrement par le SIEMEngine.
        """
        if not force and self._last_trained:
            from datetime import timedelta
            elapsed = datetime.now(timezone.utc) - self._last_trained
            if elapsed.total_seconds() < 6 * 3600:
                return False

        return self.train()

    # ─────────────────────────────────────────────
    # Vectorisation
    # ─────────────────────────────────────────────

    def _vectorize(self, event: NormalizedEvent) -> list[float]:
        """
        Transforme un NormalizedEvent en vecteur numérique.

        Features :
          [0] heure (0-23)
          [1] jour semaine (0-6)
          [2] sévérité (1-5 : info=1 … critical=5)
          [3] port destination (0 si inconnu)
          [4] catégorie encodée (0-10)
          [5] IP source octet 1
          [6] IP source octet 2
          [7] IP source octet 3
          [8] IP source octet 4
          [9] hors heures bureau (0/1)
          [10] week-end (0/1)
        """
        ts = event.timestamp
        hour = ts.hour
        weekday = ts.weekday()

        severity_map = {
            AlertSeverity.INFO: 1, AlertSeverity.LOW: 2,
            AlertSeverity.MEDIUM: 3, AlertSeverity.HIGH: 4,
            AlertSeverity.CRITICAL: 5,
        }
        severity_num = severity_map.get(event.severity, 3)

        dst_port = event.destination_port or 0

        category_num = CATEGORY_ENCODING.get(event.category, 0)

        # Décomposer l'IP source en octets
        ip_octets = [0, 0, 0, 0]
        if event.source_ip:
            try:
                parts = event.source_ip.split(".")
                ip_octets = [int(p) for p in parts[:4]]
            except Exception:
                pass

        outside_hours = 1 if (hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END) else 0
        is_weekend = 1 if weekday >= 5 else 0

        return [
            float(hour),
            float(weekday),
            float(severity_num),
            float(min(dst_port, 65535)),
            float(category_num),
            float(ip_octets[0]),
            float(ip_octets[1]),
            float(ip_octets[2]),
            float(ip_octets[3]),
            float(outside_hours),
            float(is_weekend),
        ]

    def _explain_anomaly(self, event: NormalizedEvent, score: float) -> str:
        """Génère une explication lisible de l'anomalie."""
        ts = event.timestamp
        reasons = []

        # Hors heures bureau ?
        if ts.hour < BUSINESS_HOURS_START or ts.hour >= BUSINESS_HOURS_END:
            reasons.append(f"activité à {ts.hour}h (hors heures bureau)")

        # Week-end ?
        if ts.weekday() >= 5:
            reasons.append("activité le week-end")

        # IP externe ?
        if event.source_ip and not (
            event.source_ip.startswith("10.") or
            event.source_ip.startswith("192.168.") or
            event.source_ip.startswith("172.")
        ):
            reasons.append(f"IP source externe ({event.source_ip})")

        # Port inhabituel ?
        if event.destination_port and event.destination_port > 49151:
            reasons.append(f"port éphémère ({event.destination_port})")

        base = f"Comportement inhabituel (score={score:.3f})"
        if reasons:
            return base + " : " + ", ".join(reasons)
        return base

    def _mock_score(self, event: NormalizedEvent) -> "AnomalyResult":
        """Score simulé quand sklearn n'est pas disponible."""
        ts = event.timestamp
        # Simuler une anomalie pour les événements hors heures bureau
        is_outside = ts.hour < BUSINESS_HOURS_START or ts.hour >= BUSINESS_HOURS_END
        score = -0.25 if (is_outside and event.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)) else 0.1
        return AnomalyResult(
            event=event,
            anomaly_score=score,
            is_anomaly=score < ANOMALY_THRESHOLD,
            reason=self._explain_anomaly(event, score) if score < ANOMALY_THRESHOLD else "",
        )

    def get_stats(self) -> dict:
        return {
            "trained":          self._trained,
            "training_samples": self._training_count,
            "last_trained":     self._last_trained.isoformat() if self._last_trained else None,
            "buffer_size":      len(self._training_buffer),
            "sklearn_available": SKLEARN_AVAILABLE,
        }


class AnomalyResult:
    """Résultat de la détection d'anomalie pour un événement."""

    def __init__(
        self,
        event: NormalizedEvent,
        anomaly_score: float,
        is_anomaly: bool,
        reason: str = "",
    ):
        self.event = event
        self.anomaly_score = anomaly_score
        self.is_anomaly = is_anomaly
        self.reason = reason

        # Si anomalie : augmenter le risk_score de l'événement
        if is_anomaly:
            boost = min(2.0, abs(anomaly_score) * 5)
            self.adjusted_risk_score = min(10.0, round(event.risk_score + boost, 1))
        else:
            self.adjusted_risk_score = event.risk_score
