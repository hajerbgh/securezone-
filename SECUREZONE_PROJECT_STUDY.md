# Étude détaillée du projet SecureZone

## 1. Vue d'ensemble

SecureZone est une plateforme de cybersécurité unifiée combinant :

- un SIEM (Security Information and Event Management)
- un moteur VM (Vulnerability Management) avec Nmap et OpenVAS
- un moteur de conformité (Compliance)
- une interface web React
- une API backend FastAPI

L’objectif du projet est de détecter, corréler et prioriser les incidents de sécurité, puis d’identifier les vulnérabilités et les écarts de conformité sur un parc d’actifs.

## 2. Architecture générale

### 2.1 Composants principaux

- `backend/` : API FastAPI, pipeline SIEM, VM Engine, Compliance Engine, modèles SQLAlchemy
- `frontend/` : application React + Vite pour visualiser les alertes, scans, vulnérabilités et conformité
- `docker-compose.yml` : orchestration de l’ensemble des services
- `nginx/` : reverse-proxy, routage API / frontend et préparation pour SSL
- `wazuh/` : configuration Wazuh Manager

### 2.2 Infrastructure Docker

Le `docker-compose.yml` définit les services suivants :

- `postgres` : base de données PostgreSQL 16
- `redis` : cache et future file de tâches
- `elasticsearch` : indexation et recherche full-text
- `backend` : application Python FastAPI
- `frontend` : application React en dev ou build production
- `nginx` : reverse proxy et SSL termination
- `wazuh-manager` : collecte des alertes siem
- `kibana` : visualisation optionnelle (profil monitoring)

### 2.3 Flux de données global

1. Wazuh reçoit des logs d’agents et de périphériques réseau.
2. Le backend interroge Wazuh, normalise les alertes et détecte :
   - des anomalies par ML
   - des patterns multi-événements
   - des alertes simples significatives
3. Le backend persiste les alertes en base PostgreSQL.
4. Le moteur VM scanne les plages IP et alimente l’inventaire d’assets et de vulnérabilités.
5. Le moteur Compliance évalue les règles de durcissement sur les assets.
6. Le frontend React expose le tableau de bord et les écrans de gestion.

## 3. Backend FastAPI

### 3.1 Point d’entrée

Fichier : `backend/app/main.py`

- Crée la base de données au démarrage via SQLAlchemy `Base.metadata.create_all()`
- Lance le scheduler de scans `scan_scheduler.start()`
- Expose les routes API sous `/api/v1`
- Active CORS pour `ALLOWED_ORIGINS`
- Points de santé : `/health`

### 3.2 Routeur principal

Fichier : `backend/app/api/v1/router.py`

Sous-routeurs :

- `/auth` : authentification JWT
- `/assets` : inventaire des actifs
- `/alerts` : gestion des alertes SIEM
- `/scans` : gestion des scans de vulnérabilités
- `/vulnerabilities` : exploitation des vulnérabilités détectées
- `/compliance` : conformité, politiques, rapports
- `/siem` : moteur SIEM, collecte et recherche

## 4. Authentification et sécurité API

### 4.1 Authentification JWT

Fichiers : `backend/app/api/v1/endpoints/auth.py`, `backend/app/core/security.py`, `backend/app/api/deps.py`

- `POST /api/v1/auth/login` : retourne `access_token` et `refresh_token`
- `GET /api/v1/auth/me` : informations utilisateur
- `POST /api/v1/auth/users` : création d’utilisateur réservée admin

Méthode :

- stocke les mots de passe hachés via `bcrypt`
- encode/décode JWT avec `python-jose`
- expire les tokens d’accès après 60 min
- permissions : analyste vs admin

### 4.2 Contrôle d’accès

- `require_analyst` : accès aux opérations SIEM, scans, vulnérabilités, conformité
- `require_admin` : création d’utilisateurs, suppression de politiques
- `get_current_user` : charge l’utilisateur depuis le token JWT

## 5. Modules métier du backend

### 5.1 SIEM Engine

Fichier : `backend/app/services/siem/engine.py`

Pipeline SIEM :

1. Collecte des alertes Wazuh (`WazuhCollector`)
2. Normalisation (`LogNormalizer`)
3. Score d’anomalie ML (`AnomalyDetector`)
4. Corrélation multi-événements (`CorrelationEngine`)
5. Persistance en DB
6. Ré-entraînement ML toutes les 6 heures

#### 5.1.1 Collecteur Wazuh

Fichier : `backend/app/services/siem/wazuh_collector.py`

- Authentifie à l’API Wazuh via JWT
- Récupère les alertes paginées
- Récupère l’état des agents
- Garde un curseur sur le dernier timestamp traité
- Simule les alertes si Wazuh n’est pas disponible

Use cases :

- ingestion automatique depuis l’écosystème Wazuh
- collecte manuelle via `/siem/collect`
- ingestion d’un flux externe via `/siem/ingest`

#### 5.1.2 Normalisation des logs

Fichier : `backend/app/services/siem/normalizer.py`

Objectif : transformer un `RawAlert` Wazuh en `NormalizedEvent` générique.

Principales tâches :

- filtrage des alertes peu utiles (`level < 3`)
- mapping Wazuh `rule_id` et `rule_groups` vers `AlertCategory`
- enrichissement MITRE ATT&CK (technique, tactique)
- normalisation de la sévérité (`info`, `low`, `medium`, `high`, `critical`)
- extraction source/destination IP et ports
- construction de tags de corrélation

Cas d’usage :

- aligner les alertes Wazuh sur des catégories SIEM cohérentes
- préparer les données pour la corrélation et le scoring ML

#### 5.1.3 Détection d’anomalies ML

Fichier : `backend/app/services/siem/anomaly_detector.py`

Algorithme : `IsolationForest` de scikit-learn (non supervisé)

Features vecteur :

- heure du jour
- jour de la semaine
- sévérité
- port destination
- catégorie encodée
- IP source en octets
- hors heures bureau
- week-end

Seuil d’anomalie : score < -0.1

Comportements couverts :

- activité hors heures bureau
- IP source externe
- port éphémère suspects
- catégories inhabituelles

En production, cela permet de détecter des incidents inconnus ou des attaques ciblées non couvertes par les règles classiques.

#### 5.1.4 Corrélation multi-événements

Fichier : `backend/app/services/siem/correlator.py`

Règles implémentées :

- CR-001 : Brute Force SSH/RDP
- CR-002 : Scan de ports
- CR-003 : Scan multi-cibles
- CR-004 : Tentatives d’exploitation répétées
- CR-005 : Accès credentials suspectes
- CR-006 : Mouvement latéral

Mécanisme :

- fenêtre glissante en RAM par clé de corrélation
- `group_by_tags` : src, category, etc.
- seuils temporels définis par règle
- si le seuil est atteint, génère une `CorrelatedAlert`
- purge automatique des événements expirés

Valeur ajoutée : transformer plusieurs alertes faibles en un incident prioritaire, réduire le bruit et mieux contextualiser.

#### 5.1.5 Persistance des alertes

Fichier : `backend/app/models/alert.py`

Table `alerts` stocke :

- titre, description, sévérité, catégorie, statut
- source et destination réseau
- lien vers `asset`
- MITRE technique
- `risk_score`
- `event_count`, `first_seen`, `last_seen`
- `correlated_alert_ids`

Seules les alertes à haute valeur (high/critical ou anomalies) sont sauvegardées.

### 5.2 VM Engine

Fichier : `backend/app/services/vm/engine.py`

Objectif : scanner le parc réseau et évaluer les vulnérabilités.

Pipeline VM :

1. `ScanJob` créé en base
2. Nmap découvre hôtes et ports ouverts
3. OpenVAS analyse les services détectés
4. Vulnérabilités CVE sauvegardées
5. Risk score des assets recalculé
6. `ScanJob` passé à `completed`

#### 5.2.1 Nmap

Fichier : `backend/app/services/vm/nmap_scanner.py`

- wrapper autour de `python-nmap`
- modes de scan configurables
- exécute nmap dans un thread pool pour ne pas bloquer l’event loop
- simule les données si nmap absent

Rôle : identifier l’infrastructure active, les ports ouverts et les services exposés.

#### 5.2.2 OpenVAS

Fichier : `backend/app/services/vm/openvas_scanner.py`

- client HTTP vers l’API GMP OpenVAS
- crée target, task, puis interroge le rapport
- gère l’indisponibilité en mode simulation
- récupère CVE, score CVSS, vecteur, solution

Rôle : détecter des vulnérabilités exploitables sur les services découverts.

#### 5.2.3 ScanScheduler

Fichier : `backend/app/services/vm/scheduler.py`

- APScheduler planifie les scans selon `cron_expression`
- charge les jobs à partir de la base au démarrage
- supporte le déclenchement manuel et la tolérance de misfire
- crée des jobs d’exécution ponctuels pour les scans programmés

Use cases :

- scan de nuit automatique
- scans réguliers toutes les 6h ou hebdomadaires
- comparaison des vulnérabilités dans le temps

#### 5.2.4 Modèles de VM

Fichier : `backend/app/models/vulnerability.py`

Tables :

- `assets` : inventaire réseau, statut, OS, tags, scores
- `vulnerabilities` : CVE, CVSS, statut de remédiation
- `scan_jobs` : historique des scans

Scoring d’asset :

- pondération CVSS par gravité
- score plafonné à 10

### 5.3 Compliance Engine

Fichiers : `backend/app/services/compliance/engine.py`, `backend/app/services/compliance/evaluator.py`, `backend/app/services/compliance/pdf_report.py`

Fonctions :

- évalue des politiques de durcissement sur les assets
- calcule des `ComplianceCheck`
- met à jour `compliance_score` par asset
- fournit des dashboards et rapports
- génère des PDF d’audit

Politiques gérées :

- port_closed, port_open
- os_version
- service_disabled
- patch_applied
- vuln_score_max
- tag_required
- field_value

Cas d’usage :

- vérifier la fermeture de RDP
- vérifier le patch d’une CVE critique
- s’assurer qu’un asset a un tag `production`
- établir une posture de conformité ISO/DORA/CIS

### 5.4 Inventaire des actifs

Fichier : `backend/app/models/asset.py`

Chaque asset contient :

- IP, hostname, MAC
- type, statut, OS
- département, owner, tags
- `compliance_score`, `risk_score`
- `open_ports`, `software_inventory`
- `wazuh_agent_id`

Ce modèle fait le lien entre SIEM, VM et Compliance.

## 6. Endpoints détaillés

### 6.1 Authentification

- `POST /api/v1/auth/login`
  - entrée : `username`, `password`
  - sortie : `access_token`, `refresh_token`, `user`
- `GET /api/v1/auth/me`
  - récupère l’utilisateur connecté
- `POST /api/v1/auth/users`
  - crée un utilisateur (admin uniquement)

### 6.2 SIEM

- `GET /api/v1/siem/dashboard`
  - KPIs SIEM, top sources, top catégories, état moteur
- `POST /api/v1/siem/collect`
  - collecte Wazuh manuelle et traite les nouvelles alertes
- `POST /api/v1/siem/ingest`
  - ingestion de logs externes via JSON
- `GET /api/v1/siem/status`
  - état du SIEM Engine
- `GET /api/v1/siem/agents`
  - état des agents Wazuh
- `POST /api/v1/siem/alerts/search`
  - recherche textuelle et filtres sur les alertes
- `GET /api/v1/siem/mitre/summary`
  - résumé des techniques MITRE détectées

### 6.3 Alertes SIEM

- `GET /api/v1/alerts/`
  - liste filtrable par sévérité, statut, catégorie, asset
- `GET /api/v1/alerts/stats`
  - statistiques d’alertes
- `GET /api/v1/alerts/{alert_id}`
  - détails d’une alerte
- `PATCH /api/v1/alerts/{alert_id}`
  - mise à jour de statut, assignation, résolution

### 6.4 Assets

- `GET /api/v1/assets/`
  - liste d’assets filtrable
- `GET /api/v1/assets/stats`
  - KPIs d’inventaire
- `GET /api/v1/assets/{asset_id}`
  - détails asset
- `POST /api/v1/assets/`
  - créer un asset (admin)
- `PATCH /api/v1/assets/{asset_id}`
  - mise à jour asset
- `DELETE /api/v1/assets/{asset_id}`
  - suppression asset (admin)

### 6.5 Scans

- `POST /api/v1/scans/`
  - crée un scan immédiat ou planifié
- `GET /api/v1/scans/`
  - liste les jobs de scan
- `GET /api/v1/scans/scheduled`
  - liste les scans planifiés
- `GET /api/v1/scans/{id}`
  - détail d’un scan
- `POST /api/v1/scans/{id}/run`
  - déclenche un scan existant
- `DELETE /api/v1/scans/{id}`
  - supprime un scan (analyste/admin)

### 6.6 Vulnérabilités

- `GET /api/v1/vulnerabilities/`
  - liste les vulnérabilités filtrables
- `GET /api/v1/vulnerabilities/stats`
  - statistiques globales
- `GET /api/v1/vulnerabilities/{id}`
  - détail d’une vulnérabilité
- `PATCH /api/v1/vulnerabilities/{id}`
  - mise à jour du statut et des notes de remédiation

### 6.7 Compliance

- `GET /api/v1/compliance/dashboard`
  - KPIs de conformité
- `POST /api/v1/compliance/evaluate`
  - exécute une évaluation de conformité
- `GET /api/v1/compliance/policies`
  - liste des politiques de durcissement
- `POST /api/v1/compliance/policies`
  - crée une politique
- `GET /api/v1/compliance/policies/{id}`
  - détail d’une politique
- `PATCH /api/v1/compliance/policies/{id}`
  - modifie une politique
- `DELETE /api/v1/compliance/policies/{id}`
  - supprime une politique
- `GET /api/v1/compliance/checks`
  - liste des checks de conformité
- `GET /api/v1/compliance/checks/asset/{id}`
  - checks par asset
- `POST /api/v1/compliance/checks/{id}/exception`
  - accorde une exception sur un check
- `POST /api/v1/compliance/reports/generate`
  - génère un rapport PDF
- `GET /api/v1/compliance/reports`
  - liste des rapports
- `GET /api/v1/compliance/reports/{id}/download`
  - télécharge le PDF généré

## 7. Frontend React

### 7.1 Structure principale

- `frontend/src/main.jsx` : point d’entrée React
- `frontend/src/App.jsx` : routes de l’application
- `frontend/src/context/AuthContext.jsx` : stockage du token et de l’utilisateur
- `frontend/src/components/ProtectedRoute.jsx` : protection des routes
- `frontend/src/lib/api.js` : client Axios centralisé avec JWT
- `frontend/src/pages/` : vues métier (Dashboard, Alerts, Compliance, Incidents, Vulnerabilities, Login)

### 7.2 Appels API

- Toutes les requêtes vont vers `/api/v1/...`
- Le token est stocké dans `localStorage` sous `sz_token`
- Le frontend redirige vers `/login` si le backend renvoie `401`

### 7.3 UX de sécurité

- accès côté client protégé
- rafraîchissement des données périodique (dashboard)
- support d’une expérience SPA moderne

## 8. Scénarios métiers et cas d’usage réels

### 8.1 Détection d’attaque

1. Un agent Wazuh remonte plusieurs échecs d’authentification SSH.
2. Le collecteur Wazuh lit ces alertes.
3. Le normalizer catégorise en `brute_force`.
4. Le corrélateur détecte `CR-001` après 5 événements en 60s.
5. Une alerte corrélée `HIGH` est créée.
6. L’analyste voit l’incident prioritaire dans le dashboard.

### 8.2 Défense contre un scan réseau

1. Nmap découvre qu’un attaquant scanne plusieurs ports.
2. Les alertes réseau Wazuh ou logs externes sont classées `port_scan`.
3. `CR-002` ou `CR-003` se déclenche.
4. Le SIEM corrèle et génère une alerte multi-cibles.
5. L’équipe sécurité peut bloquer l’IP source et vérifier les bastions.

### 8.3 Détection d’anomalie inconnue

1. Un utilisateur tente des actions inhabituelles en dehors des heures.
2. Le modèle IsolationForest marque l’événement comme anomalie.
3. L’alerte est enrichie avec une raison (`activité à 23h`, `IP externe`).
4. Même sans règle explicite, l’incident remonte au SOC.

### 8.4 Gestion des vulnérabilités

1. Un scan VM trouve un service exposé.
2. OpenVAS identifie des CVE critiques.
3. Les vulnérabilités sont stockées dans `vulnerabilities`.
4. Le score d’asset augmente et devient visible sur la liste des assets.
5. L’équipe peut utiliser l’API `PATCH /vulnerabilities/{id}` pour suivre le statut.

### 8.5 Conformité et audit

1. Un responsable crée des politiques de durcissement.
2. Le ComplianceEngine évalue les assets via `POST /compliance/evaluate`.
3. Des checks non conformes sont générés.
4. Un rapport PDF est créé pour l’audit.
5. Une exception peut être accordée si le contrôle est justifié.

## 9. Pipeline ML et sécurité

### 9.1 Pipeline ML

- Données d’entrée : événements normalisés issus de Wazuh ou logs externes
- Pré-traitement : normalisation, mapping MITRE
- Entraînement : IsolationForest non supervisé sur les 1000 derniers événements
- Score d’anomalie : `score_samples` de scikit-learn
- Seuil : `ANOMALY_THRESHOLD = -0.1`
- Ré-entraînement : toutes les 6 heures ou manuellement via `retrain_if_needed()`

### 9.2 Valeur cyber

- détecte les incidents inconnus et les comportements basés sur structure
- combine règles statiques et détection basée sur comportement
- corrèle les événements pour réduire les faux positifs
- intègre MITRE ATT&CK pour contextualiser la menace

## 10. Mise en production

### 10.1 Commandes clés

- démarrage : `docker compose up -d`
- arrêt : `docker compose down`
- logs backend : `docker compose logs -f backend`
- vérifier l’état : `docker compose ps`

### 10.2 Variables d’environnement

Fichier : `backend/.env` ou variables Docker Compose

Principales variables :

- `DATABASE_URL`
- `REDIS_URL`
- `ELASTICSEARCH_URL`
- `WAZUH_MANAGER_URL`
- `WAZUH_API_USER`, `WAZUH_API_PASSWORD`
- `SECRET_KEY`
- `ALLOWED_ORIGINS`
- `SCAN_SCHEDULER_TIMEZONE`

### 10.3 Déploiement recommandé

- exécuter le backend en mode production via `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- construire le frontend en production et servir par Nginx
- activer SSL dans `nginx/conf.d/securezone.conf`
- déployer PostgreSQL, Redis, Elasticsearch, Wazuh sur des conteneurs ou VM séparés
- sécuriser les mots de passe et `SECRET_KEY`
- surveiller les logs et la santé des services

### 10.4 Points de production importants

- le backend crée automatiquement les tables SQL au démarrage
- le scheduler de scans est lancé dans le `lifespan` FastAPI
- les scans OpenVAS peuvent être longs → `proxy_read_timeout` large dans Nginx
- Elasticsearch est prévu pour indexation, mais l’indexation n’est pas visible dans le code actuel

## 11. Intégration dans le SI de l’entreprise

### 11.1 Intégration SIEM

- connecter Wazuh aux agents existants du parc
- utiliser `POST /siem/ingest` pour recevoir des logs externes (firewall, IDS, EDR)
- centraliser les alertes dans SecureZone
- exposer le dashboard aux analystes SOC

### 11.2 Intégration VM

- scanner les plages IP internes et externes autorisées
- planifier les scans par cron via `is_scheduled` dans `/scans`
- harmoniser les actifs découverts avec l’inventaire CMDB

### 11.3 Intégration Compliance

- créer des politiques ISO/DORA/CIS adaptées au périmètre
- exécuter les évaluations après chaque scan ou changement de configuration
- publier les rapports PDF aux auditeurs

### 11.4 Intégration opérationnelle

- identifier les rôles : admin, analyste, auditeur
- former les SOC/Infra à créer des scans et lire les alertes
- exploiter les scores `risk_score` et `compliance_score`
- lier les alertes à des tickets dans un ITSM externe si besoin

## 12. Démonstration recommandée

### 12.1 Scénario de démo

1. ouvrir l’application frontend
2. se connecter avec un utilisateur existant
3. afficher le dashboard SIEM et expliquer les KPI
4. lancer un scan de vulnérabilité immédiat
5. afficher le progrès du `ScanJob`
6. montrer les vulnérabilités détectées et l’asset impacté
7. exécuter `/compliance/evaluate` et afficher les résultats de conformité
8. démontrer `POST /siem/collect` pour collecter une alerte Wazuh et afficher la route d’investigation
9. créer un rapport PDF et montrer le téléchargement

### 12.2 Points à mettre en avant

- architecture modulaire : SIEM / VM / Compliance
- pipeline de traitement des alertes
- corrélation multi-événements et détection ML
- utilisation de Wazuh comme source de logs
- planification automatique des scans
- valeur business : priorisation et réduction du bruit

## 13. Points de vigilance possibles lors de la validation

- le modèle ML n’est pas supervisé, il détecte des anomalies structurelles
- la corrélation repose sur une fenêtre en mémoire ; en production, Redis serait plus adapté
- les règles de politique Compliance sont personnalisables mais nécessitent un référentiel métier
- OpenVAS et Wazuh doivent être déployés et accessibles pour une intégration réelle
- Elasticsearch est configuré, mais le code d’indexation full-text n’est pas développé dans les fichiers inspectés

## 14. Annexes techniques

### 14.1 Technologie utilisée

- Python 3.12, FastAPI, SQLAlchemy, asyncpg
- React, Vite, Axios, Recharts
- PostgreSQL, Redis, Elasticsearch
- Nginx
- Wazuh Manager
- Nmap, OpenVAS

### 14.2 Fichiers importants

- `backend/app/main.py`
- `backend/app/api/v1/router.py`
- `backend/app/services/siem/engine.py`
- `backend/app/services/siem/normalizer.py`
- `backend/app/services/siem/anomaly_detector.py`
- `backend/app/services/siem/correlator.py`
- `backend/app/services/vm/engine.py`
- `backend/app/services/vm/scheduler.py`
- `backend/app/services/compliance/engine.py`
- `backend/app/core/config.py`
- `docker-compose.yml`
- `nginx/conf.d/securezone.conf`

## 15. Conclusion

SecureZone est un projet de cybersécurité complet à mi-chemin entre un SOC et un outil de gestion de vulnérabilités/conformité. Il combine plusieurs couches : collecte Wazuh, normalisation, détection machine-learning, corrélation d’attaques, scans de vulnérabilités et contrôles de conformité.

Pour ton encadrant, l’axe principal à souligner est la valeur ajoutée :

- visibilité centralisée des incidents
- priorisation automatique
- détection à la fois par règles et par comportement
- intégration d’un inventaire d’actifs et d’un moteur de conformité
- déploiement Docker simple et séparation claire des composants
