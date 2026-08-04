"""
Script de seed — Playbooks de réponse aux incidents.

7 playbooks pour le lab SecureZone :
  1. Brute Force       — log IOC → scan VM → [MANUAL] bloquer IP iptables
  2. Phishing          — log IOC → scan poste → [MANUAL] blacklist Squid → notifier
  3. Port Scan         — log IOC → évaluation conformité → [MANUAL] investiguer
  4. Generic High      — scan VM → [MANUAL] analyser → [MANUAL] containment
  5. DDoS              — log IOC → compliance → rate_limit_asset (AUTO) → notifier
  6. Ransomware        — log IOC → scan VM → [MANUAL] isolate_host → [MANUAL] sauvegardes
  7. Exfiltration      — log IOC → compliance → [MANUAL] identifier données → [MANUAL] block_ip

Usage :
    cd backend && .\\venv\\Scripts\\python.exe scripts/seed_playbooks.py
"""

import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PLAYBOOKS = [
    {
        "name": "Réponse Brute Force",
        "description": "Playbook de réponse aux tentatives d'intrusion par brute force (SSH, RDP, etc.).",
        "trigger_category": "brute_force",
        "trigger_severity_min": "high",
        "mitre_techniques": ["T1110", "T1021"],
        "steps": [
            {
                "order": 1,
                "title": "Enregistrer les IOCs",
                "action_type": "log_ioc",
                "description": "Logger l'IP source de l'attaquant et l'asset cible comme IOCs dans l'incident.",
                "requires_approval": False,
            },
            {
                "order": 2,
                "title": "Scanner les vulnérabilités de l'asset ciblé",
                "action_type": "trigger_scan",
                "description": "Lancer un scan VM sur l'asset cible pour détecter d'éventuelles failles exploitables.",
                "requires_approval": False,
            },
            {
                "order": 3,
                "title": "Bloquer l'IP source sur le firewall",
                "action_type": "block_ip",
                "description": "Ajouter une règle iptables sur le firewall Ubuntu pour bloquer l'IP de l'attaquant.",
                "requires_approval": True,
            },
            {
                "order": 4,
                "title": "Vérifier et réinitialiser les credentials compromis",
                "action_type": "manual_task",
                "description": "Identifier les comptes ciblés et forcer un reset du mot de passe. Vérifier les logs d'authentification.",
                "requires_approval": True,
            },
        ],
    },
    {
        "name": "Réponse Phishing",
        "description": "Playbook de réponse à la détection d'une navigation vers un site de phishing.",
        "trigger_category": "phishing",
        "trigger_severity_min": "medium",
        "mitre_techniques": ["T1566", "T1598"],
        "steps": [
            {
                "order": 1,
                "title": "Enregistrer les IOCs (URL / domaine de phishing)",
                "action_type": "log_ioc",
                "description": "Logger le domaine phishing et l'IP du poste source comme IOCs.",
                "requires_approval": False,
            },
            {
                "order": 2,
                "title": "Scanner le poste ayant cliqué",
                "action_type": "trigger_scan",
                "description": "Vérifier si le poste est compromis (malware, backdoor) suite au clic.",
                "requires_approval": False,
            },
            {
                "order": 3,
                "title": "Blacklister le domaine phishing dans Squid",
                "action_type": "squid_blacklist",
                "description": "Ajouter le domaine phishing dans /etc/squid/blacklists.conf pour bloquer tous les accès futurs.",
                "requires_approval": True,
            },
            {
                "order": 4,
                "title": "Notifier l'équipe SOC et l'utilisateur",
                "action_type": "send_notification",
                "description": "Envoyer une notification à l'équipe SOC et sensibiliser l'utilisateur concerné.",
                "requires_approval": False,
            },
            {
                "order": 5,
                "title": "Session de sensibilisation utilisateur",
                "action_type": "manual_task",
                "description": "Organiser une session de sensibilisation avec l'utilisateur. Documenter dans l'incident.",
                "requires_approval": True,
            },
        ],
    },
    {
        "name": "Réponse Port Scan / Reconnaissance",
        "description": "Playbook de réponse à une tentative de reconnaissance réseau (scan de ports).",
        "trigger_category": "port_scan",
        "trigger_severity_min": "medium",
        "mitre_techniques": ["T1046", "T1595"],
        "steps": [
            {
                "order": 1,
                "title": "Enregistrer l'IP source comme IOC",
                "action_type": "log_ioc",
                "description": "Logger l'IP de la sonde et les assets ciblés.",
                "requires_approval": False,
            },
            {
                "order": 2,
                "title": "Évaluer la conformité des assets exposés",
                "action_type": "run_compliance",
                "description": "Vérifier que les assets scannés respectent les politiques de sécurité (ports ouverts, patches).",
                "requires_approval": False,
            },
            {
                "order": 3,
                "title": "Identifier la source (interne / externe ?)",
                "action_type": "manual_task",
                "description": "Déterminer si l'IP source est un scanner légitime (pentest), une machine compromise, ou une attaque externe.",
                "requires_approval": True,
            },
            {
                "order": 4,
                "title": "Bloquer si source malveillante",
                "action_type": "block_ip",
                "description": "Si l'IP est identifiée comme malveillante, bloquer via iptables.",
                "requires_approval": True,
            },
        ],
    },
    {
        "name": "Réponse Générique (Haute Sévérité)",
        "description": "Playbook générique pour les alertes critiques/hautes sans playbook spécifique.",
        "trigger_category": "generic_high",
        "trigger_severity_min": "high",
        "mitre_techniques": [],
        "steps": [
            {
                "order": 1,
                "title": "Enregistrer les IOCs",
                "action_type": "log_ioc",
                "description": "Logger les IPs et indicateurs de compromission.",
                "requires_approval": False,
            },
            {
                "order": 2,
                "title": "Scanner l'asset impliqué",
                "action_type": "trigger_scan",
                "description": "Lancer un scan de vulnérabilités sur l'asset concerné.",
                "requires_approval": False,
            },
            {
                "order": 3,
                "title": "Analyser et qualifier l'incident",
                "action_type": "manual_task",
                "description": "L'analyste SOC doit investiguer l'alerte et qualifier l'incident (vrai positif / faux positif, vecteur d'attaque).",
                "requires_approval": True,
            },
            {
                "order": 4,
                "title": "Décision de containment",
                "action_type": "manual_task",
                "description": "Décider et exécuter les mesures de containment adaptées (isolation réseau, blocage IP, désactivation compte, etc.).",
                "requires_approval": True,
            },
        ],
    },

    # ══════════════════════════════════════════════════════════════
    # 5. DDoS — 100% automatisable (rate-limiting réversible)
    # Déclenché par catégorie ddos (future règle CR-007)
    # ══════════════════════════════════════════════════════════════
    {
        "name": "Réponse DDoS",
        "description": (
            "Réponse à une attaque DDoS : multi-sources vers un même asset. "
            "100% automatisable — le rate-limiting est réversible et auto-expirant, "
            "sans bloquer d'IP individuelles (risque de faux positifs sur IPs usurpées)."
        ),
        "trigger_category": "ddos",
        "trigger_severity_min": "high",
        "mitre_techniques": ["T1498", "T1499"],
        "steps": [
            {
                "order": 1,
                "title": "Enregistrer les IPs sources impliquées",
                "action_type": "log_ioc",
                "description": "Logger l'ensemble des IPs sources du botnet et l'asset ciblé comme IOCs.",
                "requires_approval": False,
            },
            {
                "order": 2,
                "title": "Réévaluer la conformité de l'asset ciblé",
                "action_type": "run_compliance",
                "description": "Vérifier que l'asset ciblé respecte les politiques de hardening (exposition inutile de services, etc.).",
                "requires_approval": False,
            },
            {
                "order": 3,
                "title": "Appliquer un rate-limiting sur l'asset ciblé",
                "action_type": "rate_limit_asset",
                "description": (
                    "Appliquer une limite temporaire de connexions/sec sur l'asset visé via iptables hashlimit. "
                    "Auto-expire après 10 minutes — jamais de blocage IP individuel. "
                    "Réversible sans impact collatéral."
                ),
                "requires_approval": False,
            },
            {
                "order": 4,
                "title": "Notifier l'équipe SOC",
                "action_type": "send_notification",
                "description": "Alerter le SOC avec le détail de l'attaque, les IPs sources et le rate-limit appliqué.",
                "requires_approval": False,
            },
        ],
    },

    # ══════════════════════════════════════════════════════════════
    # 6. Ransomware — isolation MANUELLE (impact business fort)
    # Déclenché par catégorie ransomware (FIM Wazuh syscheck — extension future)
    # ══════════════════════════════════════════════════════════════
    {
        "name": "Réponse Ransomware",
        "description": (
            "Réponse à un comportement ransomware détecté (chiffrement/renommage massif via FIM Wazuh). "
            "L'isolation de l'hôte est une étape MANUELLE : un faux positif (ex : sauvegarde légitime) "
            "causerait une interruption de service non justifiée."
        ),
        "trigger_category": "ransomware",
        "trigger_severity_min": "critical",
        "mitre_techniques": ["T1486", "T1490", "T1083"],
        "steps": [
            {
                "order": 1,
                "title": "Enregistrer l'hôte et les IOCs fichiers",
                "action_type": "log_ioc",
                "description": "Logger l'IP de l'hôte compromis et les IOCs fichiers (extensions chiffrées, note de rançon détectée).",
                "requires_approval": False,
            },
            {
                "order": 2,
                "title": "Scanner les vulnérabilités de l'hôte",
                "action_type": "trigger_scan",
                "description": "Identifier le vecteur d'entrée initial (CVE exploitée, service vulnérable) sur l'hôte affecté.",
                "requires_approval": False,
            },
            {
                "order": 3,
                "title": "Isoler l'hôte du réseau",
                "action_type": "isolate_host",
                "description": (
                    "Débrancher/isoler l'hôte via iptables ou port switch. "
                    "ATTENTION : décision à fort impact — valider que ce n'est pas une sauvegarde légitime avant d'exécuter. "
                    "Nécessite approbation analyste."
                ),
                "requires_approval": True,
            },
            {
                "order": 4,
                "title": "Vérifier les sauvegardes récentes",
                "action_type": "manual_task",
                "description": (
                    "Vérifier l'existence et l'intégrité des sauvegardes (backup) avant toute restauration. "
                    "Identifier la dernière sauvegarde saine. Documenter dans l'incident."
                ),
                "requires_approval": True,
            },
        ],
    },

    # ══════════════════════════════════════════════════════════════
    # 7. Exfiltration — blocage flux sortant MANUEL (contexte métier requis)
    # Déclenché par catégorie exfiltration (AlertCategory.EXFILTRATION)
    # ══════════════════════════════════════════════════════════════
    {
        "name": "Réponse Exfiltration",
        "description": (
            "Réponse à une suspicion de vol de données : volume sortant anormal vers une IP externe "
            "à un horaire suspect (détectable via Isolation Forest + règle de corrélation volume). "
            "Le blocage du flux reste MANUEL : seul un humain peut qualifier si l'export est légitime."
        ),
        "trigger_category": "exfiltration",
        "trigger_severity_min": "high",
        "mitre_techniques": ["T1048", "T1041", "T1567"],
        "steps": [
            {
                "order": 1,
                "title": "Enregistrer la destination externe suspecte",
                "action_type": "log_ioc",
                "description": "Logger l'IP/domaine de destination externe et l'asset source comme IOCs dans l'incident.",
                "requires_approval": False,
            },
            {
                "order": 2,
                "title": "Réévaluer la conformité de l'asset source",
                "action_type": "run_compliance",
                "description": "Vérifier si l'asset source respecte les politiques DLP/exfiltration (ports de sortie autorisés, etc.).",
                "requires_approval": False,
            },
            {
                "order": 3,
                "title": "Identifier la nature de la donnée concernée",
                "action_type": "manual_task",
                "description": (
                    "Analyser les logs pour qualifier les données exportées : fichiers, base de données, credentials. "
                    "Vérifier s'il s'agit d'un transfert métier autorisé (export partenaire, backup cloud). "
                    "Contexte métier requis — ne peut pas être automatisé."
                ),
                "requires_approval": True,
            },
            {
                "order": 4,
                "title": "Bloquer la destination externe",
                "action_type": "block_ip",
                "description": (
                    "Bloquer l'IP de destination via iptables OUTPUT. "
                    "Fort impact : peut couper une intégration métier légitime. "
                    "Validation analyste obligatoire après qualification de l'étape 3."
                ),
                "requires_approval": True,
            },
        ],
    },
]


async def seed():
    from app.db.session import AsyncSessionLocal
    from app.models.incident import Playbook
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        for pb_data in PLAYBOOKS:
            existing = await db.execute(
                select(Playbook).where(Playbook.name == pb_data["name"])
            )
            if existing.scalar_one_or_none():
                print(f"  deja existant : {pb_data['name']}")
                continue

            pb = Playbook(
                name=pb_data["name"],
                description=pb_data["description"],
                trigger_category=pb_data["trigger_category"],
                trigger_severity_min=pb_data["trigger_severity_min"],
                mitre_techniques=pb_data["mitre_techniques"],
                steps=pb_data["steps"],
                is_active=True,
            )
            db.add(pb)
            print(f"  cree : {pb_data['name']} ({len(pb_data['steps'])} etapes)")

        await db.commit()
        print(f"\n{len(PLAYBOOKS)} playbooks traites.")


if __name__ == "__main__":
    asyncio.run(seed())
