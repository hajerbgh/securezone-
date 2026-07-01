"""
Script de seed — Playbooks de réponse aux incidents.

4 playbooks concrets pour le lab SecureZone :
  1. Brute Force       — log IOC → scan VM → [MANUAL] bloquer IP iptables
  2. Phishing          — log IOC → scan poste → [MANUAL] blacklist Squid → notifier
  3. Port Scan         — log IOC → évaluation conformité → [MANUAL] investiguer
  4. Generic High      — scan VM → [MANUAL] analyser → [MANUAL] containment

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
