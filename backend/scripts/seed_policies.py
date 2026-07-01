"""
Script de seed — Politiques de durcissement par défaut.

Injecte un jeu de policies prêtes à l'emploi pour :
  - ISO 27001 (contrôles techniques A.12, A.13, A.14)
  - DORA (Articles 5, 9, 10 — gestion des risques ICT)
  - CIS Controls v8 (contrôles 4, 13, 18)

Usage :
    docker compose exec backend python scripts/seed_policies.py
    # ou en local :
    cd backend && python scripts/seed_policies.py
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

POLICIES = [

    # ══════════════════════════════════════════════════════════════
    # ISO 27001 — Contrôles de sécurité réseau
    # ══════════════════════════════════════════════════════════════

    {
        "name":        "RDP non exposé",
        "description": "Le bureau à distance Windows (RDP/3389) ne doit pas être accessible depuis le réseau.",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.13.1.1",
        "severity":    "critical",
        "rule_type":   "port_closed",
        "rule_config": {"port": 3389, "protocol": "tcp"},
    },
    {
        "name":        "Telnet désactivé",
        "description": "Telnet transmet les credentials en clair — interdit sur tous les équipements.",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.13.1.1",
        "severity":    "critical",
        "rule_type":   "port_closed",
        "rule_config": {"port": 23, "protocol": "tcp"},
    },
    {
        "name":        "FTP désactivé",
        "description": "FTP transmet les données en clair — remplacer par SFTP/FTPS.",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.13.1.1",
        "severity":    "high",
        "rule_type":   "port_closed",
        "rule_config": {"port": 21, "protocol": "tcp"},
    },
    {
        "name":        "SMBv1 désactivé",
        "description": "SMB port 445 exposé — vecteur d'attaque WannaCry/NotPetya.",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.12.6.1",
        "severity":    "critical",
        "rule_type":   "port_closed",
        "rule_config": {"port": 445, "protocol": "tcp"},
        "applies_to_asset_types": ["server", "workstation"],
    },
    {
        "name":        "SSH activé sur les serveurs",
        "description": "Accès administratif sécurisé via SSH requis sur tous les serveurs.",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.9.4.2",
        "severity":    "medium",
        "rule_type":   "port_open",
        "rule_config": {"port": 22, "protocol": "tcp", "service": "ssh"},
        "applies_to_asset_types": ["server"],
    },
    {
        "name":        "OS non en fin de support",
        "description": "Les OS Windows Server 2008/2012 et RHEL 6 ne reçoivent plus de patches.",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.12.6.1",
        "severity":    "high",
        "rule_type":   "os_version",
        "rule_config": {
            "forbidden_patterns": [
                "Windows Server 2008", "Windows Server 2012",
                "Windows 7", "RHEL 6", "CentOS 6",
                "Ubuntu 16.04", "Ubuntu 18.04",
            ]
        },
    },
    {
        "name":        "Classification des assets obligatoire",
        "description": "Chaque asset doit avoir un département renseigné (ISO 27001 A.8.1).",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.8.1",
        "severity":    "medium",
        "rule_type":   "field_value",
        "rule_config": {"field": "department", "operator": "not_null"},
    },
    {
        "name":        "Risque résiduel acceptable",
        "description": "Le risk_score d'un asset ne doit pas dépasser 7.0 (ISO 27001 A.12.6).",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.12.6.1",
        "severity":    "high",
        "rule_type":   "vuln_score_max",
        "rule_config": {"max_score": 7.0},
        "applies_to_asset_types": ["server", "firewall"],
    },

    # ══════════════════════════════════════════════════════════════
    # DORA — Digital Operational Resilience Act
    # ══════════════════════════════════════════════════════════════

    {
        "name":        "BlueKeep patché (CVE-2019-0708)",
        "description": "DORA Art.9 : la vulnérabilité BlueKeep doit être corrigée sous 30 jours.",
        "framework":   "dora",
        "control_id":  "DORA-Art.9.2",
        "severity":    "critical",
        "rule_type":   "patch_applied",
        "rule_config": {"cve_id": "CVE-2019-0708", "description": "BlueKeep RDP RCE"},
    },
    {
        "name":        "EternalBlue patché (CVE-2017-0144)",
        "description": "DORA Art.9 : MS17-010 (WannaCry) doit être correctement patchée.",
        "framework":   "dora",
        "control_id":  "DORA-Art.9.2",
        "severity":    "critical",
        "rule_type":   "patch_applied",
        "rule_config": {"cve_id": "CVE-2017-0144", "description": "EternalBlue SMB"},
    },
    {
        "name":        "Score de risque DORA faible",
        "description": "DORA Art.5 : les systèmes critiques doivent maintenir un risque résiduel minimal.",
        "framework":   "dora",
        "control_id":  "DORA-Art.5.4",
        "severity":    "critical",
        "rule_type":   "vuln_score_max",
        "rule_config": {"max_score": 5.0},
        "applies_to_tags": ["critical", "production"],
    },
    {
        "name":        "Port 8080 non exposé",
        "description": "DORA Art.9 : les ports d'administration non sécurisés doivent être fermés.",
        "framework":   "dora",
        "control_id":  "DORA-Art.9.1",
        "severity":    "medium",
        "rule_type":   "port_closed",
        "rule_config": {"port": 8080, "protocol": "tcp"},
        "applies_to_tags": ["production"],
    },

    # ══════════════════════════════════════════════════════════════
    # CIS Controls v8
    # ══════════════════════════════════════════════════════════════

    {
        "name":        "SNMP v1/v2 désactivé",
        "description": "CIS Control 4.8 : SNMP v1/v2 communique en clair et doit être désactivé.",
        "framework":   "cis",
        "control_id":  "CIS-4.8",
        "severity":    "medium",
        "rule_type":   "service_disabled",
        "rule_config": {"service_name": "snmp", "ports": [161, 162]},
        "applies_to_asset_types": ["switch", "router", "firewall"],
    },
    {
        "name":        "VNC désactivé",
        "description": "CIS Control 4.8 : VNC non sécurisé doit être désactivé.",
        "framework":   "cis",
        "control_id":  "CIS-4.8",
        "severity":    "high",
        "rule_type":   "service_disabled",
        "rule_config": {"service_name": "vnc", "ports": [5900, 5901, 5902]},
    },
    {
        "name":        "Accès base de données non exposé",
        "description": "CIS Control 13.3 : les ports DB ne doivent pas être exposés en dehors du réseau applicatif.",
        "framework":   "cis",
        "control_id":  "CIS-13.3",
        "severity":    "high",
        "rule_type":   "port_closed",
        "rule_config": {"port": 5432, "protocol": "tcp"},
        "applies_to_tags": ["production"],
        "applies_to_asset_types": ["server"],
    },

    # ══════════════════════════════════════════════════════════════
    # Règles basées sur les alertes SIEM (cross-correlation)
    # Ces règles lisent directement les alertes ouvertes dans le SIEM
    # ══════════════════════════════════════════════════════════════

    {
        "name":        "Aucune tentative de brute force active",
        "description": "DORA Art.9 / CIS 4.1 : aucune alerte brute force ouverte ne doit viser cet asset.",
        "framework":   "dora",
        "control_id":  "DORA-Art.9.3",
        "severity":    "high",
        "rule_type":   "no_brute_force",
        "rule_config": {"max_attempts": 0},
    },
    {
        "name":        "Aucune navigation phishing détectée",
        "description": "ISO 27001 A.7.2.2 : aucun utilisateur de cet asset ne doit avoir navigué vers un site phishing.",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.7.2.2",
        "severity":    "high",
        "rule_type":   "no_phishing_detection",
        "rule_config": {"max_detections": 0},
    },
    {
        "name":        "Incidents de sécurité traités",
        "description": "ISO 27001 A.16.1.4 : aucune alerte SIEM ouverte ne doit rester sans traitement.",
        "framework":   "iso_27001",
        "control_id":  "ISO-27001-A.16.1.4",
        "severity":    "medium",
        "rule_type":   "no_active_alerts",
        "rule_config": {"max_alerts": 0},
    },
]


async def seed_policies():
    from app.db.session import AsyncSessionLocal
    from app.models.compliance import HardeningPolicy, PolicyFramework, PolicySeverity
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        for p in POLICIES:
            # Éviter les doublons
            existing = await db.execute(
                select(HardeningPolicy).where(HardeningPolicy.name == p["name"])
            )
            if existing.scalar_one_or_none():
                print(f"  ↷ Déjà existante : {p['name']}")
                continue

            policy = HardeningPolicy(
                name=p["name"],
                description=p.get("description"),
                framework=PolicyFramework(p["framework"]),
                control_id=p.get("control_id"),
                severity=PolicySeverity(p.get("severity", "medium")),
                rule_type=p["rule_type"],
                rule_config=p["rule_config"],
                applies_to_tags=p.get("applies_to_tags", []),
                applies_to_asset_types=p.get("applies_to_asset_types", []),
                applies_to_departments=p.get("applies_to_departments", []),
                is_active=True,
            )
            db.add(policy)
            print(f"   Créée : [{p['framework'].upper()}] {p['name']}")

        await db.commit()
        print(f"\n {len(POLICIES)} politiques chargées.")


if __name__ == "__main__":
    asyncio.run(seed_policies())
