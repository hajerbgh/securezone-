#!/usr/bin/env python3
"""
SecureZone — Script de test SIEM + Phishing avec VMs réelles.

Usage (depuis Kali ou Windows) :
    python test_siem_scenarios.py --backend http://192.168.8.X:8000 --scenario all

Scénarios disponibles :
    1  Port scan detection
    2  Brute force SSH/FTP
    3  Phishing URL (proxy web)
    4  Phishing email (gateway)
    5  Lateral movement
    all  Tous les scénarios en séquence
"""

import argparse
import json
import time
import sys
import requests
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────
DEFAULT_BACKEND = "http://localhost:8000"
API_KEY = "securezone-ingest-2024"
LOGIN_USER = "admin"
LOGIN_PASS = "admin"

# IPs des VMs (adapte selon ton réseau)
KALI_IP         = "192.168.8.129"
METASPLOIT_IP   = "192.168.8.128"
UBUNTU_IP       = "192.168.8.130"  # modifie si différent

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def banner(text):
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}")


def ok(msg):
    print(f"  {GREEN}✓{RESET} {msg}")


def warn(msg):
    print(f"  {YELLOW}⚠{RESET} {msg}")


def err(msg):
    print(f"  {RED}✗{RESET} {msg}")


def info(msg):
    print(f"  {CYAN}→{RESET} {msg}")


# ── Auth ──────────────────────────────────────────────────────────

def get_token(base_url: str) -> str:
    resp = requests.post(f"{base_url}/api/v1/auth/login",
                         data={"username": LOGIN_USER, "password": LOGIN_PASS},
                         timeout=5)
    resp.raise_for_status()
    token = resp.json()["access_token"]
    ok(f"Authentifié comme {LOGIN_USER}")
    return token


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def ingest_headers() -> dict:
    return {"X-Api-Key": API_KEY, "Content-Type": "application/json"}


# ── Scénario 1 : Scan de ports ────────────────────────────────────

def scenario_port_scan(base_url: str, token: str):
    banner("SCÉNARIO 1 — Détection de scan de ports (Kali → Metasploitable2)")
    info(f"Simulé comme si Kali ({KALI_IP}) scannait Metasploitable2 ({METASPLOIT_IP})")
    info("Dans un vrai setup : nmap -sV -T4 192.168.8.128 est détecté par Wazuh/Snort")
    print()

    # Via l'ingestion automatique (ce que Wazuh enverrait)
    events = [
        {
            "type": "url",  # proxy log de la machine attaquante
            "source_ip": KALI_IP,
            "user": "attacker",
            "url": "http://192.168.8.128/",  # connexion directe par IP
            "log_source": "squid",
            "raw_log": {
                "event": "port_scan_detected",
                "scanner_ip": KALI_IP,
                "target_ip": METASPLOIT_IP,
                "ports_scanned": [21, 22, 23, 25, 80, 139, 445, 3306],
                "scan_type": "SYN",
                "tool_fingerprint": "Nmap",
            }
        }
    ]

    resp = requests.post(
        f"{base_url}/api/v1/phishing/ingest",
        headers=ingest_headers(),
        json={"events": events},
        timeout=10,
    )

    if resp.status_code == 200:
        data = resp.json()
        ok(f"Ingestion : {data['processed']} événement(s) traité(s)")
        for r in data["results"]:
            if r["alert_created"]:
                ok(f"Alerte créée — score={r['score']:.0f}, sévérité={r['severity']}, ID=#{r['alert_id']}")
            else:
                warn(f"Score={r['score']:.0f} — seuil non atteint (< 31)")
    else:
        err(f"Erreur {resp.status_code}: {resp.text[:200]}")

    # Déclencher un vrai scan Nmap via l'API
    print()
    info("Déclenchement d'un vrai scan Nmap via l'API...")
    scan_resp = requests.post(
        f"{base_url}/api/v1/scans/",
        headers=auth_headers(token),
        json={
            "scanner_type": "nmap",
            "ip_ranges": [METASPLOIT_IP],
            "description": "Test scénario 1 — scan de ports",
        },
        timeout=10,
    )
    if scan_resp.status_code == 200:
        scan_id = scan_resp.json()["id"]
        ok(f"Scan Nmap lancé → ScanJob #{scan_id}")
        info(f"Surveille sur http://localhost:3000 → Vulnérabilités")
        return scan_id
    else:
        err(f"Scan échoué : {scan_resp.text[:200]}")
        return None


# ── Scénario 2 : Brute Force SSH/FTP ─────────────────────────────

def scenario_brute_force(base_url: str, token: str):
    banner("SCÉNARIO 2 — Brute Force SSH/FTP (Kali → Metasploitable2)")
    info(f"Simulé : Hydra ou Medusa depuis Kali ({KALI_IP}) → SSH port 22 ({METASPLOIT_IP})")
    info("Commande réelle à exécuter sur Kali (dans un autre terminal) :")
    print(f"\n  {YELLOW}hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt {METASPLOIT_IP} ssh{RESET}")
    print(f"  {YELLOW}hydra -l admin -P /usr/share/wordlists/rockyou.txt {METASPLOIT_IP} ftp{RESET}\n")

    # Simulation de 15 tentatives de brute force (ce que Wazuh détecterait)
    events = []
    passwords_tried = ["admin", "root", "password", "123456", "msfadmin", "test"]
    for i, pwd in enumerate(passwords_tried):
        events.append({
            "type": "email",  # email alert du système auth
            "source_ip": KALI_IP,
            "sender": f"auth-alert@{METASPLOIT_IP}",
            "subject": f"ALERTE : Tentative connexion SSH #{i+1} échouée — user=root pwd={pwd}",
            "spf_result": "fail",  # alert automatique sans SPF
            "log_source": "wazuh",
            "raw_log": {
                "event": "authentication_failure",
                "service": "sshd",
                "user": "root",
                "password_attempt": pwd,
                "src_ip": KALI_IP,
                "dst_ip": METASPLOIT_IP,
                "dst_port": 22,
                "attempt_number": i + 1,
                "rule_id": "5710",  # Wazuh rule: SSH brute force
            }
        })

    resp = requests.post(
        f"{base_url}/api/v1/phishing/ingest",
        headers=ingest_headers(),
        json={"events": events},
        timeout=15,
    )

    if resp.status_code == 200:
        data = resp.json()
        ok(f"{data['processed']} événements traités — {data['alerts_created']} alerte(s) créée(s)")
        for r in data["results"]:
            if r["alert_created"]:
                ok(f"Alerte brute-force : score={r['score']:.0f}, sévérité={r['severity']}")
    else:
        err(f"Erreur {resp.status_code}: {resp.text[:200]}")


# ── Scénario 3 : URLs phishing (proxy Squid) ──────────────────────

def scenario_phishing_urls(base_url: str, token: str):
    banner("SCÉNARIO 3 — URLs phishing détectées dans proxy web (Ubuntu → Internet)")
    info("Simule ce qu'un proxy Squid enverrait automatiquement au SIEM")
    info("Un utilisateur sur Ubuntu a cliqué sur des liens suspects")
    print()

    phishing_urls = [
        ("http://paypa1.com/account/verify?token=abc123xyz", UBUNTU_IP, "alice"),
        ("http://bit.ly/3xK9fake",                          UBUNTU_IP, "alice"),
        ("https://192.168.1.100/banking/login",             UBUNTU_IP, "bob"),
        ("http://microsoft-security-alert.tk/update",       UBUNTU_IP, "carol"),
        ("https://accounts.google.com.phishing-site.ml/",  UBUNTU_IP, "dave"),
        ("https://www.netflix.com/login",                   UBUNTU_IP, "alice"),  # légitime
        ("https://github.com",                              UBUNTU_IP, "bob"),    # légitime
    ]

    events = []
    for url, ip, user in phishing_urls:
        events.append({
            "type": "url",
            "source_ip": ip,
            "user": user,
            "url": url,
            "log_source": "squid",
            "raw_log": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "proxy": "squid3",
                "action": "TCP_MISS/200",
                "bytes": 4096,
            }
        })

    resp = requests.post(
        f"{base_url}/api/v1/phishing/ingest",
        headers=ingest_headers(),
        json={"events": events},
        timeout=15,
    )

    if resp.status_code == 200:
        data = resp.json()
        print(f"\n  {'URL':<55} {'Score':>5}  {'Sévérité':<10} {'Alerte'}")
        print(f"  {'-'*55} {'-----':>5}  {'-'*10} {'------'}")
        for i, r in enumerate(data["results"]):
            url_short = phishing_urls[i][0][:52] + "..." if len(phishing_urls[i][0]) > 55 else phishing_urls[i][0]
            alerte = f"{GREEN}✓ #{r['alert_id']}{RESET}" if r["alert_created"] else f"{YELLOW}—{RESET}"
            sev_color = RED if r["severity"] in ("critical", "high") else YELLOW if r["severity"] == "medium" else GREEN
            print(f"  {url_short:<55} {r['score']:>5.0f}  {sev_color}{r['severity']:<10}{RESET} {alerte}")
        ok(f"\n{data['alerts_created']}/{data['processed']} URL(s) ont généré une alerte SIEM")
    else:
        err(f"Erreur {resp.status_code}: {resp.text[:200]}")


# ── Scénario 4 : Phishing email (Email Gateway) ───────────────────

def scenario_phishing_email(base_url: str, token: str):
    banner("SCÉNARIO 4 — Emails phishing détectés par l'email gateway")
    info("Simule ce que Postfix/Exchange enverrait au SIEM après analyse des headers")
    print()

    phishing_emails = [
        {
            "sender": "security@paypa1.com",
            "recipient": "alice@company.local",
            "subject": "Urgent : Votre compte PayPal a été suspendu",
            "spf_result": "fail",
            "dmarc_result": "fail",
            "reply_to": "collect@gmail-phish.tk",
            "body_urls": ["http://paypa1.com/unlock", "http://bit.ly/3fake"],
            "source_ip": "185.220.101.45",  # IP externe suspecte
        },
        {
            "sender": "no-reply@microsoft-security.ml",
            "recipient": "bob@company.local",
            "subject": "Action requise : Activez votre compte Microsoft",
            "spf_result": "softfail",
            "dmarc_result": "fail",
            "body_urls": ["http://login-microsoft.tk/verify"],
            "source_ip": "45.33.32.156",
        },
        {
            "sender": "newsletter@linkedin.com",  # légitime
            "recipient": "carol@company.local",
            "subject": "Découvrez les nouvelles offres d'emploi",
            "spf_result": "pass",
            "dmarc_result": "pass",
            "source_ip": "108.174.10.10",
        },
        {
            "sender": "daf@company-partner.com",
            "recipient": "directeur@company.local",
            "subject": "Virement urgent — Ordre confidentiel",
            "spf_result": "none",
            "dmarc_result": "none",
            "reply_to": "daf@company-partner-secure.ga",
            "source_ip": "91.108.56.200",
        },
    ]

    events = [
        {
            "type": "email",
            "source_ip": e["source_ip"],
            "sender": e["sender"],
            "subject": e["subject"],
            "spf_result": e["spf_result"],
            "dmarc_result": e["dmarc_result"],
            "body_urls": e.get("body_urls", []),
            "reply_to": e.get("reply_to"),
            "recipient": e.get("recipient"),
            "log_source": "postfix",
            "raw_log": {"smtp_src": e["source_ip"]},
        }
        for e in phishing_emails
    ]

    resp = requests.post(
        f"{base_url}/api/v1/phishing/ingest",
        headers=ingest_headers(),
        json={"events": events},
        timeout=15,
    )

    if resp.status_code == 200:
        data = resp.json()
        print(f"\n  {'Expéditeur':<40} {'Sujet':<35} {'Score':>5}  {'Alerte'}")
        print(f"  {'-'*40} {'-'*35} {'-----':>5}  {'------'}")
        for i, r in enumerate(data["results"]):
            e = phishing_emails[i]
            sender_s = e["sender"][:38] + ".." if len(e["sender"]) > 40 else e["sender"]
            subj_s   = e["subject"][:33] + ".." if len(e["subject"]) > 35 else e["subject"]
            alerte   = f"{GREEN}✓ #{r['alert_id']}{RESET}" if r["alert_created"] else f"{YELLOW}— (score trop bas){RESET}"
            print(f"  {sender_s:<40} {subj_s:<35} {r['score']:>5.0f}  {alerte}")
        ok(f"\n{data['alerts_created']}/{data['processed']} email(s) ont généré une alerte SIEM")
    else:
        err(f"Erreur {resp.status_code}: {resp.text[:200]}")


# ── Scénario 5 : Mouvement latéral ───────────────────────────────

def scenario_lateral_movement(base_url: str, token: str):
    banner("SCÉNARIO 5 — Détection mouvement latéral (Metasploitable → Ubuntu)")
    info(f"Simule : après compromission de Metasploitable2, l'attaquant pivote vers Ubuntu")
    info("Ce qu'un Wazuh/HIDS verrait sur Ubuntu en temps réel :")
    print()
    info("Commandes réelles à exécuter DEPUIS Metasploitable2 compromis :")
    print(f"\n  {YELLOW}# Sur Metasploitable2 (après exploit vsftpd backdoor via Metasploit){RESET}")
    print(f"  {YELLOW}use exploit/unix/ftp/vsftpd_234_backdoor{RESET}")
    print(f"  {YELLOW}set RHOSTS {METASPLOIT_IP}{RESET}")
    print(f"  {YELLOW}exploit{RESET}")
    print(f"  {YELLOW}# shell → scanner le réseau interne{RESET}")
    print(f"  {YELLOW}ifconfig ; arp -a ; nmap -sn 192.168.8.0/24{RESET}\n")

    # Simulation de l'événement envoyé par Wazuh sur Ubuntu
    events = [
        {
            "type": "url",
            "source_ip": METASPLOIT_IP,  # Metasploitable2 compromis accède à Ubuntu
            "user": "root",
            "url": f"http://{UBUNTU_IP}/admin",
            "log_source": "wazuh",
            "raw_log": {
                "event": "lateral_movement",
                "src_host": "metasploitable2",
                "src_ip": METASPLOIT_IP,
                "dst_ip": UBUNTU_IP,
                "technique": "T1021",  # Remote Services
                "wazuh_rule": "40101",
                "description": "Connexion SSH depuis hôte compromis",
            }
        }
    ]

    resp = requests.post(
        f"{base_url}/api/v1/phishing/ingest",
        headers=ingest_headers(),
        json={"events": events},
        timeout=10,
    )

    if resp.status_code == 200:
        data = resp.json()
        ok(f"Événement mouvement latéral traité")
        for r in data["results"]:
            if r["alert_created"]:
                ok(f"Alerte créée — score={r['score']:.0f}, sévérité={r['severity']}, ID=#{r['alert_id']}")
    else:
        err(f"Erreur: {resp.text[:200]}")

    # Déclencher un scan OpenVAS complet pour trouver les CVEs
    print()
    info("Déclenchement scan OpenVAS full sur les deux cibles...")
    scan_resp = requests.post(
        f"{base_url}/api/v1/scans/",
        headers=auth_headers(token),
        json={
            "scanner_type": "full",
            "ip_ranges": [METASPLOIT_IP],
            "description": "Scan post-incident — mouvement latéral détecté",
        },
        timeout=10,
    )
    if scan_resp.status_code == 200:
        ok(f"Scan full lancé → ScanJob #{scan_resp.json()['id']}")


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SecureZone SIEM test scenarios")
    parser.add_argument("--backend", default=DEFAULT_BACKEND, help="Backend URL")
    parser.add_argument("--scenario", default="all",
                        choices=["1", "2", "3", "4", "5", "all"],
                        help="Scénario à exécuter")
    parser.add_argument("--kali-ip", default=KALI_IP)
    parser.add_argument("--metasploit-ip", default=METASPLOIT_IP)
    parser.add_argument("--ubuntu-ip", default=UBUNTU_IP)
    args = parser.parse_args()

    global KALI_IP, METASPLOIT_IP, UBUNTU_IP
    KALI_IP = args.kali_ip
    METASPLOIT_IP = args.metasploit_ip
    UBUNTU_IP = args.ubuntu_ip

    banner(f"SecureZone — Test SIEM + Phishing | Backend: {args.backend}")
    print(f"  VMs : Kali={KALI_IP} | Metasploitable2={METASPLOIT_IP} | Ubuntu={UBUNTU_IP}")

    # Auth
    try:
        token = get_token(args.backend)
    except Exception as e:
        err(f"Connexion impossible : {e}")
        sys.exit(1)

    scenarios = {
        "1": scenario_port_scan,
        "2": scenario_brute_force,
        "3": scenario_phishing_urls,
        "4": scenario_phishing_email,
        "5": scenario_lateral_movement,
    }

    to_run = list(scenarios.keys()) if args.scenario == "all" else [args.scenario]

    for s in to_run:
        try:
            scenarios[s](args.backend, token)
        except KeyboardInterrupt:
            warn("Interrompu")
            break
        except Exception as e:
            err(f"Scénario {s} échoué : {e}")
        if args.scenario == "all" and s != to_run[-1]:
            time.sleep(2)

    banner("Résultats — Ouvre le dashboard pour voir les alertes")
    print(f"  {GREEN}→ http://localhost:3000/alerts{RESET}    (toutes les alertes)")
    print(f"  {GREEN}→ http://localhost:3000/phishing{RESET}  (alertes phishing)")
    print(f"  {GREEN}→ http://localhost:3000/{RESET}           (tableau de bord)")
    print()


if __name__ == "__main__":
    main()
