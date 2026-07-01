#!/usr/bin/env python3
"""
Hook Squid → SecureZone Phishing Module.

Place ce script sur Ubuntu (où tourne Squid).
Lit les access logs Squid en temps réel et envoie les URLs au SIEM.

Installation :
    # Sur Ubuntu
    sudo pip3 install requests
    sudo python3 squid_phishing_hook.py --backend http://192.168.8.X:8000

    # Ou en service systemd (voir EOF)
"""

import sys
import time
import re
import requests
import argparse
from datetime import datetime, timezone

SECUREZONE_URL = "http://localhost:8000"
API_KEY = "securezone-ingest-2024"
SQUID_LOG = "/var/log/squid/access.log"

# Regex pour parser les logs Squid
SQUID_RE = re.compile(
    r'(\d+\.\d+)\s+\d+\s+(\S+)\s+\S+/\d+\s+\d+\s+\S+\s+(\S+)\s+\S+\s+\S+/(\S+)'
)


def parse_squid_line(line: str):
    """Extrait (timestamp, client_ip, url, server_ip) d'une ligne Squid."""
    m = SQUID_RE.match(line.strip())
    if not m:
        return None
    return {
        "timestamp": m.group(1),
        "client_ip": m.group(2),
        "url": m.group(3),
        "server": m.group(4),
    }


def send_url_event(backend: str, url: str, client_ip: str):
    try:
        resp = requests.post(
            f"{backend}/api/v1/phishing/ingest",
            headers={"X-Api-Key": API_KEY, "Content-Type": "application/json"},
            json={"events": [{
                "type": "url",
                "source_ip": client_ip,
                "url": url,
                "log_source": "squid",
                "raw_log": {"proxy": "squid", "time": datetime.now(timezone.utc).isoformat()},
            }]},
            timeout=3,
        )
        if resp.status_code == 200:
            data = resp.json()
            for r in data.get("results", []):
                if r.get("alert_created"):
                    print(f"[ALERTE] {url[:60]} | score={r['score']:.0f} | ID=#{r['alert_id']}")
    except requests.exceptions.ConnectionError:
        pass  # Backend inaccessible — on continue


def tail_log(log_path: str, backend: str):
    print(f"[Squid Hook] Surveillance de {log_path} → {backend}")
    with open(log_path, "r") as f:
        f.seek(0, 2)  # aller à la fin du fichier
        while True:
            line = f.readline()
            if line:
                parsed = parse_squid_line(line)
                if parsed and parsed["url"].startswith("http"):
                    send_url_event(backend, parsed["url"], parsed["client_ip"])
            else:
                time.sleep(0.1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", default=SECUREZONE_URL)
    parser.add_argument("--log", default=SQUID_LOG)
    args = parser.parse_args()
    tail_log(args.log, args.backend)

# ── Systemd service (sudo nano /etc/systemd/system/sz-phishing.service) ──
# [Unit]
# Description=SecureZone Phishing Hook
# After=squid.service
#
# [Service]
# ExecStart=/usr/bin/python3 /opt/securezone/squid_phishing_hook.py --backend http://BACKEND_IP:8000
# Restart=always
#
# [Install]
# WantedBy=multi-user.target
