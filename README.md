# SecureZone — Unified Security Platform

A full-stack Security Operations Center (SOC) platform built for hands-on cybersecurity labs and learning environments. SecureZone integrates SIEM, Vulnerability Management, Compliance, Incident Response, and Phishing Detection into a single cohesive dashboard — inspired by real enterprise tools like Splunk Enterprise Security and Microsoft Sentinel.

> **Purpose:** Academic/lab environment demonstrating SOC workflows end-to-end, from raw log ingestion to automated incident response and compliance reporting.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Lab Network Topology](#lab-network-topology)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Seed Scripts](#seed-scripts)
- [API Reference](#api-reference)
- [Module Deep-Dives](#module-deep-dives)
  - [SIEM Engine](#siem-engine)
  - [Vulnerability Management](#vulnerability-management)
  - [Compliance Engine](#compliance-engine)
  - [Incident Response & SOAR](#incident-response--soar)
  - [Phishing Detection](#phishing-detection)
  - [PDF Reports](#pdf-reports)
  - [AI Chatbot (SecureBot)](#ai-chatbot-securebot)
- [Playbooks Reference](#playbooks-reference)
- [Compliance Policies Reference](#compliance-policies-reference)

---

## Features

| Module | Capability |
|---|---|
| **SIEM** | Alert ingestion, ML anomaly detection (Isolation Forest), rule-based correlation, event normalization |
| **Vulnerability Management** | Nmap + OpenVAS/GVM scans, CVE tracking, risk scoring, scheduled scans via APScheduler |
| **Compliance** | ISO 27001, DORA, CIS Controls v8 evaluation engine — 18 policies, SIEM-correlated rules |
| **Incident Response** | Automatic incident creation from critical alerts, 4 playbooks, SOAR action execution |
| **Phishing Detection** | Real-time URL scoring via Squid proxy hook, typosquatting, homoglyph, entropy analysis |
| **Reports** | Professional PDF generation (Executive, Technical, Compliance) via ReportLab |
| **AI Chatbot** | Groq-powered SecureBot with live SIEM context injection (RAG-like) |
| **API** | RESTful FastAPI backend, JWT authentication, OpenAPI docs at `/docs` |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SECUREZONE PLATFORM                          │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    React Frontend (Vite)                     │   │
│  │  Dashboard · Alerts · Vulns · Compliance · Incidents ·      │   │
│  │  Phishing · ChatBot                                          │   │
│  └─────────────────────────┬────────────────────────────────────┘   │
│                            │  REST API / JWT                        │
│  ┌─────────────────────────▼────────────────────────────────────┐   │
│  │                  FastAPI Backend (async)                      │   │
│  │                                                              │   │
│  │  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────┐  │   │
│  │  │   SIEM   │ │    VM    │ │Compliance │ │     IR /     │  │   │
│  │  │  Engine  │ │  Engine  │ │  Engine   │ │    SOAR      │  │   │
│  │  │          │ │          │ │           │ │              │  │   │
│  │  │Normalize │ │  Nmap    │ │ 18 Rules  │ │ 4 Playbooks  │  │   │
│  │  │Correlate │ │ OpenVAS  │ │ISO/DORA/  │ │ Auto-trigger │  │   │
│  │  │ML Score  │ │Scheduler │ │   CIS     │ │ SOAR Actions │  │   │
│  │  └────┬─────┘ └────┬─────┘ └─────┬─────┘ └──────┬───────┘  │   │
│  │       │            │             │               │           │   │
│  │  ┌────▼────────────▼─────────────▼───────────────▼───────┐  │   │
│  │  │              PostgreSQL Database                       │  │   │
│  │  │  alerts · assets · vulnerabilities · incidents ·      │  │   │
│  │  │  compliance_checks · playbooks · phishing_events      │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  External Integrations:                                             │
│  ┌──────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │
│  │  Squid Proxy Hook │  │  Nmap / OpenVAS   │  │   Groq API      │  │
│  │  (Phishing URL    │  │  (Vuln Scanning)  │  │  (AI Chatbot)   │  │
│  │   real-time feed) │  │                   │  │  llama-3.1-8b   │  │
│  └──────────────────┘  └───────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow — Alert Lifecycle

```
Raw Log / Event
      │
      ▼
Normalizer         → Standardizes source format into SIEMEvent
      │
      ▼
Anomaly Detector   → Isolation Forest ML model, flags statistical outliers
      │
      ▼
Correlator         → Groups related events (same IP, time window, MITRE technique)
      │
      ▼
Alert (DB)         → Persisted with severity, category, source/dest IPs, risk score
      │
      ├─── CRITICAL or HIGH ?
      │           │
      │           ▼
      │     IREngine.auto_create_from_alert()
      │           │
      │           ▼
      │     Incident (DB) ←── Playbook selected by trigger_category
      │           │
      │           ▼
      │     PlaybookActions ←── SOAR auto-executes: log_ioc, trigger_scan, etc.
      │
      └─── All alerts → Dashboard · Compliance evaluation · Report generation
```

---

## Lab Network Topology

```
┌──────────────────────────────────────────────────┐
│              VMware Host-Only Network             │
│                  192.168.8.0/24                  │
│                                                  │
│  ┌─────────────────┐    ┌──────────────────────┐ │
│  │  Windows Host   │    │   Ubuntu 22.04 VM    │ │
│  │  192.168.8.1    │    │   192.168.8.130      │ │
│  │                 │    │                      │ │
│  │  SecureZone     │    │  Squid Proxy :3128   │ │
│  │  Backend :8000  │    │  squid_phishing_hook │ │
│  │  Frontend :5173 │    │  /opt/squid_phishing │ │
│  │  PostgreSQL     │    │  _hook.py            │ │
│  └─────────────────┘    └──────────────────────┘ │
│                                                  │
│  ┌──────────────────────┐  ┌───────────────────┐ │
│  │    Kali Linux VM     │  │  Metasploitable2  │ │
│  │    192.168.8.129     │  │  192.168.8.128    │ │
│  │                      │  │                   │ │
│  │  OpenVAS/GVM :9390   │  │  Intentionally    │ │
│  │  Attack tools        │  │  Vulnerable       │ │
│  └──────────────────────┘  └───────────────────┘ │
└──────────────────────────────────────────────────┘
```

**Squid Proxy Hook:** The Ubuntu VM runs a Squid forward proxy. A Python hook tails `/var/log/squid/access.log` in real time and POSTs every browsed URL to `POST /api/v1/phishing/ingest` for scoring. This catches phishing navigation from any machine routing traffic through the proxy.

---

## Tech Stack

### Backend
| Component | Technology |
|---|---|
| Framework | FastAPI 0.111 (async) |
| Database ORM | SQLAlchemy 2.0 (async) + asyncpg |
| Database | PostgreSQL 16 |
| Auth | JWT (python-jose) + bcrypt (passlib) |
| ML | scikit-learn 1.4 (Isolation Forest) |
| Scheduler | APScheduler 3.10 |
| PDF Generation | ReportLab 4.2 |
| HTTP Client | httpx 0.27 |
| Port Scanner | python-nmap |
| Vuln Scanner | python-gvm (OpenVAS/GVM) |

### Frontend
| Component | Technology |
|---|---|
| Framework | React 18 + Vite 5 |
| Routing | React Router v6 |
| State / Cache | TanStack Query v5 |
| HTTP | Axios |
| Charts | Recharts |
| Icons | Lucide React |
| Styling | Tailwind CSS v3 |

### External Services
| Service | Purpose |
|---|---|
| Groq API (`llama-3.1-8b-instant`) | AI chatbot with SIEM context |
| OpenVAS / GVM | Enterprise vulnerability scanning |
| Squid Proxy | Phishing URL interception |

---

## Project Structure

```
securezone/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── endpoints/
│   │   │       │   ├── alerts.py          # Alert CRUD + stats
│   │   │       │   ├── assets.py          # Asset inventory + enrichment
│   │   │       │   ├── auth.py            # Login, token refresh, user mgmt
│   │   │       │   ├── chat.py            # SecureBot chatbot (Groq API)
│   │   │       │   ├── compliance.py      # Compliance evaluation + policy CRUD
│   │   │       │   ├── incidents.py       # IR Engine: incidents, playbooks, SOAR
│   │   │       │   ├── phishing.py        # Phishing detection + ingest
│   │   │       │   ├── reports.py         # PDF report generation (3 types)
│   │   │       │   ├── scans.py           # VM scan jobs + scheduler
│   │   │       │   ├── siem.py            # SIEM dashboard + ingest
│   │   │       │   └── vulnerabilities.py # CVE tracking + CRUD
│   │   │       └── router.py
│   │   ├── core/
│   │   │   ├── config.py                  # Pydantic settings (reads .env)
│   │   │   └── security.py                # JWT helpers
│   │   ├── db/
│   │   │   └── session.py                 # Async SQLAlchemy engine + session
│   │   ├── models/
│   │   │   ├── alert.py                   # Alert, AlertSeverity, AlertCategory
│   │   │   ├── asset.py                   # Asset, AssetType, AssetCriticality
│   │   │   ├── compliance.py              # HardeningPolicy, ComplianceCheck
│   │   │   ├── incident.py                # Incident, Playbook, PlaybookAction
│   │   │   ├── user.py                    # User, Role
│   │   │   └── vulnerability.py           # Vulnerability, ScanJob
│   │   ├── schemas/                       # Pydantic request/response schemas
│   │   ├── services/
│   │   │   ├── compliance/
│   │   │   │   ├── engine.py              # ComplianceEngine orchestrator
│   │   │   │   └── evaluator.py           # PolicyEvaluator (11 rule types)
│   │   │   ├── ir/
│   │   │   │   ├── engine.py              # IREngine: auto incident creation
│   │   │   │   └── soar.py               # SOAR action executors
│   │   │   ├── siem/
│   │   │   │   ├── anomaly_detector.py   # Isolation Forest ML
│   │   │   │   ├── correlator.py         # Alert correlation rules
│   │   │   │   ├── engine.py             # SIEMEngine ingest pipeline
│   │   │   │   ├── normalizer.py         # Event normalization
│   │   │   │   ├── phishing.py           # URL phishing scoring engine
│   │   │   │   └── wazuh_collector.py    # Wazuh log collector
│   │   │   └── vm/
│   │   │       ├── engine.py             # VMEngine orchestrator
│   │   │       ├── nmap_scanner.py       # Nmap wrapper + port parsing
│   │   │       ├── openvas_scanner.py    # GVM/OpenVAS async client
│   │   │       └── scheduler.py          # APScheduler cron integration
│   │   └── main.py                       # App entrypoint + migrations
│   ├── scripts/
│   │   ├── seed_playbooks.py             # Seed 4 IR playbooks
│   │   ├── seed_policies.py              # Seed 18 compliance policies
│   │   └── squid_phishing_hook.py        # Deploy on Ubuntu Squid VM
│   ├── requirements.txt
│   └── .env                              # Environment variables (see below)
│
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── ChatBot.jsx               # Floating AI assistant widget
│       │   ├── Layout.jsx                # App shell + navigation
│       │   ├── ProtectedRoute.jsx        # JWT-gated route wrapper
│       │   ├── Sidebar.jsx               # Navigation sidebar
│       │   └── ui.jsx                    # Shared design system components
│       ├── context/
│       │   └── AuthContext.jsx           # JWT auth state + axios interceptors
│       ├── lib/
│       │   ├── api.js                    # Axios instance with base URL + auth
│       │   └── format.js                 # Number/date/severity formatters
│       ├── pages/
│       │   ├── Alerts.jsx                # Alert feed + filters
│       │   ├── Compliance.jsx            # Compliance score + policy list + evaluate
│       │   ├── Dashboard.jsx             # KPI overview + charts + report dropdown
│       │   ├── Incidents.jsx             # IR: incident list + playbook step panel
│       │   ├── Login.jsx                 # Auth form
│       │   ├── Phishing.jsx              # Phishing detections + risk scores
│       │   └── Vulnerabilities.jsx       # CVE list + severity breakdown
│       └── App.jsx
│
├── nginx/                                # Reverse proxy config (optional)
├── scripts/                              # Dev/deploy utilities
└── wazuh/                                # Wazuh agent integration files
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- PostgreSQL 16
- (Optional) Nmap installed at `/usr/bin/nmap` (or configured in `.env`)
- (Optional) OpenVAS/GVM on Kali at `192.168.8.129:9390`

### 1. Clone and set up the backend

```bash
cd backend
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure the database

```sql
-- In psql
CREATE USER securezone WITH PASSWORD 'securezone_secret';
CREATE DATABASE securezone_db OWNER securezone;
GRANT ALL PRIVILEGES ON DATABASE securezone_db TO securezone;
```

### 3. Configure environment variables

Copy and edit `.env`:

```bash
cp .env.example .env
# Edit .env with your values (see Configuration section below)
```

### 4. Start the backend

```bash
# From backend/ directory
uvicorn app.main:app --reload --reload-dir app --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`. Tables are created automatically on startup via SQLAlchemy `create_all`. Incremental migrations run automatically.

### 5. Seed initial data

```bash
# Seed 18 compliance policies (ISO 27001, DORA, CIS Controls)
python scripts/seed_policies.py

# Seed 4 IR playbooks (Brute Force, Phishing, Port Scan, Generic)
python scripts/seed_playbooks.py

# Create admin user (if a create_users.py script is available)
python create_users.py
```

### 6. Start the frontend

```bash
cd frontend
npm install
npm run dev
# Available at http://localhost:5173
```

### 7. Deploy the Squid phishing hook (Ubuntu VM)

```bash
# Copy the hook to the Ubuntu VM
scp backend/scripts/squid_phishing_hook.py hajer@192.168.8.130:/opt/

# On the Ubuntu VM:
sudo chown proxy:proxy /opt/squid_phishing_hook.py
sudo chmod 640 /opt/squid_phishing_hook.py

# Allow the proxy user to read Squid logs
sudo chmod 640 /var/log/squid/access.log
sudo chown proxy:proxy /var/log/squid/access.log
sudo usermod -aG proxy $USER

# Run the hook (as proxy user or via systemd)
sudo -u proxy python3 /opt/squid_phishing_hook.py
```

---

## Configuration

All settings are defined in `backend/app/core/config.py` and read from `backend/.env`.

```env
# Application
APP_NAME=SecureZone
DEBUG=false
SECRET_KEY=your-secret-key-here        # openssl rand -hex 32

# Allowed CORS origins (comma-separated)
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000

# Database
DATABASE_URL=postgresql+asyncpg://securezone:securezone_secret@localhost:5432/securezone_db

# JWT
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Scanning
NMAP_PATH=/usr/bin/nmap

# OpenVAS / GVM (on Kali VM)
GVM_HOST=192.168.8.129
GVM_PORT=9390
GVM_USERNAME=admin
GVM_PASSWORD=your-gvm-password

# Ingest API key (used by Squid hook and Wazuh)
INGEST_API_KEY=securezone-ingest-2024

# Groq API (AI chatbot)
GROQ_API_KEY=gsk_your_groq_api_key_here

# SMTP (optional — for SOAR notifications)
SMTP_HOST=localhost
SMTP_PORT=587
SMTP_USER=alerts@company.local
SMTP_PASSWORD=
SMTP_FROM=securezone@company.local
```

---

## Seed Scripts

| Script | Purpose | Run |
|---|---|---|
| `seed_policies.py` | Creates 18 compliance policies (ISO/DORA/CIS + SIEM-correlated rules) | `python scripts/seed_policies.py` |
| `seed_playbooks.py` | Creates 4 IR playbooks with step definitions | `python scripts/seed_playbooks.py` |
| `squid_phishing_hook.py` | Real-time Squid log tailer → phishing ingestion | Deployed to Ubuntu VM |

---

## API Reference

All endpoints are prefixed with `/api/v1`. Interactive documentation: `http://localhost:8000/docs`

### Authentication
```
POST /auth/login              # Returns access + refresh tokens
POST /auth/refresh            # Rotate tokens
GET  /auth/me                 # Current user info
```

### SIEM
```
POST /siem/ingest             # Ingest raw log batch
GET  /siem/dashboard          # KPI summary (total alerts, categories, top sources)
GET  /alerts/                 # Alert list with filters
GET  /alerts/stats            # Severity breakdown counts
PATCH /alerts/{id}/status     # Update alert status
```

### Vulnerability Management
```
POST /scans/                   # Create and launch scan
GET  /scans/                   # List scan jobs
POST /scans/{id}/run           # Manually trigger a scheduled scan
POST /scans/from-alert/{id}    # Trigger targeted scan from alert
GET  /vulnerabilities/         # CVE list with filters
GET  /vulnerabilities/stats    # Open/critical/patched counts
```

### Compliance
```
POST /compliance/evaluate      # Run full compliance evaluation
GET  /compliance/dashboard     # Global score + top violations
GET  /compliance/policies      # List all policies
POST /compliance/policies      # Create custom policy
POST /compliance/checks/{id}/grant-exception  # Grant exception
```

### Incident Response
```
GET  /incidents/               # List incidents (filterable by status/severity)
POST /incidents/               # Create incident manually
GET  /incidents/stats          # MTTD / MTTR metrics
GET  /incidents/{id}           # Full detail with playbook actions
PATCH /incidents/{id}/status   # Advance status in workflow
POST /incidents/{id}/note      # Add analyst note
POST /incidents/from-alert/{id}         # Create incident from alert
POST /incidents/actions/{id}/approve    # Approve a manual SOAR step
POST /incidents/actions/{id}/execute    # Execute an approved action
POST /incidents/actions/{id}/skip       # Skip a step
GET  /incidents/playbooks/list          # List available playbooks
```

### Phishing
```
POST /phishing/ingest          # Ingest URL for scoring (used by Squid hook)
GET  /phishing/alerts          # Phishing detection feed
GET  /phishing/stats           # Detection statistics
```

### Reports
```
GET /reports/executive         # Executive PDF (management/CISO)
GET /reports/technical         # Technical PDF (SOC engineers)
GET /reports/compliance        # Compliance PDF (ISO/DORA/CIS)
```

### ChatBot
```
POST /chat/message             # Send message, receive AI response with SIEM context
```

---

## Module Deep-Dives

### SIEM Engine

**File:** `app/services/siem/engine.py`

The SIEM pipeline processes raw log batches in 6 stages:

1. **Collection** — Accepts raw events from Wazuh, direct API POST, or Squid hook
2. **Normalization** — Converts heterogeneous formats into `SIEMEvent` objects with standard fields
3. **ML Anomaly Detection** — Isolation Forest model scores each event; statistical outliers get elevated risk scores
4. **Correlation** — Groups events by source IP + technique + time window into `CorrelatedAlert` objects
5. **Persistence** — Saves correlated and high-severity uncorrelated alerts to PostgreSQL
6. **IR Auto-trigger** — For every CRITICAL/HIGH alert saved, automatically calls `IREngine.auto_create_from_alert()`

**Phishing URL Scoring** (`app/services/siem/phishing.py`):

The scoring engine evaluates URLs on 6 dimensions, each contributing to a 0–100 risk score:

| Check | Score | Example |
|---|---|---|
| Known brand typosquatting | +40 | `paypa1.com` |
| Homoglyph substitution | +40 | `goog1e.com` |
| Suspicious TLD | +25 | `.tk`, `.ml`, `.ga` |
| High entropy domain | +20 | `xkf29a.xyz` |
| Excessive subdomain depth | +20 | `login.verify.update.bank.com` |
| IP address as hostname | +30 | `http://192.168.1.1/login` |

Detections above the threshold (default 50) are saved as `PHISHING` category alerts.

### Vulnerability Management

**Files:** `app/services/vm/engine.py`, `nmap_scanner.py`, `openvas_scanner.py`

- **Nmap scanner**: Runs `-sV -sC` service version detection, parses XML output into structured port/service data, enriches `Asset.open_ports`
- **OpenVAS/GVM scanner**: Connects to GVM API on Kali VM, creates scan targets, polls task completion, imports CVEs as `Vulnerability` records
- **VMEngine**: Orchestrates both scanners based on `ScanJob.scanner_type` (`nmap`, `openvas`, or `full`)
- **APScheduler**: Supports cron expressions per scan job (`"0 2 * * *"` = nightly at 2 AM)
- **Risk scoring**: CVE CVSS score × asset criticality weight → `Asset.risk_score`

### Compliance Engine

**Files:** `app/services/compliance/engine.py`, `evaluator.py`

The compliance engine is a **passive judge**: it reads existing SIEM, vulnerability, and asset data, evaluates it against defined policies, and produces compliance scores. It never generates alerts itself.

**Evaluation Formula:**
```
compliance_score = (compliant + 0.5 × partially_compliant) / applicable × 100
```

`NOT_APPLICABLE` checks are excluded from the denominator. Exception grants count as COMPLIANT.

**Supported Rule Types (11):**

| Rule Type | What It Checks | Data Source |
|---|---|---|
| `port_closed` | Port must be closed | `Asset.open_ports` (from Nmap) |
| `port_open` | Required service must be active | `Asset.open_ports` |
| `os_version` | OS must not match forbidden patterns | `Asset.os_name` |
| `service_disabled` | Service/daemon must not be running | `Asset.open_ports` |
| `patch_applied` | CVE must not be present | `Vulnerability` table |
| `vuln_score_max` | Risk score under threshold | `Asset.risk_score` |
| `tag_required` | Asset must have mandatory tag | `Asset.tags` |
| `field_value` | Arbitrary field equals/contains/not-null | `Asset.*` |
| `no_brute_force` | No open brute force alerts targeting this IP | `Alert` table (SIEM) |
| `no_phishing_detection` | No phishing navigation from this asset's IP | `Alert` table (SIEM) |
| `no_active_alerts` | No open alerts of specified categories | `Alert` table (SIEM) |

The last three rule types (`no_brute_force`, `no_phishing_detection`, `no_active_alerts`) make compliance **SIEM-correlated** — they cross-reference live alert data, so compliance scores degrade in real time when attacks are detected.

**Asset Weight for Global Score:**

| Asset Type | Weight |
|---|---|
| SERVER, FIREWALL | 3.0× |
| ROUTER, SWITCH | 2.0× |
| WORKSTATION | 1.0× |
| PRINTER, IOT | 0.5× |

### Incident Response & SOAR

**Files:** `app/services/ir/engine.py`, `soar.py`

**Incident lifecycle:**
```
NEW → ASSIGNED → INVESTIGATING → CONTAINMENT → ERADICATION → RECOVERY → CLOSED
```

MTTD (Mean Time To Detect) and MTTR (Mean Time To Respond) are calculated automatically from timestamps.

**Auto-trigger logic:** Every time the SIEM engine saves a CRITICAL or HIGH alert, `IREngine.auto_create_from_alert()` is called. It:
1. Checks for duplicates (same alert ID already linked to an open incident)
2. Creates the `Incident` record with extracted IOCs (source IP, destination IP)
3. Selects the best matching `Playbook` by `trigger_category`
4. Instantiates `PlaybookAction` records from the playbook's JSON step definitions
5. Auto-executes all steps where `requires_approval = False` in a background task

**SOAR Actions:**

| Action Type | Mode | What It Does |
|---|---|---|
| `log_ioc` | AUTO | Extracts IPs and phishing domains from the alert, adds to `incident.ioc_list` |
| `trigger_scan` | AUTO | Creates a `ScanJob` targeting the incident's victim IP, launches in background |
| `run_compliance` | AUTO | Triggers `ComplianceEngine.run_full_evaluation()` |
| `send_notification` | AUTO | Sends email to SOC team via SMTP (or logs notification body if SMTP not configured) |
| `block_ip` | MANUAL | Returns exact `iptables` commands to paste on the Ubuntu firewall VM |
| `squid_blacklist` | MANUAL | Returns exact commands to add domain to Squid blacklist |
| `manual_task` | MANUAL | Analyst reads description, performs action, then marks done |

**Manual actions display the exact commands to execute**, shown as a dark terminal block in the UI with copy-ready output.

### Phishing Detection

**Squid Hook (`scripts/squid_phishing_hook.py`):**

Deployed on the Ubuntu VM, this script:
- Tails `/var/log/squid/access.log` using `subprocess.Popen`
- Parses each access log line for the requested URL
- POSTs the URL to `POST /api/v1/phishing/ingest` with `X-Api-Key` authentication
- The backend scores the URL and creates an alert if the risk score exceeds the threshold

**Setup on Ubuntu:**
```bash
# Squid must be configured as a forward proxy
# Configure clients to use http://192.168.8.130:3128 as proxy

# The hook runs as the 'proxy' user to read access.log
sudo -u proxy python3 /opt/squid_phishing_hook.py
```

### PDF Reports

**File:** `app/api/v1/endpoints/reports.py`

Three report types, all built with ReportLab:

| Report | Audience | Contents |
|---|---|---|
| **Executive** | CISO / Management | KPI overview, risk posture summary, compliance score, top threats, strategic recommendations |
| **Technical** | SOC Engineers | Full alert list, all CVEs, scan results, compliance violation details, technical remediation |
| **Compliance** | Auditors / GRC | Per-framework scores (ISO 27001, DORA, CIS), policy-by-policy check results, exception log |

All reports feature:
- Dark-themed cover page with generation timestamp
- Page header/footer with SecureZone branding on all pages
- CONFIDENTIEL watermark
- Professional data tables with alternating row colors
- Dynamic recommendations based on actual data

Download from the Dashboard via the "Générer un rapport" dropdown, or from the Compliance page.

### AI Chatbot (SecureBot)

**Files:** `app/api/v1/endpoints/chat.py`, `frontend/src/components/ChatBot.jsx`

SecureBot is a floating chat widget available on all authenticated pages. It uses a RAG-like approach:

1. On every message, the backend fetches live SIEM context from the database:
   - Alert counts by severity (critical, high, medium, low)
   - 5 most recent critical/high alerts with titles and IPs
   - Open vulnerability count
   - Global compliance score
   - Active phishing detections
   - Total asset count

2. This context is injected into the Groq API system prompt

3. The LLM answers the analyst's question grounded in real data

**Example questions:**
- *"Combien d'alertes critiques avons-nous ?"*
- *"Quel est notre score de conformité ISO 27001 ?"*
- *"Y a-t-il des vulnérabilités critiques non traitées ?"*
- *"Quelles sont les actions prioritaires pour cette semaine ?"*

**Model:** `llama-3.1-8b-instant` via Groq API (fast inference, ~1s response)

**Configuration:** Set `GROQ_API_KEY` in `.env`. The widget appears in the bottom-right corner of all pages after login.

---

## Playbooks Reference

### Réponse Brute Force
**Trigger:** `alert.category == brute_force`  
**MITRE ATT&CK:** T1110 (Brute Force), T1021 (Remote Services)

| Step | Title | Mode | Action |
|---|---|---|---|
| 1 | Enregistrer les IOCs | AUTO | `log_ioc` — logs attacker IP and target IP |
| 2 | Scanner l'asset ciblé | AUTO | `trigger_scan` — Nmap scan of victim IP |
| 3 | Bloquer l'IP source | MANUAL | `block_ip` — iptables commands for Ubuntu |
| 4 | Réinitialiser les credentials | MANUAL | `manual_task` — analyst resets passwords |

### Réponse Phishing
**Trigger:** `alert.category == phishing`  
**MITRE ATT&CK:** T1566 (Phishing), T1598 (Spearphishing)

| Step | Title | Mode | Action |
|---|---|---|---|
| 1 | Enregistrer les IOCs | AUTO | `log_ioc` — logs phishing domain and source IP |
| 2 | Scanner le poste infecté | AUTO | `trigger_scan` — scan workstation for compromise |
| 3 | Blacklister le domaine | MANUAL | `squid_blacklist` — Squid config commands |
| 4 | Notifier l'équipe SOC | AUTO | `send_notification` — email alert |
| 5 | Sensibilisation utilisateur | MANUAL | `manual_task` — conduct awareness training |

### Réponse Port Scan
**Trigger:** `alert.category == port_scan`  
**MITRE ATT&CK:** T1046 (Network Service Discovery), T1595 (Active Scanning)

| Step | Title | Mode | Action |
|---|---|---|---|
| 1 | Enregistrer l'IOC | AUTO | `log_ioc` — logs scanner IP |
| 2 | Évaluer la conformité | AUTO | `run_compliance` — full policy evaluation |
| 3 | Qualifier la source | MANUAL | `manual_task` — internal scanner or attacker? |
| 4 | Bloquer si malveillant | MANUAL | `block_ip` — conditional IP block |

### Réponse Générique (Haute Sévérité)
**Trigger:** Fallback for any category without a specific playbook

| Step | Title | Mode | Action |
|---|---|---|---|
| 1 | Enregistrer les IOCs | AUTO | `log_ioc` |
| 2 | Scanner l'asset | AUTO | `trigger_scan` |
| 3 | Analyser et qualifier | MANUAL | `manual_task` — triage by analyst |
| 4 | Décision de containment | MANUAL | `manual_task` — containment action |

---

## Compliance Policies Reference

### ISO 27001 (8 policies)

| Control | Policy | Rule Type |
|---|---|---|
| A.13.1.1 | RDP non exposé (port 3389) | `port_closed` |
| A.13.1.1 | Telnet désactivé (port 23) | `port_closed` |
| A.13.1.1 | FTP désactivé (port 21) | `port_closed` |
| A.12.6.1 | SMBv1 désactivé (port 445) | `port_closed` |
| A.9.4.2 | SSH activé sur les serveurs | `port_open` |
| A.12.6.1 | OS non en fin de support | `os_version` |
| A.8.1 | Classification des assets (department non vide) | `field_value` |
| A.12.6.1 | Risque résiduel acceptable (max 7.0) | `vuln_score_max` |
| A.7.2.2 | Aucune navigation phishing détectée | `no_phishing_detection` |
| A.16.1.4 | Incidents de sécurité traités | `no_active_alerts` |

### DORA (5 policies)

| Control | Policy | Rule Type |
|---|---|---|
| Art.9.2 | BlueKeep patché (CVE-2019-0708) | `patch_applied` |
| Art.9.2 | EternalBlue patché (CVE-2017-0144) | `patch_applied` |
| Art.5.4 | Score de risque DORA faible (max 5.0, assets critiques) | `vuln_score_max` |
| Art.9.1 | Port 8080 non exposé (production) | `port_closed` |
| Art.9.3 | Aucune tentative de brute force active | `no_brute_force` |

### CIS Controls v8 (3 policies)

| Control | Policy | Rule Type |
|---|---|---|
| CIS-4.8 | SNMP v1/v2 désactivé (ports 161/162) | `service_disabled` |
| CIS-4.8 | VNC désactivé (ports 5900-5902) | `service_disabled` |
| CIS-13.3 | PostgreSQL non exposé (port 5432, production servers) | `port_closed` |

---

## Contributing

This is a learning/lab project. If you extend it, consider:

- Adding a Wazuh agent on Metasploitable2 for real-time attack telemetry
- Implementing ELK Stack integration (Elasticsearch index is already configured)
- Adding MITRE ATT&CK Navigator integration for technique visualization
- Extending the ML model with labeled attack data for supervised learning

---

## License

MIT License — built for educational purposes.
