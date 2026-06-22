#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecureZone — Script d'installation initiale
#  Usage : bash scripts/setup.sh
#
#  Ce script :
#    1. Vérifie les prérequis (Docker, Docker Compose)
#    2. Crée le fichier .env avec des valeurs sécurisées
#    3. Démarre tous les services
#    4. Crée l'utilisateur admin initial
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'

log()  { echo -e "${CYAN}[SecureZone]${RESET} $1"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $1"; }
warn() { echo -e "${YELLOW}[⚠]${RESET} $1"; }
err()  { echo -e "${RED}[✗]${RESET} $1"; exit 1; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║      SecureZone — Installation       ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════╝${RESET}"
echo ""

# ── 1. Vérification des prérequis ────────────────────────────────
log "Vérification des prérequis..."

command -v docker >/dev/null 2>&1 || err "Docker n'est pas installé. Voir https://docs.docker.com/get-docker/"
ok "Docker $(docker --version | cut -d' ' -f3 | tr -d ',')"

docker compose version >/dev/null 2>&1 || err "Docker Compose v2 requis. Voir https://docs.docker.com/compose/install/"
ok "Docker Compose $(docker compose version --short)"

# Vérifier les ressources minimales
TOTAL_MEM=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo "0")
if [ "$TOTAL_MEM" -lt 4096 ] 2>/dev/null; then
    warn "RAM disponible : ${TOTAL_MEM}MB. SecureZone recommande 8GB minimum."
fi

# ── 2. Fichier .env ───────────────────────────────────────────────
if [ -f ".env" ]; then
    warn ".env existe déjà — conservation des paramètres existants"
else
    log "Génération du fichier .env avec clés sécurisées..."
    cp .env.example .env

    # Générer des secrets aléatoires
    SECRET_KEY=$(openssl rand -hex 32)
    PG_PASS=$(openssl rand -base64 24 | tr -d "=/+" | cut -c1-20)
    REDIS_PASS=$(openssl rand -base64 16 | tr -d "=/+")

    # Remplacer les placeholders dans .env
    sed -i "s/CHANGE_ME_generate_with_openssl_rand_hex_32/${SECRET_KEY}/g" .env
    sed -i "s/securezone_secret_CHANGE_ME/${PG_PASS}/g" .env
    sed -i "s/redis_secret_CHANGE_ME/${REDIS_PASS}/g" .env

    ok ".env créé avec des secrets générés automatiquement"
fi

# ── 3. Démarrage des services ─────────────────────────────────────
log "Construction et démarrage des services..."
docker compose build --quiet
docker compose up -d

# ── 4. Attente que les services soient prêts ──────────────────────
log "Attente que PostgreSQL soit prêt..."
RETRIES=30
until docker compose exec -T postgres pg_isready -U securezone -q 2>/dev/null || [ $RETRIES -eq 0 ]; do
    printf "."
    sleep 2
    RETRIES=$((RETRIES - 1))
done
echo ""
[ $RETRIES -eq 0 ] && err "PostgreSQL ne répond pas après 60 secondes"
ok "PostgreSQL prêt"

log "Attente que le backend FastAPI soit prêt..."
RETRIES=20
until curl -sf http://localhost:8000/health >/dev/null 2>&1 || [ $RETRIES -eq 0 ]; do
    printf "."
    sleep 3
    RETRIES=$((RETRIES - 1))
done
echo ""
[ $RETRIES -eq 0 ] && err "Backend ne répond pas après 60 secondes"
ok "Backend prêt"

# ── 5. Création de l'utilisateur admin ───────────────────────────
log "Création de l'utilisateur administrateur..."
ADMIN_PASS=$(openssl rand -base64 12 | tr -d "=/+")

docker compose exec -T backend python - << PYEOF
import asyncio
from app.db.session import AsyncSessionLocal
from app.models.user import User, UserRole
from app.core.security import hash_password

async def create_admin():
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(User).where(User.username == 'admin'))
        if result.scalar_one_or_none():
            print("Admin existe déjà")
            return
        admin = User(
            email="admin@securezone.local",
            username="admin",
            full_name="Administrateur SecureZone",
            hashed_password=hash_password("${ADMIN_PASS}"),
            role=UserRole.ADMIN,
            is_superuser=True,
        )
        db.add(admin)
        await db.commit()
        print("Admin créé avec succès")

asyncio.run(create_admin())
PYEOF

# ── 6. Résumé ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║      SecureZone installé avec succès !       ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}Dashboard :${RESET}  http://localhost"
echo -e "  ${CYAN}API Docs  :${RESET}  http://localhost/docs"
echo -e "  ${CYAN}Login     :${RESET}  admin / ${ADMIN_PASS}"
echo ""
echo -e "  ${YELLOW}⚠  Notez ce mot de passe — il ne sera plus affiché${RESET}"
echo ""
echo -e "  Logs :   ${CYAN}make logs${RESET}"
echo -e "  Status : ${CYAN}make status${RESET}"
echo -e "  Arrêt :  ${CYAN}make down${RESET}"
echo ""
