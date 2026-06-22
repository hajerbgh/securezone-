# ══════════════════════════════════════════════════════════════════
#  SecureZone — Makefile
#  Commandes utiles pour le développement et la production
# ══════════════════════════════════════════════════════════════════

.PHONY: help up down restart logs shell-backend shell-db migrate seed clean

# Couleurs
CYAN  = \033[0;36m
RESET = \033[0m

help: ## Affiche cette aide
	@echo ""
	@echo "  $(CYAN)SecureZone — Commandes disponibles$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ── Cycle de vie ─────────────────────────────────────────────────

up: ## Démarrer tous les services
	@echo "$(CYAN)Démarrage de SecureZone...$(RESET)"
	cp -n .env.example .env 2>/dev/null || true
	docker compose up -d
	@echo "$(CYAN)✅ SecureZone démarré$(RESET)"
	@echo "   Dashboard : http://localhost"
	@echo "   API docs  : http://localhost/docs"

down: ## Arrêter tous les services
	docker compose down

restart: ## Redémarrer un service (ex: make restart s=backend)
	docker compose restart $(s)

logs: ## Suivre les logs (ex: make logs s=backend)
	docker compose logs -f $(or $(s), backend)

status: ## État de tous les services
	docker compose ps

# ── Développement ─────────────────────────────────────────────────

build: ## Reconstruire les images
	docker compose build --no-cache $(s)

shell-backend: ## Shell dans le conteneur backend
	docker compose exec backend bash

shell-db: ## psql dans PostgreSQL
	docker compose exec postgres psql -U securezone -d securezone_db

redis-cli: ## Redis CLI
	docker compose exec redis redis-cli -a $$(grep REDIS_PASSWORD .env | cut -d= -f2)

# ── Base de données ───────────────────────────────────────────────

migrate: ## Appliquer les migrations Alembic
	docker compose exec backend alembic upgrade head

migrate-create: ## Créer une nouvelle migration (ex: make migrate-create m="add_column_x")
	docker compose exec backend alembic revision --autogenerate -m "$(m)"

seed: ## Insérer des données de test
	docker compose exec backend python scripts/seed_data.py

# ── Production ────────────────────────────────────────────────────

build-prod: ## Build image de production
	docker compose -f docker-compose.yml -f docker-compose.prod.yml build

up-prod: ## Démarrer en mode production
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

gen-certs: ## Générer les certificats SSL auto-signés
	bash scripts/gen_certs.sh

# ── Monitoring optionnel ──────────────────────────────────────────

monitoring: ## Démarrer avec Kibana (monitoring)
	docker compose --profile monitoring up -d

# ── Nettoyage ─────────────────────────────────────────────────────

clean: ## Supprimer conteneurs + volumes (⚠️ perte de données)
	@echo "$(CYAN)⚠️  Suppression de tous les volumes...$(RESET)"
	docker compose down -v --remove-orphans
	docker image prune -f

clean-logs: ## Vider les logs Docker
	docker compose logs --no-color > /dev/null 2>&1 || true
