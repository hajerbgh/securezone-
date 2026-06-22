-- ══════════════════════════════════════════════════════════════
--  SecureZone — Initialisation PostgreSQL
--  Exécuté automatiquement au premier démarrage du conteneur
-- ══════════════════════════════════════════════════════════════

-- Extensions utiles
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";   -- Génération UUID
CREATE EXTENSION IF NOT EXISTS "pg_trgm";     -- Recherche fuzzy (LIKE rapide)

-- Les tables sont créées par SQLAlchemy/Alembic au démarrage du backend
-- Ce script ne fait que préparer les extensions et le schéma initial

-- Index supplémentaires pour les performances (créés après les tables)
-- Ces commandes seront ignorées si les tables n'existent pas encore
DO $$
BEGIN
    -- Index full-text sur les alertes (recherche par titre)
    IF EXISTS (SELECT FROM pg_tables WHERE tablename = 'alerts') THEN
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_title_trgm
            ON alerts USING gin(title gin_trgm_ops);

        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_created_severity
            ON alerts(created_at DESC, severity);
    END IF;

    -- Index sur les vulnérabilités pour le dashboard
    IF EXISTS (SELECT FROM pg_tables WHERE tablename = 'vulnerabilities') THEN
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vuln_cvss_desc
            ON vulnerabilities(cvss_score DESC NULLS LAST)
            WHERE status = 'open';
    END IF;

EXCEPTION WHEN OTHERS THEN
    -- Ignorer les erreurs si les tables n'existent pas encore
    NULL;
END $$;
