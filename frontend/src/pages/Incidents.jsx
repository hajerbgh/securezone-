import { useQuery } from "@tanstack/react-query";
import { Siren, Clock, Activity } from "lucide-react";
import api from "../lib/api";
import { Card, KpiCard, SeverityBadge, StatusBadge, Spinner, EmptyState } from "../components/ui";
import { formatNumber, formatRelativeTime } from "../lib/format";

export default function Incidents() {
  // L'IR Engine n'a pas encore d'endpoints — on prépare l'UI
  // et on tombe proprement en l'absence de données.
  const { data: incidents, isLoading } = useQuery({
    queryKey: ["incidents"],
    queryFn: async () => {
      try {
        return (await api.get("/incidents/")).data;
      } catch {
        return []; // Endpoint pas encore disponible
      }
    },
    retry: false,
  });

  const list = incidents || [];

  // Stats calculées côté client
  const openCount = list.filter((i) => i.status !== "closed").length;
  const criticalCount = list.filter((i) => i.severity === "critical").length;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold text-ink">Réponse aux incidents</h1>
        <p className="mt-0.5 text-sm text-ink-muted">
          Gestion des incidents de sécurité et playbooks de remédiation
        </p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard label="Incidents ouverts" value={formatNumber(openCount)} variant="neutral" />
        <KpiCard label="Critiques" value={formatNumber(criticalCount)} variant="critical" />
        <KpiCard label="MTTD moyen" value="—" hint="Temps de détection" variant="medium" />
        <KpiCard label="MTTR moyen" value="—" hint="Temps de réponse" variant="low" />
      </div>

      {/* Bannière IR Engine en construction */}
      {!list.length && !isLoading && (
        <div className="rounded-card border border-amber-200 bg-amber-50 px-5 py-4">
          <div className="flex items-start gap-3">
            <Activity className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
            <div>
              <p className="text-sm font-medium text-amber-900">
                Moteur de réponse aux incidents en cours de déploiement
              </p>
              <p className="mt-0.5 text-sm text-amber-700">
                Le backend IR Engine (incidents automatiques + playbooks) sera la prochaine
                étape de développement. Cette vue est prête à l'afficher dès son activation.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Liste des incidents */}
      <Card className="overflow-hidden p-0">
        {isLoading ? (
          <Spinner />
        ) : !list.length ? (
          <EmptyState
            icon={Siren}
            title="Aucun incident actif"
            message="Les incidents sont créés automatiquement depuis les alertes critiques."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs font-medium text-ink-subtle">
                  <th className="px-5 py-3">Sévérité</th>
                  <th className="px-5 py-3">Incident</th>
                  <th className="px-5 py-3">Statut</th>
                  <th className="px-5 py-3">Risque</th>
                  <th className="px-5 py-3">Détecté</th>
                </tr>
              </thead>
              <tbody>
                {list.map((inc) => (
                  <tr key={inc.id} className="border-b border-slate-100 transition hover:bg-surface-hover">
                    <td className="px-5 py-3"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-5 py-3">
                      <p className="font-medium text-ink line-clamp-1">{inc.title}</p>
                    </td>
                    <td className="px-5 py-3"><StatusBadge status={inc.status} /></td>
                    <td className="px-5 py-3 tabular font-semibold text-ink">
                      {inc.risk_score?.toFixed(1) || "—"}
                    </td>
                    <td className="px-5 py-3 text-xs text-ink-subtle">
                      <span className="inline-flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatRelativeTime(inc.detected_at || inc.created_at)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
