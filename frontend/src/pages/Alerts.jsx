import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import api from "../lib/api";
import { Card, SeverityBadge, StatusBadge, Spinner, EmptyState } from "../components/ui";
import { formatRelativeTime } from "../lib/format";

const SEVERITIES = ["", "critical", "high", "medium", "low"];
const SEV_LABELS = { "": "Toutes", critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible" };

export default function Alerts() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");

  const { data: alerts, isLoading } = useQuery({
    queryKey: ["alerts", severity, status],
    queryFn: async () => {
      const params = {};
      if (severity) params.severity = severity;
      if (status) params.status = status;
      const { data } = await api.get("/alerts/", { params });
      return data;
    },
    refetchInterval: 20000,
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold text-ink">Alertes de sécurité</h1>
        <p className="mt-0.5 text-sm text-ink-muted">
          Événements détectés par le moteur SIEM et corrélés en temps réel
        </p>
      </div>

      {/* Filtres */}
      <div className="flex flex-wrap gap-3">
        <div className="flex gap-1.5 rounded-lg border border-slate-200 bg-surface p-1">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition ${
                severity === s ? "bg-brand-600 text-white" : "text-ink-muted hover:bg-surface-hover"
              }`}
            >
              {SEV_LABELS[s]}
            </button>
          ))}
        </div>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-lg border border-slate-200 bg-surface px-3 py-1.5 text-sm outline-none focus:border-brand-400"
        >
          <option value="">Tous les statuts</option>
          <option value="open">Ouvertes</option>
          <option value="investigating">En cours</option>
          <option value="resolved">Résolues</option>
        </select>
      </div>

      {/* Table */}
      <Card className="overflow-hidden p-0">
        {isLoading ? (
          <Spinner />
        ) : !alerts?.length ? (
          <EmptyState
            icon={ShieldAlert}
            title="Aucune alerte"
            message="Aucune alerte ne correspond aux filtres sélectionnés."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs font-medium text-ink-subtle">
                  <th className="px-5 py-3">Sévérité</th>
                  <th className="px-5 py-3">Alerte</th>
                  <th className="px-5 py-3">Source</th>
                  <th className="px-5 py-3">MITRE</th>
                  <th className="px-5 py-3">Statut</th>
                  <th className="px-5 py-3">Détectée</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id} className="border-b border-slate-100 transition hover:bg-surface-hover">
                    <td className="px-5 py-3"><SeverityBadge severity={a.severity} /></td>
                    <td className="px-5 py-3">
                      <p className="font-medium text-ink line-clamp-1">{a.title}</p>
                      <p className="text-xs text-ink-subtle">{a.category}</p>
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-ink-muted">
                      {a.source_ip || "—"}
                    </td>
                    <td className="px-5 py-3">
                      {a.mitre_technique_id ? (
                        <span className="rounded bg-brand-50 px-1.5 py-0.5 font-mono text-xs text-brand-700">
                          {a.mitre_technique_id}
                        </span>
                      ) : "—"}
                    </td>
                    <td className="px-5 py-3"><StatusBadge status={a.status} /></td>
                    <td className="px-5 py-3 text-xs text-ink-subtle">
                      {formatRelativeTime(a.created_at)}
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
