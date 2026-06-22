import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ScanSearch, Play } from "lucide-react";
import api from "../lib/api";
import { Card, KpiCard, SeverityBadge, StatusBadge, Spinner, EmptyState } from "../components/ui";
import { formatNumber } from "../lib/format";

export default function Vulnerabilities() {
  const [severity, setSeverity] = useState("");

  const { data: stats } = useQuery({
    queryKey: ["vuln-stats"],
    queryFn: async () => (await api.get("/vulnerabilities/stats")).data,
  });

  const { data: vulns, isLoading } = useQuery({
    queryKey: ["vulns", severity],
    queryFn: async () => {
      const params = severity ? { severity } : {};
      return (await api.get("/vulnerabilities/", { params })).data;
    },
  });

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-ink">Gestion des vulnérabilités</h1>
          <p className="mt-0.5 text-sm text-ink-muted">
            CVEs détectées par Nmap et OpenVAS sur le parc
          </p>
        </div>
        <button className="btn btn-primary">
          <Play className="h-4 w-4" />
          Lancer un scan
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard label="Total CVEs" value={formatNumber(stats?.total || 0)} variant="neutral" />
        <KpiCard label="Critiques" value={formatNumber(stats?.critical || 0)} variant="critical" />
        <KpiCard label="Élevées" value={formatNumber(stats?.high || 0)} variant="high" />
        <KpiCard label="Ouvertes" value={formatNumber(stats?.open || 0)} variant="medium" />
      </div>

      {/* Filtres */}
      <div className="flex gap-1.5 rounded-lg border border-slate-200 bg-surface p-1 w-fit">
        {["", "critical", "high", "medium", "low"].map((s) => (
          <button
            key={s}
            onClick={() => setSeverity(s)}
            className={`rounded-md px-3 py-1.5 text-sm font-medium capitalize transition ${
              severity === s ? "bg-brand-600 text-white" : "text-ink-muted hover:bg-surface-hover"
            }`}
          >
            {s === "" ? "Toutes" : s}
          </button>
        ))}
      </div>

      {/* Table */}
      <Card className="overflow-hidden p-0">
        {isLoading ? (
          <Spinner />
        ) : !vulns?.length ? (
          <EmptyState icon={ScanSearch} title="Aucune vulnérabilité" message="Lancez un scan pour détecter les CVEs." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs font-medium text-ink-subtle">
                  <th className="px-5 py-3">Sévérité</th>
                  <th className="px-5 py-3">CVE</th>
                  <th className="px-5 py-3">Titre</th>
                  <th className="px-5 py-3">CVSS</th>
                  <th className="px-5 py-3">Port</th>
                  <th className="px-5 py-3">Statut</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((v) => (
                  <tr key={v.id} className="border-b border-slate-100 transition hover:bg-surface-hover">
                    <td className="px-5 py-3"><SeverityBadge severity={v.severity} /></td>
                    <td className="px-5 py-3 font-mono text-xs text-brand-700">{v.cve_id || "—"}</td>
                    <td className="px-5 py-3">
                      <p className="font-medium text-ink line-clamp-1">{v.title}</p>
                    </td>
                    <td className="px-5 py-3">
                      <span className="tabular font-semibold text-ink">{v.cvss_score?.toFixed(1) || "—"}</span>
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-ink-muted">
                      {v.affected_port || "—"}/{v.affected_service || ""}
                    </td>
                    <td className="px-5 py-3"><StatusBadge status={v.status} /></td>
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
