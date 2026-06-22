import { useQuery } from "@tanstack/react-query";
import { ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { FileCheck2, FileDown } from "lucide-react";
import api from "../lib/api";
import { Card, SeverityBadge, Spinner, EmptyState } from "../components/ui";

export default function Compliance() {
  const { data: dashboard, isLoading } = useQuery({
    queryKey: ["compliance-dashboard"],
    queryFn: async () => (await api.get("/compliance/dashboard")).data,
  });

  const { data: policies } = useQuery({
    queryKey: ["policies"],
    queryFn: async () => (await api.get("/compliance/policies")).data,
  });

  if (isLoading) return <Spinner />;

  const score = Math.round(dashboard?.global_score || 0);
  const scoreColor = score >= 90 ? "#0F766E" : score >= 70 ? "#D97706" : "#DC2626";

  // Grouper les policies par framework
  const byFramework = (policies || []).reduce((acc, p) => {
    (acc[p.framework] = acc[p.framework] || []).push(p);
    return acc;
  }, {});

  const FRAMEWORK_LABELS = {
    iso_27001: "ISO 27001",
    dora: "DORA",
    cis: "CIS Controls",
    custom: "Personnalisé",
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-ink">Conformité réglementaire</h1>
          <p className="mt-0.5 text-sm text-ink-muted">
            Évaluation continue ISO 27001, DORA et CIS Controls
          </p>
        </div>
        <button className="btn btn-primary">
          <FileDown className="h-4 w-4" />
          Générer le rapport PDF
        </button>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Score global */}
        <Card title="Score global">
          <div className="flex flex-col items-center py-4">
            <div className="relative flex h-40 w-40 items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={[{ value: score }, { value: 100 - score }]}
                    dataKey="value"
                    innerRadius={58}
                    outerRadius={74}
                    startAngle={90}
                    endAngle={-270}
                  >
                    <Cell fill={scoreColor} />
                    <Cell fill="#E2E8F0" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute text-center">
                <p className="tabular text-3xl font-bold" style={{ color: scoreColor }}>
                  {score}%
                </p>
              </div>
            </div>
            <p className="mt-2 text-sm text-ink-muted">
              {dashboard?.non_compliant_assets || 0} assets non conformes
            </p>
          </div>
        </Card>

        {/* Top policies violées */}
        <Card title="Politiques les plus violées" className="lg:col-span-2">
          {dashboard?.top_violated_policies?.length ? (
            <div className="space-y-3">
              {dashboard.top_violated_policies.map((p, i) => (
                <div key={i} className="flex items-center gap-3">
                  <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-ink-muted">
                    {FRAMEWORK_LABELS[p.framework] || p.framework}
                  </span>
                  <span className="flex-1 truncate text-sm text-ink">{p.policy}</span>
                  <span className="rounded-full bg-red-50 px-2.5 py-0.5 text-xs font-semibold text-sev-high">
                    {p.violations} violations
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState icon={FileCheck2} title="Aucune violation" message="Lancez une évaluation de conformité." />
          )}
        </Card>
      </div>

      {/* Politiques par framework */}
      {Object.entries(byFramework).map(([fw, items]) => (
        <Card key={fw} title={FRAMEWORK_LABELS[fw] || fw} subtitle={`${items.length} politiques`}>
          <div className="space-y-2">
            {items.map((p) => (
              <div key={p.id} className="flex items-center justify-between rounded-lg border border-slate-100 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-ink">{p.name}</p>
                  <p className="text-xs text-ink-subtle">{p.control_id} · {p.rule_type}</p>
                </div>
                <SeverityBadge severity={p.severity} />
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}
