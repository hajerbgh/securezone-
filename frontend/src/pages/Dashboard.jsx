import { useQuery } from "@tanstack/react-query";
import {
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  BarChart, Bar,
} from "recharts";
import { FileDown, Plus } from "lucide-react";
import api from "../lib/api";
import { Card, KpiCard, Spinner } from "../components/ui";
import { formatNumber, formatRelativeTime, CHART_PALETTE } from "../lib/format";

// Récupère plusieurs stats en parallèle pour le dashboard
function useDashboardData() {
  return useQuery({
    queryKey: ["dashboard"],
    queryFn: async () => {
      const [siem, alertStats, vulnStats, compliance, assetStats] =
        await Promise.all([
          api.get("/siem/dashboard").then((r) => r.data).catch(() => null),
          api.get("/alerts/stats").then((r) => r.data).catch(() => null),
          api.get("/vulnerabilities/stats").then((r) => r.data).catch(() => null),
          api.get("/compliance/dashboard").then((r) => r.data).catch(() => null),
          api.get("/assets/stats").then((r) => r.data).catch(() => null),
        ]);
      return { siem, alertStats, vulnStats, compliance, assetStats };
    },
    refetchInterval: 30000, // Rafraîchit toutes les 30s (sensation temps réel)
  });
}

export default function Dashboard() {
  const { data, isLoading } = useDashboardData();

  if (isLoading) return <Spinner />;

  const siem = data?.siem || {};
  const alertStats = data?.alertStats || {};
  const vulnStats = data?.vulnStats || {};
  const compliance = data?.compliance || {};

  const updated = formatRelativeTime(new Date());

  // Données pour le donut des catégories d'alertes
  const categoryData = (siem.top_categories || []).map((c) => ({
    name: c.category,
    value: c.count,
  }));

  // Données pour le donut MITRE (réutilise top_sources faute de mieux)
  const severityData = [
    { name: "Critique", value: alertStats.critical || 0 },
    { name: "Élevée", value: alertStats.high || 0 },
    { name: "Moyenne", value: alertStats.medium || 0 },
    { name: "Faible", value: alertStats.low || 0 },
  ].filter((d) => d.value > 0);

  // Données simulées pour le graphe temporel (le backend ne fournit pas encore d'historique)
  const timeSeriesData = generateTimeSeries();

  return (
    <div className="space-y-5">
      {/* En-tête de page */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-ink">Tableau de bord</h1>
          <p className="mt-0.5 text-sm text-ink-muted">
            Vue d'ensemble de la posture de sécurité
          </p>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-ghost">
            <FileDown className="h-4 w-4" />
            Générer un rapport
          </button>
          <button className="btn btn-primary">
            <Plus className="h-4 w-4" />
            Créer un ticket
          </button>
        </div>
      </div>

      {/* Cartes KPI */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Alertes totales"
          value={formatNumber(siem.total_alerts || 0)}
          variant="neutral"
          updated={updated}
        />
        <KpiCard
          label="Alertes critiques"
          value={formatNumber(siem.critical_count || 0)}
          hint={`${siem.critical_count || 0} actions immédiates`}
          variant="critical"
          updated={updated}
        />
        <KpiCard
          label="Alertes élevées"
          value={formatNumber(siem.high_count || 0)}
          hint={`${siem.high_count || 0} à investiguer`}
          variant="high"
          updated={updated}
        />
        <KpiCard
          label="Vulnérabilités ouvertes"
          value={formatNumber(vulnStats.open || 0)}
          hint={`${vulnStats.critical || 0} critiques`}
          variant="medium"
          updated={updated}
        />
      </div>

      {/* Ligne 1 : sources + types d'alertes */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card
          title="Activité des alertes"
          subtitle="Volume sur les dernières 24 heures"
          className="lg:col-span-2"
        >
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timeSeriesData} margin={{ left: -20, right: 8, top: 8 }}>
              <defs>
                <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4F46E5" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#4F46E5" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
              <XAxis dataKey="hour" tick={{ fontSize: 11, fill: "#94A3B8" }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#94A3B8" }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{
                  borderRadius: 10,
                  border: "1px solid #E2E8F0",
                  fontSize: 12,
                }}
              />
              <Area
                type="monotone"
                dataKey="alerts"
                stroke="#4F46E5"
                strokeWidth={2}
                fill="url(#g1)"
                name="Alertes"
              />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Répartition par sévérité" subtitle={`${formatNumber(alertStats.total || 0)} alertes`}>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={2}
                >
                  {severityData.map((_, i) => (
                    <Cell key={i} fill={CHART_PALETTE[i % CHART_PALETTE.length]} />
                  ))}
                </Pie>
                <Legend
                  iconType="circle"
                  wrapperStyle={{ fontSize: 12 }}
                />
                <Tooltip contentStyle={{ borderRadius: 10, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[260px] items-center justify-center text-sm text-ink-subtle">
              Aucune alerte
            </div>
          )}
        </Card>
      </div>

      {/* Ligne 2 : MITRE + conformité */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card title="Top catégories d'attaque" subtitle="Techniques détectées">
          {categoryData.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={categoryData} layout="vertical" margin={{ left: 20 }}>
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={{ fontSize: 11, fill: "#64748B" }}
                  tickLine={false}
                  axisLine={false}
                  width={110}
                />
                <Tooltip contentStyle={{ borderRadius: 10, fontSize: 12 }} cursor={{ fill: "#F1F5F9" }} />
                <Bar dataKey="value" fill="#4F46E5" radius={[0, 4, 4, 0]} name="Alertes" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[240px] items-center justify-center text-sm text-ink-subtle">
              Aucune donnée
            </div>
          )}
        </Card>

        <Card
          title="Score de conformité"
          subtitle="ISO 27001 · DORA · CIS"
          className="lg:col-span-2"
        >
          <div className="flex items-center gap-8 py-4">
            <div className="relative flex h-36 w-36 items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={[
                      { value: compliance.global_score || 0 },
                      { value: 100 - (compliance.global_score || 0) },
                    ]}
                    dataKey="value"
                    innerRadius={52}
                    outerRadius={68}
                    startAngle={90}
                    endAngle={-270}
                  >
                    <Cell fill="#4F46E5" />
                    <Cell fill="#E2E8F0" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute text-center">
                <p className="tabular text-2xl font-bold text-ink">
                  {Math.round(compliance.global_score || 0)}%
                </p>
                <p className="text-[11px] text-ink-subtle">conforme</p>
              </div>
            </div>
            <div className="flex-1 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                <span className="text-sm text-ink-muted">Assets non conformes</span>
                <span className="text-sm font-semibold text-ink">
                  {compliance.non_compliant_assets || 0}
                </span>
              </div>
              {(compliance.top_violated_policies || []).slice(0, 3).map((p, i) => (
                <div key={i} className="flex items-center justify-between text-sm">
                  <span className="truncate text-ink-muted">{p.policy}</span>
                  <span className="ml-2 shrink-0 font-medium text-sev-high">
                    {p.violations}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

// Génère une série temporelle factice pour le graphe (24h)
// Sera remplacé par un vrai endpoint d'historique plus tard.
function generateTimeSeries() {
  const data = [];
  for (let h = 0; h < 24; h += 2) {
    data.push({
      hour: `${String(h).padStart(2, "0")}h`,
      alerts: Math.floor(40 + Math.random() * 120 + (h > 8 && h < 18 ? 60 : 0)),
    });
  }
  return data;
}
