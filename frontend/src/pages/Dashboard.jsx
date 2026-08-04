import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  BarChart, Bar,
} from "recharts";
import { FileDown, Plus, ChevronDown, Loader2, FileText, Shield, CheckSquare, X, AlertTriangle } from "lucide-react";
import api from "../lib/api";
import { Card, KpiCard, Spinner } from "../components/ui";
import { formatNumber, formatRelativeTime, CHART_PALETTE } from "../lib/format";
import { useRole } from "../context/AuthContext";

const SEVERITY_OPTIONS = [
  { value: "critical", label: "Critique",  color: "text-red-600" },
  { value: "high",     label: "Élevée",    color: "text-orange-500" },
  { value: "medium",   label: "Moyenne",   color: "text-amber-500" },
  { value: "low",      label: "Faible",    color: "text-blue-500" },
];

function CreateIncidentModal({ onClose }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [form, setForm] = useState({ title: "", severity: "high", description: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function submit(e) {
    e.preventDefault();
    if (!form.title.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.post("/incidents/", {
        title: form.title.trim(),
        severity: form.severity,
        description: form.description.trim() || null,
      });
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: ["incident-stats"] });
      onClose();
      navigate(`/incidents`);
    } catch (err) {
      setError(err?.response?.data?.detail || "Erreur lors de la création.");
    } finally {
      setLoading(false);
    }
  }

  // Close on Escape
  useEffect(() => {
    const handler = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-orange-500" />
            <h2 className="text-base font-semibold text-ink">Créer un incident</h2>
          </div>
          <button onClick={onClose} className="rounded p-1 hover:bg-slate-100">
            <X className="h-4 w-4 text-ink-muted" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={submit} className="space-y-4 px-6 py-5">
          {/* Title */}
          <div>
            <label className="mb-1.5 block text-xs font-semibold text-ink-muted uppercase tracking-wider">
              Titre *
            </label>
            <input
              autoFocus
              value={form.title}
              onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
              placeholder="ex: Accès non autorisé détecté sur le serveur web"
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm text-ink placeholder-slate-400 focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
              required
            />
          </div>

          {/* Severity */}
          <div>
            <label className="mb-1.5 block text-xs font-semibold text-ink-muted uppercase tracking-wider">
              Sévérité
            </label>
            <div className="grid grid-cols-4 gap-2">
              {SEVERITY_OPTIONS.map((s) => (
                <button
                  key={s.value}
                  type="button"
                  onClick={() => setForm((f) => ({ ...f, severity: s.value }))}
                  className={`rounded-xl border py-2 text-xs font-semibold transition-colors ${
                    form.severity === s.value
                      ? "border-brand-400 bg-brand-50 text-brand-700"
                      : "border-slate-200 bg-white text-slate-500 hover:border-slate-300"
                  }`}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="mb-1.5 block text-xs font-semibold text-ink-muted uppercase tracking-wider">
              Description <span className="font-normal normal-case text-slate-400">(optionnel)</span>
            </label>
            <textarea
              rows={3}
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              placeholder="Contexte, IPs impliquées, vecteur d'attaque..."
              className="w-full resize-none rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm text-ink placeholder-slate-400 focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
            />
          </div>

          {error && (
            <p className="rounded-lg bg-red-50 px-3 py-2 text-xs text-red-600">{error}</p>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="btn btn-ghost"
              disabled={loading}
            >
              Annuler
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading || !form.title.trim()}
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              {loading ? "Création…" : "Créer l'incident"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

const REPORT_TYPES = [
  { key: "executive",  label: "Rapport Exécutif",  icon: Shield,      desc: "Management / CISO" },
  { key: "technical",  label: "Rapport Technique",  icon: FileText,    desc: "SOC Engineers" },
  { key: "compliance", label: "Rapport Conformité", icon: CheckSquare, desc: "ISO 27001 · DORA · CIS" },
];

function ReportDropdown() {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(null);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const download = async (type) => {
    setOpen(false);
    setLoading(type);
    try {
      const res = await api.get(`/reports/${type}`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([res.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `securezone-${type}-${new Date().toISOString().slice(0, 10)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Erreur génération rapport", err);
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="relative" ref={ref}>
      <button
        className="btn btn-ghost flex items-center gap-1.5"
        onClick={() => setOpen((o) => !o)}
        disabled={!!loading}
      >
        {loading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <FileDown className="h-4 w-4" />
        )}
        {loading ? "Génération…" : "Générer un rapport"}
        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="absolute right-0 top-full z-50 mt-1 w-56 rounded-xl border border-slate-200 bg-white shadow-lg">
          <p className="px-3 pt-2.5 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Type de rapport
          </p>
          {REPORT_TYPES.map(({ key, label, icon: Icon, desc }) => (
            <button
              key={key}
              className="flex w-full items-start gap-3 px-3 py-2.5 text-left hover:bg-slate-50 last:mb-1"
              onClick={() => download(key)}
            >
              <Icon className="mt-0.5 h-4 w-4 shrink-0 text-brand-500" />
              <div>
                <p className="text-sm font-medium text-slate-800">{label}</p>
                <p className="text-xs text-slate-400">{desc}</p>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

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
    refetchInterval: 30000,
  });
}

export default function Dashboard() {
  const { data, isLoading } = useDashboardData();
  const { canWrite, isAdmin } = useRole();
  const [showCreateIncident, setShowCreateIncident] = useState(false);
  const [historyRange, setHistoryRange] = useState("24h");

  const { data: historyData = [] } = useQuery({
    queryKey: ["alert-history", historyRange],
    queryFn: () => api.get("/alerts/history", { params: { range: historyRange } }).then(r => r.data).catch(() => []),
    refetchInterval: 60000,
  });

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

  // Données pour le donut par sévérité
  const severityData = [
    { name: "Critique", value: alertStats.critical || 0 },
    { name: "Élevée", value: alertStats.high || 0 },
    { name: "Moyenne", value: alertStats.medium || 0 },
    { name: "Faible", value: alertStats.low || 0 },
  ].filter((d) => d.value > 0);

  // Fallback to mock data only if real history query is still loading
  const timeSeriesData = historyData.length ? historyData : generateTimeSeries();

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
          <ReportDropdown />
          {canWrite && (
            <button className="btn btn-primary" onClick={() => setShowCreateIncident(true)}>
              <Plus className="h-4 w-4" />
              Créer un ticket
            </button>
          )}
          {showCreateIncident && (
            <CreateIncidentModal onClose={() => setShowCreateIncident(false)} />
          )}
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
          subtitle={historyData.length ? "Données réelles depuis la base" : "Données simulées (aucune alerte sur la période)"}
          className="lg:col-span-2"
        >
          <div className="mb-3 flex gap-1">
            {["24h", "7d", "30d"].map(r => (
              <button
                key={r}
                onClick={() => setHistoryRange(r)}
                className={`rounded-lg px-3 py-1 text-xs font-medium transition-colors ${
                  historyRange === r
                    ? "bg-brand-600 text-white"
                    : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
          <ResponsiveContainer width="100%" height={230}>
            <AreaChart data={timeSeriesData} margin={{ left: -20, right: 8, top: 8 }}>
              <defs>
                <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#16A34A" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#16A34A" stopOpacity={0} />
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
                stroke="#16A34A"
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
                <Bar dataKey="value" fill="#16A34A" radius={[0, 4, 4, 0]} name="Alertes" />
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
                    <Cell fill="#16A34A" />
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


