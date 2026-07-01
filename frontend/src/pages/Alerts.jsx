import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldAlert, RefreshCw, ChevronDown, ChevronRight,
  Activity, CheckCircle2, Clock, Search, Zap, ShieldX,
} from "lucide-react";
import api from "../lib/api";
import { Card, SeverityBadge, Spinner, EmptyState } from "../components/ui";
import { formatRelativeTime } from "../lib/format";

// ── Couleurs & métadonnées ──────────────────────────────────────
const SEV_BORDER = {
  critical: "#DC2626",
  high:     "#EA580C",
  medium:   "#D97706",
  low:      "#16A34A",
};

const CAT_META = {
  vulnerability:     { label: "Vulnérabilité",     color: "#7C3AED", bg: "#F5F3FF" },
  phishing:          { label: "Phishing",           color: "#0369A1", bg: "#EFF6FF" },
  port_scan:         { label: "Scan de ports",      color: "#2563EB", bg: "#EFF6FF" },
  brute_force:       { label: "Brute Force",        color: "#DC2626", bg: "#FEF2F2" },
  lateral_movement:  { label: "Mouv. latéral",      color: "#D97706", bg: "#FFFBEB" },
  credential_access: { label: "Accès identifiants", color: "#DB2777", bg: "#FDF2F8" },
  sql_injection:     { label: "Injection SQL",      color: "#059669", bg: "#ECFDF5" },
  command_exec:      { label: "Exec. commandes",    color: "#7C3AED", bg: "#F5F3FF" },
  exfiltration:      { label: "Exfiltration",       color: "#DC2626", bg: "#FEF2F2" },
  anomaly:           { label: "Anomalie ML",         color: "#0891B2", bg: "#ECFEFF" },
  compliance:        { label: "Conformité",          color: "#64748B", bg: "#F8FAFC" },
  other:             { label: "Autre",               color: "#64748B", bg: "#F8FAFC" },
};

const STATUS_CLS = {
  open:          "bg-red-100 text-red-700",
  investigating: "bg-amber-100 text-amber-700",
  resolved:      "bg-emerald-100 text-emerald-700",
  false_positive:"bg-slate-100 text-slate-500",
  suppressed:    "bg-slate-100 text-slate-400",
};

const STATUS_LBL = {
  open:          "Ouverte",
  investigating: "En cours",
  resolved:      "Résolue",
  false_positive:"Faux positif",
  suppressed:    "Supprimée",
};

const SEVERITIES    = ["", "critical", "high", "medium", "low"];
const SEV_TAB_LABEL = { "": "Toutes", critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible" };

// ── KPI box ─────────────────────────────────────────────────────
function KpiBox({ label, value, colorCls, icon: Icon }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
      <div className={`rounded-lg p-2 ${colorCls}`}>
        <Icon size={17} className="text-white" />
      </div>
      <div>
        <div className="text-2xl font-bold text-ink leading-none">{value ?? "—"}</div>
        <div className="mt-0.5 text-xs text-ink-muted">{label}</div>
      </div>
    </div>
  );
}

// ── Barre catégorie ──────────────────────────────────────────────
function CatBar({ label, count, max, color }) {
  const pct = max > 0 ? Math.max(4, (count / max) * 100) : 0;
  return (
    <div className="flex items-center gap-3">
      <span className="w-36 shrink-0 truncate text-xs text-ink-muted">{label}</span>
      <div className="flex-1 h-2 rounded-full bg-slate-100">
        <div className="h-2 rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="w-6 text-right text-xs font-semibold text-ink">{count}</span>
    </div>
  );
}

// ── Score visuel ─────────────────────────────────────────────────
function RiskScore({ score }) {
  if (!score || score === 0) return <span className="text-ink-subtle">—</span>;
  const cls = score >= 9 ? "text-red-600 font-bold" : score >= 7 ? "text-orange-600 font-bold" : "text-amber-600";
  return <span className={`text-sm ${cls}`}>{score.toFixed(1)}</span>;
}

// ── Ligne alerte (expandable) ────────────────────────────────────
function AlertRow({ alert, onAction, pending }) {
  const [open, setOpen] = useState(false);
  const sev  = SEV_BORDER[alert.severity]  || "#94A3B8";
  const cat  = CAT_META[alert.category]    || CAT_META.other;
  const busy = pending === alert.id;

  return (
    <>
      <tr
        onClick={() => setOpen((v) => !v)}
        className="group border-b border-slate-100 cursor-pointer hover:bg-slate-50/70 transition-colors"
      >
        {/* Barre couleur sévérité */}
        <td className="w-1 p-0">
          <div style={{ backgroundColor: sev, minHeight: 48, width: 3 }} className="rounded-l" />
        </td>

        {/* Expand icon + sévérité */}
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="flex items-center gap-2">
            {open
              ? <ChevronDown  size={13} className="text-ink-subtle shrink-0" />
              : <ChevronRight size={13} className="text-ink-subtle shrink-0" />
            }
            <SeverityBadge severity={alert.severity} />
          </div>
        </td>

        {/* Titre + catégorie */}
        <td className="px-4 py-3 max-w-xs">
          <p className="font-medium text-ink text-sm truncate leading-tight">{alert.title}</p>
          <span
            className="mt-0.5 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium"
            style={{ backgroundColor: cat.bg, color: cat.color }}
          >
            {cat.label}
          </span>
        </td>

        {/* IPs */}
        <td className="px-4 py-3 font-mono text-xs text-ink-muted">
          {alert.source_ip ? (
            <>{alert.source_ip}{alert.source_port ? <span className="text-ink-subtle">:{alert.source_port}</span> : null}</>
          ) : "—"}
        </td>
        <td className="px-4 py-3 font-mono text-xs text-ink-muted">
          {alert.destination_ip ? (
            <>{alert.destination_ip}{alert.destination_port ? <span className="text-ink-subtle">:{alert.destination_port}</span> : null}</>
          ) : "—"}
        </td>

        {/* MITRE */}
        <td className="px-4 py-3">
          {alert.mitre_technique_id ? (
            <span className="rounded bg-brand-50 px-1.5 py-0.5 font-mono text-xs text-brand-700">
              {alert.mitre_technique_id}
            </span>
          ) : "—"}
        </td>

        {/* Score */}
        <td className="px-4 py-3 text-center">
          <RiskScore score={alert.risk_score} />
        </td>

        {/* Statut */}
        <td className="px-4 py-3">
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_CLS[alert.status] || ""}`}>
            {STATUS_LBL[alert.status] || alert.status}
          </span>
        </td>

        {/* Date + event count */}
        <td className="px-4 py-3 text-xs text-ink-subtle whitespace-nowrap">
          {alert.event_count > 1 && (
            <span className="mr-1.5 rounded-full bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-ink-muted">
              ×{alert.event_count}
            </span>
          )}
          {formatRelativeTime(alert.created_at)}
        </td>
      </tr>

      {/* Panel détail ──────────────────────────────────────── */}
      {open && (
        <tr className="bg-slate-50/80 border-b border-slate-200">
          <td className="w-1 p-0">
            <div style={{ backgroundColor: sev, minHeight: "100%", width: 3 }} />
          </td>
          <td colSpan={8} className="px-6 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

              {/* Détails */}
              <div className="space-y-3">
                {alert.description && (
                  <div>
                    <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-subtle">Description</p>
                    <p className="text-sm text-ink leading-relaxed whitespace-pre-wrap">{alert.description}</p>
                  </div>
                )}
                <div className="flex flex-wrap gap-5 text-xs text-ink-muted">
                  {alert.first_seen && (
                    <span>
                      Première détection :{" "}
                      <span className="text-ink">{new Date(alert.first_seen).toLocaleString("fr-FR")}</span>
                    </span>
                  )}
                  {alert.last_seen && (
                    <span>
                      Dernière :{" "}
                      <span className="text-ink">{new Date(alert.last_seen).toLocaleString("fr-FR")}</span>
                    </span>
                  )}
                  {alert.event_count > 1 && (
                    <span>
                      Occurrences : <span className="text-ink font-semibold">{alert.event_count}</span>
                    </span>
                  )}
                </div>
                {alert.mitre_technique_id && (
                  <div className="text-xs">
                    <span className="text-ink-muted">MITRE ATT&amp;CK : </span>
                    <span className="font-medium text-brand-700">
                      {alert.mitre_technique_id}
                      {alert.mitre_technique_name ? ` — ${alert.mitre_technique_name}` : ""}
                    </span>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-subtle">Actions</p>
                <div className="flex flex-wrap gap-2">
                  {alert.status === "open" && (
                    <button
                      disabled={busy}
                      onClick={(e) => { e.stopPropagation(); onAction(alert.id, "investigating"); }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-amber-300 bg-amber-50
                                 px-3 py-1.5 text-xs font-medium text-amber-700 transition
                                 hover:bg-amber-100 disabled:opacity-50"
                    >
                      <Activity size={13} />
                      {busy ? "En cours…" : "Investiguer"}
                    </button>
                  )}
                  {alert.status === "investigating" && (
                    <span className="inline-flex items-center gap-1 rounded-lg bg-amber-50 px-3 py-1.5 text-xs text-amber-700 border border-amber-200">
                      <Activity size={13} /> Investigation en cours
                    </span>
                  )}
                  {!["resolved", "false_positive"].includes(alert.status) && (
                    <button
                      disabled={busy}
                      onClick={(e) => { e.stopPropagation(); onAction(alert.id, "resolved"); }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-300 bg-emerald-50
                                 px-3 py-1.5 text-xs font-medium text-emerald-700 transition
                                 hover:bg-emerald-100 disabled:opacity-50"
                    >
                      <CheckCircle2 size={13} />
                      {busy ? "En cours…" : "Marquer résolue"}
                    </button>
                  )}
                  {alert.status === "open" && (
                    <button
                      disabled={busy}
                      onClick={(e) => { e.stopPropagation(); onAction(alert.id, "false_positive"); }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-slate-50
                                 px-3 py-1.5 text-xs font-medium text-slate-600 transition
                                 hover:bg-slate-100 disabled:opacity-50"
                    >
                      Faux positif
                    </button>
                  )}
                  {["resolved", "false_positive"].includes(alert.status) && (
                    <span className="inline-flex items-center gap-1 rounded-lg bg-slate-50 px-3 py-1.5 text-xs text-slate-500 border border-slate-200">
                      <CheckCircle2 size={13} /> Traitée
                    </span>
                  )}
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Page principale ──────────────────────────────────────────────
export default function Alerts() {
  const [severity, setSeverity] = useState("");
  const [status,   setStatus]   = useState("");
  const [category, setCategory] = useState("");
  const [search,   setSearch]   = useState("");
  const [lastRef,  setLastRef]  = useState(new Date());
  const [pending,  setPending]  = useState(null);
  const qc = useQueryClient();

  // ── Stats ──────────────────────────────────────────────────────
  const { data: stats } = useQuery({
    queryKey: ["alerts-stats"],
    queryFn:  async () => { const { data } = await api.get("/alerts/stats"); return data; },
    refetchInterval: 30000,
  });

  // ── Alert list ─────────────────────────────────────────────────
  const { data: alerts, isLoading, refetch } = useQuery({
    queryKey: ["alerts", severity, status, category],
    queryFn:  async () => {
      const params = {};
      if (severity) params.severity = severity;
      if (status)   params.status   = status;
      if (category) params.category = category;
      const { data } = await api.get("/alerts/", { params });
      return data;
    },
    refetchInterval: 15000,
  });

  useEffect(() => {
    if (alerts) setLastRef(new Date());
  }, [alerts]);

  // ── Mutation statut ────────────────────────────────────────────
  const updateStatus = useMutation({
    mutationFn: ({ id, status: s }) => api.patch(`/alerts/${id}`, { status: s }),
    onMutate:   ({ id }) => setPending(id),
    onSettled:  () => {
      setPending(null);
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["alerts-stats"] });
    },
  });

  const handleRefresh = () => {
    refetch();
    qc.invalidateQueries({ queryKey: ["alerts-stats"] });
  };

  // ── Filtre client (search) ─────────────────────────────────────
  const filtered = (alerts || []).filter((a) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      a.title?.toLowerCase().includes(q) ||
      a.source_ip?.includes(q) ||
      a.destination_ip?.includes(q) ||
      a.mitre_technique_id?.toLowerCase().includes(q) ||
      a.category?.includes(q)
    );
  });

  // ── Barres par catégorie ───────────────────────────────────────
  const catEntries = Object.entries(stats?.by_category || {})
    .sort(([, a], [, b]) => b - a)
    .slice(0, 7);
  const catMax = catEntries[0]?.[1] || 1;

  // ── Critiques récents ─────────────────────────────────────────
  const criticalFeed = (alerts || [])
    .filter((a) => a.severity === "critical")
    .slice(0, 5);

  const resolvedCount = stats?.by_status?.resolved ?? 0;

  return (
    <div className="space-y-5">

      {/* ── En-tête ───────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-ink">
            <ShieldAlert size={21} className="text-red-600" />
            Alertes SIEM
          </h1>
          <p className="mt-0.5 text-sm text-ink-muted">
            Centre opérationnel de sécurité — détection et corrélation en temps réel
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <span className="text-xs text-ink-subtle hidden sm:block">
            Mis à jour {formatRelativeTime(lastRef.toISOString())}
          </span>
          <button
            onClick={handleRefresh}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200
                       bg-white px-3 py-1.5 text-sm text-ink-muted hover:bg-slate-50 transition"
          >
            <RefreshCw size={14} />
            Rafraîchir
          </button>
        </div>
      </div>

      {/* ── KPI row ───────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <KpiBox label="Total alertes"       value={stats?.total}    colorCls="bg-slate-600"   icon={ShieldAlert}  />
        <KpiBox label="Critiques"           value={stats?.critical} colorCls="bg-red-600"     icon={ShieldX}      />
        <KpiBox label="Élevées"             value={stats?.high}     colorCls="bg-orange-500"  icon={Zap}          />
        <KpiBox label="Ouvertes"            value={stats?.open}     colorCls="bg-brand-600"   icon={Clock}        />
        <KpiBox label="Résolues"            value={resolvedCount}   colorCls="bg-emerald-600" icon={CheckCircle2} />
      </div>

      {/* ── Catégories + flux critique ────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        {/* Répartition par catégorie */}
        <Card title="Répartition par catégorie">
          {catEntries.length === 0 ? (
            <p className="py-4 text-center text-xs text-ink-subtle">Aucune donnée disponible</p>
          ) : (
            <div className="mt-1 space-y-3">
              {catEntries.map(([cat, count]) => {
                const m = CAT_META[cat] || CAT_META.other;
                return <CatBar key={cat} label={m.label} count={count} max={catMax} color={m.color} />;
              })}
            </div>
          )}
        </Card>

        {/* Flux critiques */}
        <Card title="Alertes critiques récentes">
          {criticalFeed.length === 0 ? (
            <p className="py-4 text-center text-xs text-ink-subtle">Aucune alerte critique active</p>
          ) : (
            <div className="mt-1 space-y-2">
              {criticalFeed.map((a) => (
                <div key={a.id} className="flex items-start gap-3 rounded-lg border border-red-100 bg-red-50 px-3 py-2">
                  <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-red-500 animate-pulse" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-red-900">{a.title}</p>
                    <p className="mt-0.5 text-xs text-red-700">
                      {a.destination_ip || a.source_ip || "IP inconnue"}
                      {" · "}
                      {formatRelativeTime(a.created_at)}
                    </p>
                  </div>
                  <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_CLS[a.status] || ""}`}>
                    {STATUS_LBL[a.status] || a.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* ── Filtres ───────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-3 items-center">
        {/* Sévérité tabs */}
        <div className="flex gap-1 rounded-lg border border-slate-200 bg-surface p-1">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition ${
                severity === s
                  ? "bg-brand-600 text-white shadow-sm"
                  : "text-ink-muted hover:bg-surface-hover"
              }`}
            >
              {SEV_TAB_LABEL[s]}
            </button>
          ))}
        </div>

        {/* Statut */}
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-lg border border-slate-200 bg-surface px-3 py-1.5 text-xs outline-none focus:border-brand-400"
        >
          <option value="">Tous les statuts</option>
          <option value="open">Ouvertes</option>
          <option value="investigating">En cours</option>
          <option value="resolved">Résolues</option>
          <option value="false_positive">Faux positifs</option>
        </select>

        {/* Catégorie */}
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-lg border border-slate-200 bg-surface px-3 py-1.5 text-xs outline-none focus:border-brand-400"
        >
          <option value="">Toutes catégories</option>
          {Object.entries(CAT_META).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>

        {/* Recherche */}
        <div className="relative ml-auto">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-subtle" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="IP, titre, MITRE…"
            className="w-56 rounded-lg border border-slate-200 bg-surface pl-8 pr-3 py-1.5 text-xs
                       outline-none focus:border-brand-400 placeholder:text-ink-subtle"
          />
        </div>
      </div>

      {/* Compteur résultats */}
      {(search || severity || status || category) && (
        <p className="text-xs text-ink-muted">
          {filtered.length} alerte{filtered.length !== 1 ? "s" : ""} affichée{filtered.length !== 1 ? "s" : ""}
          {search && <> pour &ldquo;<span className="font-medium text-ink">{search}</span>&rdquo;</>}
        </p>
      )}

      {/* ── Table ─────────────────────────────────────────────── */}
      <Card className="overflow-hidden p-0">
        {isLoading ? (
          <Spinner />
        ) : !filtered.length ? (
          <EmptyState
            icon={ShieldAlert}
            title="Aucune alerte"
            message="Aucune alerte ne correspond aux filtres sélectionnés."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-left text-xs font-semibold text-ink-subtle">
                  <th className="w-1 p-0" />
                  <th className="px-4 py-3">Sévérité</th>
                  <th className="px-4 py-3">Alerte / Catégorie</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Destination</th>
                  <th className="px-4 py-3">MITRE</th>
                  <th className="px-4 py-3 text-center">Score</th>
                  <th className="px-4 py-3">Statut</th>
                  <th className="px-4 py-3">Détectée</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => (
                  <AlertRow
                    key={a.id}
                    alert={a}
                    pending={pending}
                    onAction={(id, newStatus) => updateStatus.mutate({ id, status: newStatus })}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
