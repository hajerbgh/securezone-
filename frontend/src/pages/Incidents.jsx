import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Siren, Clock, Shield, ChevronRight, X, CheckCircle2,
  AlertTriangle, PlayCircle, SkipForward, ThumbsUp,
  Terminal, User2, Plus, RefreshCw, Loader2, Eye,
} from "lucide-react";
import api from "../lib/api";
import { Card, KpiCard, SeverityBadge, Spinner, EmptyState } from "../components/ui";
import { formatNumber, formatRelativeTime } from "../lib/format";

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

const STATUS_LABELS = {
  new: "Nouveau",
  assigned: "Assigné",
  investigating: "Investigation",
  containment: "Containment",
  eradication: "Éradication",
  recovery: "Rétablissement",
  closed: "Clôturé",
};

const STATUS_COLORS = {
  new: "bg-slate-100 text-slate-700",
  assigned: "bg-blue-50 text-blue-700",
  investigating: "bg-amber-50 text-amber-700",
  containment: "bg-orange-50 text-orange-700",
  eradication: "bg-red-50 text-red-700",
  recovery: "bg-teal-50 text-teal-700",
  closed: "bg-green-50 text-green-600",
};

const ACTION_STATUS_ICONS = {
  pending: <Clock className="h-4 w-4 text-slate-400" />,
  approved: <ThumbsUp className="h-4 w-4 text-blue-500" />,
  executing: <Loader2 className="h-4 w-4 animate-spin text-amber-500" />,
  done: <CheckCircle2 className="h-4 w-4 text-green-500" />,
  skipped: <SkipForward className="h-4 w-4 text-slate-400" />,
  failed: <AlertTriangle className="h-4 w-4 text-red-500" />,
};

const ACTION_TYPE_ICONS = {
  trigger_scan: <Shield className="h-3.5 w-3.5" />,
  run_compliance: <CheckCircle2 className="h-3.5 w-3.5" />,
  log_ioc: <Eye className="h-3.5 w-3.5" />,
  send_notification: <Siren className="h-3.5 w-3.5" />,
  block_ip: <Terminal className="h-3.5 w-3.5 text-red-500" />,
  squid_blacklist: <Terminal className="h-3.5 w-3.5 text-orange-500" />,
  manual_task: <User2 className="h-3.5 w-3.5 text-blue-500" />,
};

function formatMinutes(min) {
  if (min == null) return "—";
  if (min < 60) return `${min}min`;
  return `${Math.floor(min / 60)}h ${min % 60}min`;
}

function StatusBadgeIR({ status }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_COLORS[status] || "bg-slate-100 text-slate-600"}`}>
      {STATUS_LABELS[status] || status}
    </span>
  );
}

// ─────────────────────────────────────────────
// Action Row Component
// ─────────────────────────────────────────────

function ActionRow({ action, onApprove, onExecute, onSkip, busy }) {
  const [showResult, setShowResult] = useState(false);
  const isDone = action.status === "done" || action.status === "skipped";
  const canApprove = action.requires_approval && action.status === "pending";
  const canExecute =
    (!action.requires_approval && action.status === "pending") ||
    action.status === "approved";

  let resultObj = null;
  if (action.execution_result) {
    try { resultObj = JSON.parse(action.execution_result); } catch { resultObj = null; }
  }
  const isManualCmd = resultObj?.type === "manual_command";

  return (
    <div className={`rounded-lg border px-4 py-3 transition-colors ${
      isDone ? "border-slate-100 bg-slate-50 opacity-70" : "border-slate-200 bg-white"
    }`}>
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-slate-200 text-xs font-bold text-ink-muted">
          {action.step_order}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">{ACTION_TYPE_ICONS[action.action_type]}</span>
            <p className="text-sm font-medium text-ink">{action.title}</p>
            {action.requires_approval && (
              <span className="rounded bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-700">
                MANUEL
              </span>
            )}
          </div>
          {action.description && (
            <p className="mt-0.5 text-xs text-ink-muted">{action.description}</p>
          )}

          {/* Résultat d'exécution */}
          {action.execution_result && (
            <div className="mt-2">
              {isManualCmd ? (
                <div className="rounded-lg bg-slate-900 p-3">
                  <p className="mb-1 text-xs text-slate-400">{resultObj.message}</p>
                  <p className="mb-1 text-xs font-medium text-slate-300">
                    Cible : {resultObj.target_host}
                  </p>
                  {resultObj.commands?.map((cmd, i) => (
                    <code key={i} className="block text-xs text-green-400 font-mono mt-1">
                      $ {cmd}
                    </code>
                  ))}
                  {resultObj.verify && (
                    <p className="mt-2 text-xs text-slate-500">
                      Vérification : <code className="text-yellow-400">{resultObj.verify}</code>
                    </p>
                  )}
                </div>
              ) : (
                <button
                  onClick={() => setShowResult((s) => !s)}
                  className="text-xs text-indigo-500 hover:underline"
                >
                  {showResult ? "Masquer résultat" : "Voir résultat"}
                </button>
              )}
              {showResult && !isManualCmd && (
                <pre className="mt-1 max-h-32 overflow-auto rounded bg-slate-100 p-2 text-xs text-slate-700">
                  {action.execution_result}
                </pre>
              )}
            </div>
          )}
        </div>

        {/* Boutons d'action */}
        <div className="flex shrink-0 items-center gap-1.5">
          {ACTION_STATUS_ICONS[action.status]}

          {canApprove && (
            <button
              onClick={() => onApprove(action.id)}
              disabled={busy}
              className="flex items-center gap-1 rounded-lg border border-blue-200 bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-700 hover:bg-blue-100 disabled:opacity-50"
            >
              <ThumbsUp className="h-3 w-3" /> Approuver
            </button>
          )}
          {canExecute && (
            <button
              onClick={() => onExecute(action.id)}
              disabled={busy}
              className="flex items-center gap-1 rounded-lg border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
            >
              <PlayCircle className="h-3 w-3" /> Exécuter
            </button>
          )}
          {!isDone && action.status !== "executing" && (
            <button
              onClick={() => onSkip(action.id)}
              disabled={busy}
              className="rounded p-1 text-slate-400 hover:text-slate-600 disabled:opacity-50"
              title="Ignorer cette étape"
            >
              <SkipForward className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Incident Detail Panel
// ─────────────────────────────────────────────

const STATUS_FLOW = [
  "new", "assigned", "investigating", "containment", "eradication", "recovery", "closed",
];

function IncidentDetail({ incidentId, onClose }) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => api.get(`/incidents/${incidentId}`).then((r) => r.data),
    refetchInterval: 5000,
  });

  async function mutate(fn) {
    setBusy(true);
    try {
      await fn();
      qc.invalidateQueries({ queryKey: ["incident", incidentId] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
    } finally {
      setBusy(false);
    }
  }

  const approve = (id) => mutate(() => api.post(`/incidents/actions/${id}/approve`));
  const execute = (id) => mutate(() => api.post(`/incidents/actions/${id}/execute`));
  const skip = (id) => mutate(() => api.post(`/incidents/actions/${id}/skip`));
  const changeStatus = (status) => mutate(() =>
    api.patch(`/incidents/${incidentId}/status`, { status })
  );
  const addNote = () => {
    if (!note.trim()) return;
    mutate(() => api.post(`/incidents/${incidentId}/note`, { note })).then(() => setNote(""));
  };

  if (isLoading) return (
    <div className="flex h-full items-center justify-center"><Spinner /></div>
  );
  if (!incident) return null;

  const currentIdx = STATUS_FLOW.indexOf(incident.status);
  const nextStatus = STATUS_FLOW[currentIdx + 1];

  const donePct = incident.playbook_actions?.length
    ? Math.round(
        (incident.playbook_actions.filter((a) => ["done", "skipped"].includes(a.status)).length /
          incident.playbook_actions.length) * 100
      )
    : 0;

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 border-b border-slate-200 p-5">
        <div>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadgeIR status={incident.status} />
            <span className="text-xs text-ink-subtle">#{incident.id}</span>
          </div>
          <h2 className="mt-2 text-base font-semibold text-ink leading-snug">{incident.title}</h2>
          <p className="mt-0.5 text-xs text-ink-muted">
            Détecté {formatRelativeTime(incident.detected_at || incident.created_at)}
            {incident.mttr_minutes && ` · MTTR : ${formatMinutes(incident.mttr_minutes)}`}
          </p>
        </div>
        <button onClick={onClose} className="shrink-0 rounded p-1 hover:bg-slate-100">
          <X className="h-4 w-4 text-ink-muted" />
        </button>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto p-5">
        {/* IOCs */}
        {incident.ioc_list?.length > 0 && (
          <div>
            <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink-subtle">
              IOCs
            </p>
            <div className="flex flex-wrap gap-1.5">
              {incident.ioc_list.map((ioc, i) => (
                <code key={i} className="rounded bg-red-50 px-2 py-0.5 text-xs font-mono text-red-700">
                  {ioc}
                </code>
              ))}
            </div>
          </div>
        )}

        {/* Playbook progress */}
        {incident.playbook_actions?.length > 0 && (
          <div>
            <div className="mb-2 flex items-center justify-between">
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-subtle">
                Playbook {incident.playbook_name && `— ${incident.playbook_name}`}
              </p>
              <span className="text-xs font-medium text-indigo-600">{donePct}% complété</span>
            </div>
            <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-slate-200">
              <div
                className="h-full rounded-full bg-indigo-500 transition-all"
                style={{ width: `${donePct}%` }}
              />
            </div>
            <div className="space-y-2">
              {incident.playbook_actions.map((action) => (
                <ActionRow
                  key={action.id}
                  action={action}
                  onApprove={approve}
                  onExecute={execute}
                  onSkip={skip}
                  busy={busy}
                />
              ))}
            </div>
          </div>
        )}

        {/* Description / Notes */}
        {incident.description && (
          <div>
            <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink-subtle">
              Notes
            </p>
            <pre className="whitespace-pre-wrap rounded-lg bg-slate-50 p-3 text-xs text-slate-700 leading-relaxed">
              {incident.description}
            </pre>
          </div>
        )}

        {/* Ajouter une note */}
        <div className="flex gap-2">
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addNote()}
            placeholder="Ajouter une note…"
            className="flex-1 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm focus:border-indigo-400 focus:outline-none"
          />
          <button
            onClick={addNote}
            disabled={!note.trim() || busy}
            className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-40"
          >
            Ajouter
          </button>
        </div>
      </div>

      {/* Footer — Status workflow */}
      <div className="border-t border-slate-200 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-ink-muted">
            {incident.mitre_techniques?.map((t) => (
              <code key={t} className="rounded bg-slate-100 px-1.5 py-0.5 text-ink-subtle">{t}</code>
            ))}
          </div>
          {nextStatus && (
            <button
              onClick={() => changeStatus(nextStatus)}
              disabled={busy}
              className="flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
            >
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ChevronRight className="h-3.5 w-3.5" />}
              Passer à : {STATUS_LABELS[nextStatus]}
            </button>
          )}
          {incident.status === "closed" && (
            <span className="text-xs font-medium text-green-600">
              Incident clôturé
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────

export default function Incidents() {
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState(null);
  const [filterStatus, setFilterStatus] = useState("");

  const { data: stats } = useQuery({
    queryKey: ["incident-stats"],
    queryFn: () => api.get("/incidents/stats").then((r) => r.data),
    refetchInterval: 30000,
  });

  const { data: incidents, isLoading } = useQuery({
    queryKey: ["incidents", filterStatus],
    queryFn: () => api.get("/incidents/", { params: { status: filterStatus || undefined } }).then((r) => r.data),
    refetchInterval: 15000,
  });

  const list = incidents || [];

  return (
    <div className="flex h-full gap-5">
      {/* Left: list */}
      <div className="flex min-w-0 flex-1 flex-col space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-ink">Réponse aux incidents</h1>
            <p className="mt-0.5 text-sm text-ink-muted">
              Case management · Playbooks · SOAR
            </p>
          </div>
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ["incidents"] })}
            className="btn btn-ghost"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>

        {/* KPIs */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <KpiCard
            label="Incidents ouverts"
            value={formatNumber(stats?.open || 0)}
            variant="neutral"
          />
          <KpiCard
            label="Critiques"
            value={formatNumber(stats?.critical_open || 0)}
            variant="critical"
          />
          <KpiCard
            label="MTTD moyen"
            value={formatMinutes(stats?.mttd_minutes)}
            hint="Temps de détection"
            variant="medium"
          />
          <KpiCard
            label="MTTR moyen"
            value={formatMinutes(stats?.mttr_minutes)}
            hint="Temps de réponse"
            variant="low"
          />
        </div>

        {/* Filter */}
        <div className="flex gap-2">
          {["", "new", "investigating", "containment", "closed"].map((s) => (
            <button
              key={s}
              onClick={() => setFilterStatus(s)}
              className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                filterStatus === s
                  ? "bg-indigo-600 text-white"
                  : "bg-slate-100 text-ink-muted hover:bg-slate-200"
              }`}
            >
              {s === "" ? "Tous" : STATUS_LABELS[s]}
            </button>
          ))}
        </div>

        {/* Incident list */}
        <Card className="overflow-hidden p-0">
          {isLoading ? (
            <Spinner />
          ) : !list.length ? (
            <EmptyState
              icon={Siren}
              title="Aucun incident"
              message="Les incidents critiques/hauts sont créés automatiquement par le SIEM."
            />
          ) : (
            <div className="divide-y divide-slate-100">
              {list.map((inc) => (
                <button
                  key={inc.id}
                  onClick={() => setSelectedId(inc.id === selectedId ? null : inc.id)}
                  className={`flex w-full items-center gap-4 px-5 py-3.5 text-left transition hover:bg-slate-50 ${
                    selectedId === inc.id ? "bg-indigo-50" : ""
                  }`}
                >
                  <SeverityBadge severity={inc.severity} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-ink">{inc.title}</p>
                    <div className="mt-0.5 flex items-center gap-2 text-xs text-ink-muted">
                      <Clock className="h-3 w-3" />
                      {formatRelativeTime(inc.detected_at || inc.created_at)}
                      {inc.ioc_list?.length > 0 && (
                        <span className="text-red-500">{inc.ioc_list.length} IOC(s)</span>
                      )}
                    </div>
                  </div>
                  <StatusBadgeIR status={inc.status} />
                  <ChevronRight className={`h-4 w-4 shrink-0 text-slate-300 transition-transform ${
                    selectedId === inc.id ? "rotate-90" : ""
                  }`} />
                </button>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Right: detail panel */}
      {selectedId && (
        <div className="w-[480px] shrink-0 rounded-card border border-slate-200 bg-white shadow-sm">
          <IncidentDetail
            incidentId={selectedId}
            onClose={() => setSelectedId(null)}
          />
        </div>
      )}
    </div>
  );
}
