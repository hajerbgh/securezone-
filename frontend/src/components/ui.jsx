import clsx from "clsx";
import { SEVERITY_COLORS, SEVERITY_LABELS } from "../lib/format";

// ── Carte widget générique ────────────────────────────────────
export function Card({ title, subtitle, action, children, className }) {
  return (
    <div className={clsx("card p-5", className)}>
      {(title || action) && (
        <div className="mb-4 flex items-start justify-between">
          <div>
            {title && (
              <h3 className="text-sm font-semibold text-ink">{title}</h3>
            )}
            {subtitle && (
              <p className="mt-0.5 text-xs text-ink-subtle">{subtitle}</p>
            )}
          </div>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

// ── Carte KPI colorée (style inspiration) ─────────────────────
// variant: "neutral" | "critical" | "high" | "medium" | "low"
export function KpiCard({ label, value, hint, variant = "neutral", updated }) {
  const filled = variant !== "neutral";
  const bg = {
    neutral: "bg-surface",
    critical: "bg-sev-critical",
    high: "bg-sev-high",
    medium: "bg-sev-medium",
    low: "bg-sev-low",
  }[variant];

  return (
    <div
      className={clsx(
        "rounded-card p-5 shadow-card border",
        filled ? `${bg} border-transparent text-white` : "bg-surface border-slate-200/60"
      )}
    >
      <div className="flex items-start justify-between">
        <span
          className={clsx(
            "text-sm font-medium",
            filled ? "text-white/90" : "text-ink-muted"
          )}
        >
          {label}
        </span>
        {updated && (
          <span
            className={clsx(
              "text-[11px]",
              filled ? "text-white/60" : "text-ink-subtle"
            )}
          >
            {updated}
          </span>
        )}
      </div>

      {hint && (
        <div
          className={clsx(
            "mt-3 inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium",
            filled ? "bg-white/15 text-white" : "bg-surface-hover text-ink-muted"
          )}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" />
          {hint}
        </div>
      )}

      <div
        className={clsx(
          "tabular mt-3 text-kpi",
          filled ? "text-white" : "text-ink"
        )}
      >
        {value}
      </div>
    </div>
  );
}

// ── Badge de sévérité ─────────────────────────────────────────
export function SeverityBadge({ severity }) {
  const color = SEVERITY_COLORS[severity] || "#64748B";
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium"
      style={{ backgroundColor: `${color}18`, color }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {SEVERITY_LABELS[severity] || severity}
    </span>
  );
}

// ── Badge de statut ───────────────────────────────────────────
export function StatusBadge({ status }) {
  const styles = {
    open: "bg-red-50 text-red-700",
    investigating: "bg-amber-50 text-amber-700",
    resolved: "bg-emerald-50 text-emerald-700",
    false_positive: "bg-slate-100 text-slate-600",
    patched: "bg-emerald-50 text-emerald-700",
    in_remediation: "bg-amber-50 text-amber-700",
    accepted_risk: "bg-slate-100 text-slate-600",
    compliant: "bg-emerald-50 text-emerald-700",
    non_compliant: "bg-red-50 text-red-700",
    completed: "bg-emerald-50 text-emerald-700",
    running: "bg-blue-50 text-blue-700",
    pending: "bg-slate-100 text-slate-600",
    failed: "bg-red-50 text-red-700",
  };
  const labels = {
    open: "Ouverte",
    investigating: "En cours",
    resolved: "Résolue",
    false_positive: "Faux positif",
    patched: "Corrigée",
    in_remediation: "En remédiation",
    accepted_risk: "Risque accepté",
    compliant: "Conforme",
    non_compliant: "Non conforme",
    completed: "Terminé",
    running: "En cours",
    pending: "En attente",
    failed: "Échec",
  };
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium",
        styles[status] || "bg-slate-100 text-slate-600"
      )}
    >
      {labels[status] || status}
    </span>
  );
}

// ── État vide ─────────────────────────────────────────────────
export function EmptyState({ icon: Icon, title, message }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      {Icon && <Icon className="mb-3 h-10 w-10 text-ink-subtle" strokeWidth={1.5} />}
      <p className="text-sm font-medium text-ink">{title}</p>
      {message && <p className="mt-1 text-xs text-ink-subtle">{message}</p>}
    </div>
  );
}

// ── Spinner ───────────────────────────────────────────────────
export function Spinner({ className }) {
  return (
    <div className={clsx("flex items-center justify-center py-12", className)}>
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-slate-200 border-t-brand-600" />
    </div>
  );
}
