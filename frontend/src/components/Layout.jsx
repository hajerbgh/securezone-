import { Outlet, useNavigate, useSearchParams, Link } from "react-router-dom";
import { Search, Bell, ShieldAlert, Bug, AlertTriangle, CheckCircle, X } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import api from "../lib/api";
import Sidebar from "./Sidebar";

const SEV_CONFIG = {
  critical: { color: "text-red-600",    bg: "bg-red-50 border-red-200",    dot: "bg-red-500",    label: "CRITIQUE" },
  high:     { color: "text-orange-600", bg: "bg-orange-50 border-orange-200", dot: "bg-orange-500", label: "HAUTE" },
  medium:   { color: "text-amber-600",  bg: "bg-amber-50 border-amber-200",   dot: "bg-amber-400",  label: "MOYENNE" },
};

const CAT_ICON = {
  brute_force:   <ShieldAlert className="h-4 w-4" />,
  phishing:      <AlertTriangle className="h-4 w-4" />,
  vulnerability: <Bug className="h-4 w-4" />,
};

function timeAgo(dateStr) {
  const diff = Math.floor((Date.now() - new Date(dateStr)) / 1000);
  if (diff < 60)   return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}min`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  return `${Math.floor(diff / 86400)}j`;
}

function NotificationPanel({ onClose }) {
  const navigate = useNavigate();

  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ["notif-alerts"],
    queryFn: () =>
      api.get("/alerts/", { params: { limit: 8, status: "open" } }).then(r =>
        r.data.filter(a => ["critical", "high"].includes(a.severity))
      ),
    refetchInterval: 30000,
  });

  const { data: incidents = [] } = useQuery({
    queryKey: ["notif-incidents"],
    queryFn: () =>
      api.get("/incidents/", { params: { limit: 3 } }).then(r =>
        r.data.filter(i => i.status === "new")
      ),
    refetchInterval: 30000,
  });

  function goTo(path) {
    navigate(path);
    onClose();
  }

  return (
    <div className="absolute right-0 top-11 z-50 w-96 rounded-xl border border-slate-200 bg-white shadow-xl">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
        <div className="flex items-center gap-2">
          <Bell className="h-4 w-4 text-ink-subtle" />
          <span className="text-sm font-semibold text-ink">Notifications</span>
          {alerts.length > 0 && (
            <span className="rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-bold text-white">
              {alerts.length + incidents.length}
            </span>
          )}
        </div>
        <button onClick={onClose} className="text-ink-subtle hover:text-ink">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="max-h-[420px] overflow-y-auto">
        {/* Incidents nouveaux */}
        {incidents.length > 0 && (
          <div>
            <p className="px-4 pt-3 pb-1 text-[10px] font-bold uppercase tracking-widest text-ink-subtle">
              Incidents à traiter
            </p>
            {incidents.map(inc => (
              <button
                key={inc.id}
                onClick={() => goTo("/incidents")}
                className="flex w-full items-start gap-3 border-b border-slate-50 px-4 py-3 text-left hover:bg-slate-50 transition-colors"
              >
                <div className="mt-0.5 flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-red-100">
                  <AlertTriangle className="h-3.5 w-3.5 text-red-600" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-ink">{inc.title}</p>
                  <p className="text-xs text-ink-subtle mt-0.5">
                    Statut: <span className="font-medium text-red-600 capitalize">{inc.status}</span>
                    {" · "}
                    Sévérité: <span className="capitalize">{inc.severity}</span>
                  </p>
                </div>
                <span className="flex-shrink-0 text-[11px] text-ink-subtle">{timeAgo(inc.created_at)}</span>
              </button>
            ))}
          </div>
        )}

        {/* Alertes critiques/hautes */}
        {isLoading ? (
          <div className="px-4 py-6 text-center text-sm text-ink-subtle">Chargement…</div>
        ) : alerts.length === 0 && incidents.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-4 py-8 text-center">
            <CheckCircle className="h-8 w-8 text-green-400" />
            <p className="text-sm font-medium text-ink">Aucune alerte critique ouverte</p>
            <p className="text-xs text-ink-subtle">Le système est sous contrôle</p>
          </div>
        ) : (
          <div>
            {alerts.length > 0 && (
              <p className="px-4 pt-3 pb-1 text-[10px] font-bold uppercase tracking-widest text-ink-subtle">
                Alertes critiques / hautes
              </p>
            )}
            {alerts.map(alert => {
              const sev = SEV_CONFIG[alert.severity] || SEV_CONFIG.high;
              return (
                <button
                  key={alert.id}
                  onClick={() => goTo("/alerts")}
                  className="flex w-full items-start gap-3 border-b border-slate-50 px-4 py-3 text-left hover:bg-slate-50 transition-colors"
                >
                  <div className={`mt-1 h-2 w-2 flex-shrink-0 rounded-full ${sev.dot}`} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-ink">{alert.title}</p>
                    <div className="mt-0.5 flex items-center gap-2 text-xs text-ink-subtle">
                      <span className={`font-semibold ${sev.color}`}>{sev.label}</span>
                      {alert.source_ip && <span>· {alert.source_ip}</span>}
                      {alert.category && (
                        <span className="capitalize">· {alert.category.replace("_", " ")}</span>
                      )}
                    </div>
                  </div>
                  <span className="flex-shrink-0 text-[11px] text-ink-subtle">{timeAgo(alert.created_at)}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="border-t border-slate-100 px-4 py-2.5">
        <button
          onClick={() => goTo("/alerts")}
          className="w-full rounded-lg py-1.5 text-center text-xs font-medium text-brand-600 hover:bg-brand-50 transition-colors"
        >
          Voir toutes les alertes →
        </button>
      </div>
    </div>
  );
}

export default function Layout() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [showNotif, setShowNotif] = useState(false);
  const notifRef = useRef(null);

  useEffect(() => {
    setQuery(searchParams.get("q") || "");
  }, [searchParams]);

  // Ferme le panneau si on clique ailleurs
  useEffect(() => {
    if (!showNotif) return;
    const handler = (e) => {
      if (notifRef.current && !notifRef.current.contains(e.target)) {
        setShowNotif(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showNotif]);

  // Compte les alertes critiques/hautes ouvertes pour le badge
  const { data: openCount = 0 } = useQuery({
    queryKey: ["notif-count"],
    queryFn: () =>
      api.get("/alerts/stats").then(r => {
        const s = r.data;
        return (s.critical || 0) + (s.high || 0);
      }).catch(() => 0),
    refetchInterval: 30000,
  });

  const handleSearch = (e) => {
    const val = e.target.value;
    setQuery(val);
    navigate(val ? `/vulnerabilities?q=${encodeURIComponent(val)}` : "/vulnerabilities");
  };

  return (
    <div className="min-h-screen bg-surface-page">
      <Sidebar />

      <div className="pl-60">
        <header className="sticky top-0 z-10 flex items-center gap-4 border-b border-slate-200 bg-surface/80 px-6 py-3 backdrop-blur">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-subtle" />
            <input
              type="search"
              value={query}
              onChange={handleSearch}
              placeholder="Rechercher une alerte, un asset, une CVE…"
              className="w-full rounded-lg border border-slate-200 bg-surface-page py-2 pl-9 pr-3 text-sm outline-none transition focus:border-brand-400 focus:bg-surface focus:ring-2 focus:ring-brand-100"
            />
          </div>

          {/* Bouton notifications */}
          <div className="relative" ref={notifRef}>
            <button
              onClick={() => setShowNotif(v => !v)}
              className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-ink-muted transition hover:bg-surface-hover"
              aria-label="Notifications"
            >
              <Bell className="h-[18px] w-[18px]" strokeWidth={2} />
              {openCount > 0 && (
                <span className="absolute -right-1 -top-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white">
                  {openCount > 9 ? "9+" : openCount}
                </span>
              )}
            </button>

            {showNotif && (
              <NotificationPanel onClose={() => setShowNotif(false)} />
            )}
          </div>
        </header>

        <main className="p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
