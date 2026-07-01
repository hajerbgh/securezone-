import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ScanSearch, Play, X, CheckCircle, AlertTriangle, Loader2, ChevronDown } from "lucide-react";
import api from "../lib/api";
import { Card, KpiCard, SeverityBadge, StatusBadge, Spinner, EmptyState } from "../components/ui";
import { formatNumber } from "../lib/format";

// ── Modal de lancement de scan ────────────────────────────────
function ScanModal({ onClose, onStarted }) {
  const [ipRanges, setIpRanges] = useState("192.168.1.0/24");
  const [excludeIps, setExcludeIps] = useState("");
  const [portRange, setPortRange] = useState("");
  const [scannerType, setScannerType] = useState("full");
  const [error, setError] = useState("");

  const mutation = useMutation({
    mutationFn: (payload) => api.post("/scans/", payload),
    onSuccess: (res) => {
      onStarted(res.data);
      onClose();
    },
    onError: (err) => {
      setError(err.response?.data?.detail || "Erreur lors du lancement du scan");
    },
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    setError("");

    const ranges = ipRanges
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);

    if (!ranges.length) {
      setError("Entrez au moins une plage IP");
      return;
    }

    const payload = {
      name: `Scan manuel — ${ranges.join(", ")}`,
      ip_ranges: ranges,
      scanner_type: scannerType,
      is_scheduled: false,
      exclude_ips: excludeIps
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean),
      port_range: portRange.trim() || null,
    };

    mutation.mutate(payload);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="relative w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between mb-5">
          <div>
            <h2 className="text-base font-semibold text-ink">Lancer un scan</h2>
            <p className="mt-0.5 text-xs text-ink-muted">
              Nmap + OpenVAS — les résultats seront stockés automatiquement
            </p>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-ink-subtle hover:bg-surface-hover transition"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* IP ranges */}
          <div>
            <label className="block text-xs font-medium text-ink mb-1.5">
              Cibles <span className="text-red-500">*</span>
            </label>
            <textarea
              rows={3}
              value={ipRanges}
              onChange={(e) => setIpRanges(e.target.value)}
              placeholder={"192.168.1.0/24\n10.0.0.0/16\n172.16.0.1"}
              className="w-full rounded-lg border border-slate-200 bg-surface px-3 py-2 text-sm font-mono text-ink placeholder:text-ink-subtle focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 resize-none"
            />
            <p className="mt-1 text-[11px] text-ink-subtle">
              Une IP/plage CIDR par ligne ou séparées par des virgules
            </p>
          </div>

          {/* Scanner type */}
          <div>
            <label className="block text-xs font-medium text-ink mb-1.5">
              Type de scan
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { value: "nmap", label: "Nmap", desc: "Ports & services" },
                { value: "openvas", label: "OpenVAS", desc: "CVEs uniquement" },
                { value: "full", label: "Complet", desc: "Nmap + OpenVAS" },
              ].map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setScannerType(opt.value)}
                  className={`rounded-lg border p-2.5 text-left transition ${
                    scannerType === opt.value
                      ? "border-brand-500 bg-brand-50 text-brand-700"
                      : "border-slate-200 hover:border-slate-300 hover:bg-surface-hover"
                  }`}
                >
                  <div className="text-xs font-semibold">{opt.label}</div>
                  <div className="text-[11px] text-ink-muted mt-0.5">{opt.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Options avancées (collapsibles) */}
          <details className="group">
            <summary className="flex cursor-pointer items-center gap-1.5 text-xs font-medium text-ink-muted select-none">
              <ChevronDown className="h-3.5 w-3.5 transition-transform group-open:rotate-180" />
              Options avancées
            </summary>
            <div className="mt-3 space-y-3 pl-5">
              {/* Exclusions */}
              <div>
                <label className="block text-xs font-medium text-ink mb-1.5">
                  IPs à exclure
                </label>
                <input
                  type="text"
                  value={excludeIps}
                  onChange={(e) => setExcludeIps(e.target.value)}
                  placeholder="192.168.1.1, 10.0.0.1"
                  className="w-full rounded-lg border border-slate-200 bg-surface px-3 py-2 text-sm font-mono text-ink placeholder:text-ink-subtle focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
                />
              </div>
              {/* Ports */}
              <div>
                <label className="block text-xs font-medium text-ink mb-1.5">
                  Plage de ports
                </label>
                <input
                  type="text"
                  value={portRange}
                  onChange={(e) => setPortRange(e.target.value)}
                  placeholder="22,80,443,3389  ou  1-1000  (vide = tous)"
                  className="w-full rounded-lg border border-slate-200 bg-surface px-3 py-2 text-sm font-mono text-ink placeholder:text-ink-subtle focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
                />
              </div>
            </div>
          </details>

          {error && (
            <div className="flex items-center gap-2 rounded-lg bg-red-50 border border-red-200 px-3 py-2.5 text-xs text-red-700">
              <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose} className="btn btn-ghost">
              Annuler
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="btn btn-primary"
            >
              {mutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Lancement…
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Lancer le scan
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Barre de progression du scan en cours ─────────────────────
function ScanProgress({ scanJob, onDone }) {
  const queryClient = useQueryClient();

  const { data: job } = useQuery({
    queryKey: ["scan-job", scanJob.id],
    queryFn: async () => (await api.get(`/scans/${scanJob.id}`)).data,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" || status === "pending" ? 2000 : false;
    },
  });

  const currentJob = job || scanJob;
  const isDone = currentJob.status === "completed" || currentJob.status === "failed";

  useEffect(() => {
    if (currentJob.status === "completed") {
      // Rafraîchir la liste des vulnérabilités et les stats
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["vulns"] });
        queryClient.invalidateQueries({ queryKey: ["vuln-stats"] });
      }, 500);
    }
  }, [currentJob.status, queryClient]);

  const statusColors = {
    pending:   "text-slate-500",
    running:   "text-blue-600",
    completed: "text-emerald-600",
    failed:    "text-red-600",
  };

  const statusLabels = {
    pending:   "En attente…",
    running:   "Scan en cours…",
    completed: "Scan terminé",
    failed:    "Échec du scan",
  };

  return (
    <div className="rounded-xl border border-slate-200 bg-surface p-4 shadow-sm">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          {currentJob.status === "running" || currentJob.status === "pending" ? (
            <Loader2 className="h-4 w-4 animate-spin text-blue-600" />
          ) : currentJob.status === "completed" ? (
            <CheckCircle className="h-4 w-4 text-emerald-600" />
          ) : (
            <AlertTriangle className="h-4 w-4 text-red-600" />
          )}
          <span className={`text-sm font-medium ${statusColors[currentJob.status] || "text-ink"}`}>
            {statusLabels[currentJob.status] || currentJob.status}
          </span>
        </div>
        {isDone && (
          <button
            onClick={onDone}
            className="text-xs text-ink-subtle hover:text-ink transition"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Barre de progression */}
      <div className="h-1.5 w-full rounded-full bg-slate-100 overflow-hidden mb-3">
        <div
          className={`h-full rounded-full transition-all duration-700 ${
            currentJob.status === "failed"
              ? "bg-red-500"
              : currentJob.status === "completed"
              ? "bg-emerald-500"
              : "bg-blue-500"
          }`}
          style={{ width: `${currentJob.progress_percent || 0}%` }}
        />
      </div>

      <div className="flex items-center justify-between text-xs text-ink-muted">
        <span className="font-mono">
          {currentJob.ip_ranges?.join(", ")}
        </span>
        {isDone && currentJob.status === "completed" && (
          <span className="font-medium text-emerald-700">
            {currentJob.vulnerabilities_found} CVE(s) trouvée(s) sur {currentJob.assets_scanned} asset(s)
          </span>
        )}
        {!isDone && (
          <span>{currentJob.progress_percent || 0}%</span>
        )}
      </div>

      {currentJob.error_message && (
        <p className="mt-2 text-xs text-red-600 bg-red-50 rounded px-2 py-1.5">
          {currentJob.error_message}
        </p>
      )}
    </div>
  );
}

// ── Page principale ───────────────────────────────────────────
export default function Vulnerabilities() {
  const [severity, setSeverity] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [activeScan, setActiveScan] = useState(null);
  const [searchParams] = useSearchParams();
  const searchQuery = searchParams.get("q") || "";

  const { data: stats } = useQuery({
    queryKey: ["vuln-stats"],
    queryFn: async () => (await api.get("/vulnerabilities/stats")).data,
  });

  const { data: vulns, isLoading, isError, error } = useQuery({
    queryKey: ["vulns", severity],
    queryFn: async () => {
      const params = severity ? { severity } : {};
      return (await api.get("/vulnerabilities/", { params })).data;
    },
  });

  // Filtre client-side par la recherche globale (CVE, titre, IP)
  const q = searchQuery.toLowerCase();
  const filteredVulns = vulns?.filter((v) => {
    if (!q) return true;
    return (
      v.cve_id?.toLowerCase().includes(q) ||
      v.title?.toLowerCase().includes(q) ||
      v.asset_ip?.toLowerCase().includes(q) ||
      v.asset_hostname?.toLowerCase().includes(q) ||
      v.affected_service?.toLowerCase().includes(q)
    );
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
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Play className="h-4 w-4" />
          Lancer un scan
        </button>
      </div>

      {/* Barre de progression du scan actif */}
      {activeScan && (
        <ScanProgress
          scanJob={activeScan}
          onDone={() => setActiveScan(null)}
        />
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard label="Total CVEs" value={formatNumber(stats?.total || 0)} variant="neutral" />
        <KpiCard label="Critiques"  value={formatNumber(stats?.critical || 0)} variant="critical" />
        <KpiCard label="Élevées"    value={formatNumber(stats?.high || 0)} variant="high" />
        <KpiCard label="Ouvertes"   value={formatNumber(stats?.open || 0)} variant="medium" />
      </div>

      {/* Filtres */}
      <div className="flex gap-1.5 rounded-lg border border-slate-200 bg-surface p-1 w-fit">
        {["", "critical", "high", "medium", "low"].map((s) => (
          <button
            key={s}
            onClick={() => setSeverity(s)}
            className={`rounded-md px-3 py-1.5 text-sm font-medium capitalize transition ${
              severity === s
                ? "bg-brand-600 text-white"
                : "text-ink-muted hover:bg-surface-hover"
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
        ) : isError ? (
          <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <AlertTriangle className="h-8 w-8 text-red-400" />
            <p className="text-sm font-medium text-ink">Erreur de chargement</p>
            <p className="text-xs text-ink-muted max-w-sm">
              {error?.response?.data?.detail || error?.message || "Impossible de récupérer les vulnérabilités — vérifiez que le backend est démarré."}
            </p>
          </div>
        ) : !filteredVulns?.length ? (
          <EmptyState
            icon={ScanSearch}
            title={searchQuery ? `Aucun résultat pour « ${searchQuery} »` : "Aucune vulnérabilité"}
            message={searchQuery ? "Essayez un autre terme : CVE, IP, service…" : "Lancez un scan pour détecter les CVEs sur votre parc."}
          />
        ) : (
          <div className="overflow-x-auto">
            {searchQuery && (
              <div className="border-b border-slate-100 px-5 py-2 text-xs text-ink-muted">
                <span className="font-medium text-ink">{filteredVulns.length}</span> résultat{filteredVulns.length > 1 ? "s" : ""} pour <span className="font-mono text-brand-600">« {searchQuery} »</span>
              </div>
            )}
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs font-medium text-ink-subtle">
                  <th className="px-5 py-3">Sévérité</th>
                  <th className="px-5 py-3">CVE</th>
                  <th className="px-5 py-3">Titre</th>
                  <th className="px-5 py-3">CVSS</th>
                  <th className="px-5 py-3">Asset</th>
                  <th className="px-5 py-3">Port</th>
                  <th className="px-5 py-3">Détecté</th>
                  <th className="px-5 py-3">Statut</th>
                </tr>
              </thead>
              <tbody>
                {filteredVulns.map((v) => {
                  const detectedDate = v.first_seen || v.created_at;
                  return (
                    <tr
                      key={v.id}
                      className="border-b border-slate-100 transition hover:bg-surface-hover"
                    >
                      <td className="px-5 py-3">
                        <SeverityBadge severity={v.severity} />
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-brand-700">
                        {v.cve_id || "—"}
                      </td>
                      <td className="px-5 py-3 max-w-xs">
                        <p className="font-medium text-ink line-clamp-1">{v.title}</p>
                        {v.affected_service && (
                          <p className="text-[11px] text-ink-muted mt-0.5">{v.affected_service}</p>
                        )}
                      </td>
                      <td className="px-5 py-3">
                        <span className="tabular font-semibold text-ink">
                          {v.cvss_score?.toFixed(1) || "—"}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        {v.asset_ip ? (
                          <div>
                            <p className="font-mono text-xs font-medium text-ink">{v.asset_ip}</p>
                            {v.asset_hostname && v.asset_hostname !== v.asset_ip && (
                              <p className="text-[11px] text-ink-muted mt-0.5 line-clamp-1">
                                {v.asset_hostname}
                              </p>
                            )}
                          </div>
                        ) : (
                          <span className="text-ink-subtle">—</span>
                        )}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-ink-muted">
                        {v.affected_port ? `${v.affected_port}/${v.affected_service || "tcp"}` : "—"}
                      </td>
                      <td className="px-5 py-3 text-xs text-ink-muted">
                        {detectedDate
                          ? new Date(detectedDate).toLocaleDateString("fr-FR", {
                              day: "2-digit",
                              month: "short",
                              year: "2-digit",
                            })
                          : "—"}
                      </td>
                      <td className="px-5 py-3">
                        <StatusBadge status={v.status} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Modal */}
      {showModal && (
        <ScanModal
          onClose={() => setShowModal(false)}
          onStarted={(job) => {
            setActiveScan(job);
            setShowModal(false);
          }}
        />
      )}
    </div>
  );
}
