import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Fish, Search, Mail, ShieldAlert, ShieldX,
  CheckCircle2, ChevronRight, ChevronDown, Zap, RefreshCw,
} from "lucide-react";
import api from "../lib/api";
import { Card, SeverityBadge, Spinner, EmptyState } from "../components/ui";
import { formatRelativeTime } from "../lib/format";

// ── Score helpers ────────────────────────────────────────────────
function scoreColor(s) {
  if (s >= 86) return "#DC2626";
  if (s >= 61) return "#EA580C";
  if (s >= 31) return "#D97706";
  return "#16A34A";
}

function scoreLabel(s) {
  if (s >= 86) return "Critique — Phishing confirmé";
  if (s >= 61) return "Élevé — Probable phishing";
  if (s >= 31) return "Moyen — Suspect";
  return "Faible — Probablement légitime";
}

const INDICATOR_META = {
  ip_as_host:            "IP brute comme hôte",
  url_shortener:         "URL shortener (masquage)",
  http_sensitive_page:   "HTTP non chiffré sur page sensible",
  many_subdomains:       "Nombreux sous-domaines (≥4)",
  high_entropy:          "Domaine à haute entropie (généré)",
  long_url:              "URL anormalement longue",
  dmarc_fail:            "DMARC échoué",
  spf_fail:              "SPF échoué",
  spf_softfail:          "SPF softfail",
  reply_to_mismatch:     "Reply-To ≠ domaine expéditeur",
  urgency_keywords:      "Mots-clés d'urgence dans le sujet",
  malicious_url_in_body: "URL suspecte dans le corps",
};

function indLabel(ind) {
  for (const [key, lbl] of Object.entries(INDICATOR_META)) {
    if (ind.startsWith(key)) return lbl;
  }
  if (ind.startsWith("typosquatting:"))     return `Typosquatting : ${ind.split(":")[1]}`;
  if (ind.startsWith("homoglyph:"))         return `Homoglyphe : ${ind.split(":")[1]}`;
  if (ind.startsWith("brand_in_subdomain:"))return `Marque dans sous-domaine : ${ind.split(":")[1]}`;
  if (ind.startsWith("suspicious_tld:"))    return `TLD suspect : ${ind.split(":")[1]}`;
  if (ind.startsWith("sender_suspicious_tld:")) return "Expéditeur sur TLD suspect";
  if (ind.startsWith("sensitive_path:"))    return `Chemin sensible : ${ind.split(":")[1]}`;
  if (ind.startsWith("urgency_keywords:"))  return `Urgence : "${ind.split(":").slice(1).join(",")}"`;
  return ind.replace(/_/g, " ");
}

// ── Composants ───────────────────────────────────────────────────

function ScoreGauge({ score }) {
  const color = scoreColor(score);
  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between">
        <span className="text-4xl font-bold leading-none" style={{ color }}>
          {score.toFixed(0)}
          <span className="text-lg font-normal text-ink-subtle">/100</span>
        </span>
        <span className="text-sm font-medium" style={{ color }}>{scoreLabel(score)}</span>
      </div>
      <div className="h-3 w-full rounded-full bg-slate-100">
        <div
          className="h-3 rounded-full transition-all duration-700"
          style={{ width: `${Math.min(100, score)}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}

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

function IndicatorBadges({ indicators }) {
  if (!indicators?.length) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {indicators.map((ind, i) => (
        <span key={i} className="rounded-full bg-red-50 px-2 py-0.5 text-xs text-red-700">
          {indLabel(ind)}
        </span>
      ))}
    </div>
  );
}

function PhishAlertRow({ alert }) {
  const [open, setOpen] = useState(false);
  const raw = alert.raw_log || {};
  const score = raw.phishing_score ?? (alert.risk_score * 10);
  const color = scoreColor(score);

  return (
    <>
      <tr
        onClick={() => setOpen((v) => !v)}
        className="cursor-pointer border-b border-slate-100 hover:bg-slate-50 transition-colors"
      >
        <td className="w-1 p-0">
          <div style={{ backgroundColor: color, minHeight: 44, width: 3 }} className="rounded-l" />
        </td>
        <td className="px-3 py-3">
          {open
            ? <ChevronDown size={13} className="text-ink-subtle" />
            : <ChevronRight size={13} className="text-ink-subtle" />
          }
        </td>
        <td className="px-4 py-3"><SeverityBadge severity={alert.severity} /></td>
        <td className="px-4 py-3 max-w-xs">
          <p className="truncate text-sm font-medium text-ink">{alert.title}</p>
          <p className="text-xs text-ink-muted mt-0.5">
            {raw.event_type === "email" ? "Email" : raw.event_type === "url" ? "URL" : "Phishing"}
          </p>
        </td>
        <td className="px-4 py-3">
          <span className="text-sm font-bold" style={{ color }}>{score.toFixed(0)}/100</span>
        </td>
        <td className="px-4 py-3 font-mono text-xs text-ink-muted">{alert.source_ip || "—"}</td>
        <td className="px-4 py-3">
          <span className="rounded bg-brand-50 px-1.5 py-0.5 font-mono text-xs text-brand-700">T1566</span>
        </td>
        <td className="px-4 py-3 text-xs text-ink-subtle">{formatRelativeTime(alert.created_at)}</td>
      </tr>
      {open && (
        <tr className="bg-slate-50 border-b border-slate-200">
          <td className="w-1 p-0">
            <div style={{ backgroundColor: color, width: 3, minHeight: "100%" }} />
          </td>
          <td />
          <td colSpan={6} className="px-5 py-4 space-y-2">
            <p className="text-sm text-ink whitespace-pre-wrap">{alert.description}</p>
            {raw.indicators?.length > 0 && (
              <div>
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-subtle">
                  Indicateurs
                </p>
                <IndicatorBadges indicators={raw.indicators} />
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// ── Page principale ──────────────────────────────────────────────
export default function Phishing() {
  const qc = useQueryClient();

  const [urlInput, setUrlInput] = useState("");
  const [urlResult, setUrlResult] = useState(null);

  const [emailForm, setEmailForm] = useState({
    sender: "", subject: "", spf_result: "none",
    dmarc_result: "none", body_urls: "", reply_to: "",
  });
  const [emailResult, setEmailResult] = useState(null);

  const { data: stats } = useQuery({
    queryKey: ["phishing-stats"],
    queryFn: async () => { const { data } = await api.get("/phishing/stats"); return data; },
    refetchInterval: 30000,
  });

  const { data: alerts, isLoading } = useQuery({
    queryKey: ["phishing-alerts"],
    queryFn: async () => { const { data } = await api.get("/phishing/alerts"); return data; },
    refetchInterval: 30000,
  });

  const urlMutation = useMutation({
    mutationFn: (body) => api.post("/phishing/analyze/url", body),
    onSuccess: (res) => {
      setUrlResult(res.data);
      if (res.data.alert_created) {
        qc.invalidateQueries({ queryKey: ["phishing-alerts"] });
        qc.invalidateQueries({ queryKey: ["phishing-stats"] });
        qc.invalidateQueries({ queryKey: ["alerts"] });
        qc.invalidateQueries({ queryKey: ["alerts-stats"] });
      }
    },
  });

  const emailMutation = useMutation({
    mutationFn: (body) => api.post("/phishing/analyze/email", body),
    onSuccess: (res) => {
      setEmailResult(res.data);
      if (res.data.alert_created) {
        qc.invalidateQueries({ queryKey: ["phishing-alerts"] });
        qc.invalidateQueries({ queryKey: ["phishing-stats"] });
        qc.invalidateQueries({ queryKey: ["alerts"] });
        qc.invalidateQueries({ queryKey: ["alerts-stats"] });
      }
    },
  });

  const handleUrlAnalyze = (createAlert) => {
    if (!urlInput.trim()) return;
    urlMutation.mutate({ url: urlInput.trim(), create_alert: createAlert });
  };

  const handleEmailAnalyze = (createAlert) => {
    if (!emailForm.sender.trim()) return;
    emailMutation.mutate({
      sender: emailForm.sender,
      subject: emailForm.subject,
      spf_result: emailForm.spf_result,
      dmarc_result: emailForm.dmarc_result,
      reply_to: emailForm.reply_to || undefined,
      body_urls: emailForm.body_urls
        ? emailForm.body_urls.split("\n").map((u) => u.trim()).filter(Boolean)
        : [],
      create_alert: createAlert,
    });
  };

  const setField = (k, v) => setEmailForm((p) => ({ ...p, [k]: v }));

  return (
    <div className="space-y-5">

      {/* En-tête */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-ink">
            <Fish size={21} className="text-blue-600" />
            Détection Phishing
          </h1>
          <p className="mt-0.5 text-sm text-ink-muted">
            Analyse heuristique d&apos;URLs et d&apos;emails — MITRE ATT&amp;CK T1566
          </p>
        </div>
        <button
          onClick={() => {
            qc.invalidateQueries({ queryKey: ["phishing-alerts"] });
            qc.invalidateQueries({ queryKey: ["phishing-stats"] });
          }}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200
                     bg-white px-3 py-1.5 text-sm text-ink-muted hover:bg-slate-50 transition"
        >
          <RefreshCw size={14} /> Rafraîchir
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <KpiBox label="Total détections" value={stats?.total}     colorCls="bg-blue-600"    icon={Fish}        />
        <KpiBox label="Ouvertes"         value={stats?.open}      colorCls="bg-red-600"     icon={ShieldAlert} />
        <KpiBox label="Haut risque"      value={stats?.high_risk} colorCls="bg-orange-500"  icon={Zap}         />
        <KpiBox label="Critiques"        value={stats?.critical}  colorCls="bg-red-700"     icon={ShieldX}     />
      </div>

      {/* Analyseurs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* URL Analyzer */}
        <Card title="Analyser une URL">
          <div className="mt-2 space-y-3">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleUrlAnalyze(false)}
              placeholder="https://paypa1.com/account/verify?token=abc123"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm
                         outline-none focus:border-brand-400 placeholder:text-ink-subtle font-mono"
            />
            <div className="flex gap-2">
              <button
                disabled={!urlInput.trim() || urlMutation.isPending}
                onClick={() => handleUrlAnalyze(false)}
                className="flex-1 rounded-lg border border-slate-300 bg-slate-50 px-3 py-2
                           text-sm font-medium text-ink hover:bg-slate-100 disabled:opacity-50 transition"
              >
                {urlMutation.isPending ? "Analyse…" : "Analyser"}
              </button>
              <button
                disabled={!urlInput.trim() || urlMutation.isPending}
                onClick={() => handleUrlAnalyze(true)}
                className="flex-1 rounded-lg bg-brand-600 px-3 py-2 text-sm font-medium
                           text-white hover:bg-brand-700 disabled:opacity-50 transition"
              >
                <Search size={14} className="inline mr-1" />
                Analyser & Alerter
              </button>
            </div>

            {urlResult && (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 space-y-3">
                <ScoreGauge score={urlResult.score} />
                {urlResult.indicators.length > 0 ? (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-subtle">
                      Indicateurs détectés
                    </p>
                    <IndicatorBadges indicators={urlResult.indicators} />
                  </div>
                ) : (
                  <p className="text-sm text-emerald-700 flex items-center gap-1.5">
                    <CheckCircle2 size={14} /> Aucun indicateur suspect
                  </p>
                )}
                {urlResult.alert_created && (
                  <p className="text-xs text-brand-700 font-medium">
                    Alerte SIEM créée — ID #{urlResult.alert_id}
                  </p>
                )}
              </div>
            )}
          </div>
        </Card>

        {/* Email Analyzer */}
        <Card title="Analyser un email">
          <div className="mt-2 space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-ink-muted">Expéditeur *</label>
                <input
                  value={emailForm.sender}
                  onChange={(e) => setField("sender", e.target.value)}
                  placeholder="admin@paypa1.com"
                  className="mt-0.5 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm
                             outline-none focus:border-brand-400 font-mono"
                />
              </div>
              <div>
                <label className="text-xs text-ink-muted">Reply-To</label>
                <input
                  value={emailForm.reply_to}
                  onChange={(e) => setField("reply_to", e.target.value)}
                  placeholder="other@domain.tk"
                  className="mt-0.5 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm
                             outline-none focus:border-brand-400 font-mono"
                />
              </div>
            </div>
            <div>
              <label className="text-xs text-ink-muted">Sujet</label>
              <input
                value={emailForm.subject}
                onChange={(e) => setField("subject", e.target.value)}
                placeholder="Urgent : Votre compte a été suspendu"
                className="mt-0.5 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm
                           outline-none focus:border-brand-400"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-xs text-ink-muted">SPF</label>
                <select
                  value={emailForm.spf_result}
                  onChange={(e) => setField("spf_result", e.target.value)}
                  className="mt-0.5 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm outline-none"
                >
                  <option value="none">none</option>
                  <option value="pass">pass</option>
                  <option value="softfail">softfail</option>
                  <option value="fail">fail</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-ink-muted">DMARC</label>
                <select
                  value={emailForm.dmarc_result}
                  onChange={(e) => setField("dmarc_result", e.target.value)}
                  className="mt-0.5 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm outline-none"
                >
                  <option value="none">none</option>
                  <option value="pass">pass</option>
                  <option value="fail">fail</option>
                </select>
              </div>
            </div>
            <div>
              <label className="text-xs text-ink-muted">URLs dans le corps (une par ligne)</label>
              <textarea
                value={emailForm.body_urls}
                onChange={(e) => setField("body_urls", e.target.value)}
                placeholder={"http://bit.ly/3xK9pL\nhttps://paypa1.com/secure"}
                rows={2}
                className="mt-0.5 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm
                           outline-none focus:border-brand-400 font-mono resize-none"
              />
            </div>
            <div className="flex gap-2">
              <button
                disabled={!emailForm.sender.trim() || emailMutation.isPending}
                onClick={() => handleEmailAnalyze(false)}
                className="flex-1 rounded-lg border border-slate-300 bg-slate-50 px-3 py-2
                           text-sm font-medium text-ink hover:bg-slate-100 disabled:opacity-50 transition"
              >
                {emailMutation.isPending ? "Analyse…" : "Analyser"}
              </button>
              <button
                disabled={!emailForm.sender.trim() || emailMutation.isPending}
                onClick={() => handleEmailAnalyze(true)}
                className="flex-1 rounded-lg bg-brand-600 px-3 py-2 text-sm font-medium
                           text-white hover:bg-brand-700 disabled:opacity-50 transition"
              >
                <Mail size={14} className="inline mr-1" />
                Analyser & Alerter
              </button>
            </div>

            {emailResult && (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 space-y-3">
                <ScoreGauge score={emailResult.score} />
                {emailResult.indicators.length > 0 ? (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-subtle">
                      Indicateurs
                    </p>
                    <IndicatorBadges indicators={emailResult.indicators} />
                  </div>
                ) : (
                  <p className="text-sm text-emerald-700 flex items-center gap-1.5">
                    <CheckCircle2 size={14} /> Email semble légitime
                  </p>
                )}
                {emailResult.alert_created && (
                  <p className="text-xs text-brand-700 font-medium">
                    Alerte SIEM créée — ID #{emailResult.alert_id}
                  </p>
                )}
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Détections récentes */}
      <Card className="overflow-hidden p-0">
        <div className="border-b border-slate-200 px-5 py-3">
          <h3 className="text-sm font-semibold text-ink">Détections phishing récentes</h3>
          <p className="text-xs text-ink-muted mt-0.5">
            Alertes SIEM générées automatiquement par le moteur phishing
          </p>
        </div>
        {isLoading ? (
          <Spinner />
        ) : !alerts?.length ? (
          <EmptyState
            icon={Fish}
            title="Aucune détection"
            message="Analysez une URL ou un email ci-dessus pour générer la première alerte."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-left text-xs font-semibold text-ink-subtle">
                  <th className="w-1 p-0" />
                  <th className="w-8 px-3 py-3" />
                  <th className="px-4 py-3">Sévérité</th>
                  <th className="px-4 py-3">Titre / Type</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Source IP</th>
                  <th className="px-4 py-3">MITRE</th>
                  <th className="px-4 py-3">Détectée</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => <PhishAlertRow key={a.id} alert={a} />)}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
