import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Users, Plus, Shield, Eye, FileCheck, Trash2, X, AlertTriangle } from "lucide-react";
import api from "../lib/api";
import { useRole } from "../context/AuthContext";

const ROLE_CONFIG = {
  admin:   { label: "Administrateur", color: "bg-red-100 text-red-700",     desc: "Accès total — gestion utilisateurs, toutes les actions" },
  analyst: { label: "Analyste SOC",   color: "bg-brand-100 text-brand-700", desc: "Gestion incidents et alertes, lancement de scans" },
  viewer:  { label: "Observateur",    color: "bg-slate-100 text-slate-600", desc: "Lecture seule — aucune modification possible" },
  auditor: { label: "Auditeur",       color: "bg-amber-100 text-amber-700", desc: "Accès conformité et rapports uniquement" },
};

function RoleBadge({ role }) {
  const cfg = ROLE_CONFIG[role] || ROLE_CONFIG.viewer;
  return <span className={`rounded px-2 py-0.5 text-xs font-semibold ${cfg.color}`}>{cfg.label}</span>;
}

function CreateUserModal({ onClose, onSuccess }) {
  const [form, setForm] = useState({ username: "", email: "", full_name: "", password: "", role: "analyst", department: "" });
  const [error, setError] = useState(null);

  const mut = useMutation({
    mutationFn: (data) => api.post("/auth/users", data).then(r => r.data),
    onSuccess: () => { onSuccess(); onClose(); },
    onError: (e) => setError(e.response?.data?.detail || "Erreur lors de la création"),
  });

  const field = (key, label, type = "text", extra = {}) => (
    <div>
      <label className="block text-xs font-medium text-ink-subtle mb-1">{label}</label>
      <input
        type={type}
        value={form[key]}
        onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
        className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none focus:border-brand-400 focus:ring-2 focus:ring-brand-100"
        {...extra}
      />
    </div>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-md rounded-xl bg-white shadow-xl">
        <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4">
          <h2 className="font-semibold text-ink">Créer un utilisateur</h2>
          <button onClick={onClose} className="text-ink-subtle hover:text-ink"><X className="h-5 w-5" /></button>
        </div>
        <div className="space-y-4 p-6">
          {error && (
            <div className="flex items-center gap-2 rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              {error}
            </div>
          )}
          {field("username", "Nom d'utilisateur *", "text", { required: true, autoFocus: true })}
          {field("email", "Email *", "email", { required: true })}
          {field("full_name", "Nom complet *", "text", { required: true })}
          {field("password", "Mot de passe *", "password", { required: true })}
          {field("department", "Département", "text", { placeholder: "ex: SOC, IT, Direction" })}
          <div>
            <label className="block text-xs font-medium text-ink-subtle mb-1">Rôle *</label>
            <select
              value={form.role}
              onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none focus:border-brand-400"
            >
              {Object.entries(ROLE_CONFIG).map(([r, cfg]) => (
                <option key={r} value={r}>{cfg.label} — {cfg.desc}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex gap-3 border-t border-slate-200 px-6 py-4">
          <button onClick={onClose} className="flex-1 rounded-lg border border-slate-200 px-4 py-2 text-sm text-ink-subtle hover:bg-slate-50">
            Annuler
          </button>
          <button
            onClick={() => mut.mutate(form)}
            disabled={mut.isPending || !form.username || !form.email || !form.full_name || !form.password}
            className="flex-1 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {mut.isPending ? "Création..." : "Créer l'utilisateur"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Admin() {
  const { canAdmin } = useRole();
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data: users = [], isLoading } = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => api.get("/auth/users").then(r => r.data).catch(() => []),
  });

  if (!canAdmin) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Shield className="h-12 w-12 text-red-400 mb-4" />
        <h2 className="text-lg font-semibold text-ink mb-2">Accès refusé</h2>
        <p className="text-sm text-ink-subtle">Cette page est réservée aux administrateurs.</p>
      </div>
    );
  }

  const roleStats = Object.keys(ROLE_CONFIG).map(r => ({
    role: r,
    count: users.filter(u => u.role === r).length,
    ...ROLE_CONFIG[r],
  }));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-ink">Administration</h1>
          <p className="text-sm text-ink-subtle mt-0.5">Gestion des utilisateurs et des rôles</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
        >
          <Plus className="h-4 w-4" />
          Nouvel utilisateur
        </button>
      </div>

      {/* Résumé des rôles */}
      <div className="grid grid-cols-4 gap-4">
        {roleStats.map(({ role, label, color, desc, count }) => (
          <div key={role} className="rounded-xl border border-slate-200 bg-white p-4">
            <div className="flex items-center justify-between mb-2">
              <span className={`rounded px-2 py-0.5 text-xs font-semibold ${color}`}>{label}</span>
              <span className="text-2xl font-bold text-ink">{count}</span>
            </div>
            <p className="text-[11px] text-ink-subtle leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>

      {/* Matrice des permissions */}
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
        <div className="border-b border-slate-200 px-6 py-4">
          <h2 className="font-semibold text-ink">Matrice des permissions</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs font-medium text-ink-subtle uppercase tracking-wide">
              <tr>
                <th className="px-6 py-3 text-left">Fonctionnalité</th>
                <th className="px-4 py-3 text-center">Admin</th>
                <th className="px-4 py-3 text-center">Analyste</th>
                <th className="px-4 py-3 text-center">Auditeur</th>
                <th className="px-4 py-3 text-center">Observateur</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {[
                ["Tableau de bord",             true,  true,  true,  true],
                ["Alertes SIEM — lecture",       true,  true,  false, true],
                ["Alertes SIEM — changer statut",true,  true,  false, false],
                ["Vulnérabilités — lecture",     true,  true,  false, true],
                ["Lancer un scan VM",            true,  true,  false, false],
                ["Phishing — analyser URL",      true,  true,  false, true],
                ["Conformité — lecture",         true,  true,  true,  true],
                ["Conformité — évaluer",         true,  true,  false, false],
                ["Télécharger rapports PDF",     true,  true,  true,  false],
                ["Incidents — lecture",          true,  true,  false, false],
                ["Incidents — créer/gérer",      true,  true,  false, false],
                ["SOAR — approuver actions",     true,  true,  false, false],
                ["Administration utilisateurs",  true,  false, false, false],
              ].map(([label, admin, analyst, auditor, viewer]) => (
                <tr key={label} className="hover:bg-slate-50/50">
                  <td className="px-6 py-3 font-medium text-ink">{label}</td>
                  {[admin, analyst, auditor, viewer].map((ok, i) => (
                    <td key={i} className="px-4 py-3 text-center">
                      {ok
                        ? <span className="text-green-600 font-bold">✓</span>
                        : <span className="text-slate-300">—</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Liste des utilisateurs */}
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
        <div className="border-b border-slate-200 px-6 py-4 flex items-center justify-between">
          <h2 className="font-semibold text-ink flex items-center gap-2">
            <Users className="h-4 w-4 text-ink-subtle" />
            Utilisateurs ({users.length})
          </h2>
        </div>
        {isLoading ? (
          <div className="p-8 text-center text-sm text-ink-subtle">Chargement...</div>
        ) : users.length === 0 ? (
          <div className="p-8 text-center text-sm text-ink-subtle">Aucun utilisateur trouvé</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs font-medium text-ink-subtle uppercase tracking-wide">
              <tr>
                <th className="px-6 py-3 text-left">Utilisateur</th>
                <th className="px-4 py-3 text-left">Email</th>
                <th className="px-4 py-3 text-left">Département</th>
                <th className="px-4 py-3 text-left">Rôle</th>
                <th className="px-4 py-3 text-left">Statut</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {users.map(u => (
                <tr key={u.id} className="hover:bg-slate-50/50">
                  <td className="px-6 py-3">
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-100 text-xs font-semibold text-brand-700">
                        {(u.full_name || u.username || "?").split(" ").map(s => s[0]).slice(0, 2).join("").toUpperCase()}
                      </div>
                      <div>
                        <p className="font-medium text-ink">{u.full_name}</p>
                        <p className="text-[11px] text-ink-subtle">@{u.username}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-ink-subtle">{u.email}</td>
                  <td className="px-4 py-3 text-ink-subtle">{u.department || "—"}</td>
                  <td className="px-4 py-3"><RoleBadge role={u.role} /></td>
                  <td className="px-4 py-3">
                    <span className={`rounded px-2 py-0.5 text-xs font-semibold ${u.is_active ? "bg-green-100 text-green-700" : "bg-slate-100 text-slate-500"}`}>
                      {u.is_active ? "Actif" : "Désactivé"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onSuccess={() => qc.invalidateQueries({ queryKey: ["admin-users"] })}
        />
      )}
    </div>
  );
}

