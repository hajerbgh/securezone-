import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Loader2 } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login, loading, error } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async () => {
    const ok = await login(username, password);
    if (ok) navigate("/");
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter" && username && password) handleSubmit();
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-page px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-600">
            <ShieldCheck className="h-8 w-8 text-white" strokeWidth={2} />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-ink">SecureZone</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Plateforme unifiée de cybersécurité
          </p>
        </div>

        {/* Formulaire */}
        <div className="card p-6">
          <div className="space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-ink">
                Nom d'utilisateur
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onKeyDown={onKeyDown}
                autoFocus
                className="w-full rounded-lg border border-slate-200 px-3 py-2.5 text-sm outline-none transition focus:border-brand-400 focus:ring-2 focus:ring-brand-100"
                placeholder="admin"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-ink">
                Mot de passe
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={onKeyDown}
                className="w-full rounded-lg border border-slate-200 px-3 py-2.5 text-sm outline-none transition focus:border-brand-400 focus:ring-2 focus:ring-brand-100"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <div className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
                {error}
              </div>
            )}

            <button
              onClick={handleSubmit}
              disabled={loading || !username || !password}
              className="btn btn-primary w-full py-2.5 disabled:opacity-50"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? "Connexion…" : "Se connecter"}
            </button>
          </div>
        </div>

        <p className="mt-6 text-center text-xs text-ink-subtle">
          Accès réservé au personnel autorisé · Conforme DORA
        </p>
      </div>
    </div>
  );
}
