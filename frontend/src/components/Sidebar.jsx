import { NavLink } from "react-router-dom";
import clsx from "clsx";
import {
  LayoutDashboard, ShieldAlert, ScanSearch, FileCheck2,
  Siren, LogOut, Fish, Settings, Crown,
} from "lucide-react";
import { useAuth, useRole } from "../context/AuthContext";

const ROLE_LABEL = {
  admin:   { text: "Administrateur", color: "bg-red-100 text-red-700" },
  analyst: { text: "Analyste SOC",   color: "bg-brand-100 text-brand-700" },
  viewer:  { text: "Observateur",    color: "bg-slate-100 text-slate-600" },
  auditor: { text: "Auditeur",       color: "bg-amber-100 text-amber-700" },
};

export default function Sidebar() {
  const { user, logout } = useAuth();
  const { isAdmin, isAnalyst, isAuditor } = useRole();

  // Navigation filtrée selon le rôle
  const NAV = [
    { to: "/",              label: "Tableau de bord",  icon: LayoutDashboard, end: true, roles: ["admin","analyst","viewer","auditor"] },
    { to: "/alerts",        label: "Alertes (SIEM)",   icon: ShieldAlert,               roles: ["admin","analyst","viewer"] },
    { to: "/vulnerabilities",label: "Vulnérabilités",  icon: ScanSearch,                roles: ["admin","analyst","viewer"] },
    { to: "/phishing",      label: "Phishing",         icon: Fish,                      roles: ["admin","analyst","viewer"] },
    { to: "/compliance",    label: "Conformité",       icon: FileCheck2,                roles: ["admin","analyst","viewer","auditor"] },
    { to: "/incidents",     label: "Incidents (IR)",   icon: Siren,                     roles: ["admin","analyst"] },
    { to: "/admin",         label: "Administration",   icon: Settings,                  roles: ["admin"] },
  ].filter(item => item.roles.includes(user?.role));

  const roleInfo = ROLE_LABEL[user?.role] || ROLE_LABEL.viewer;

  return (
    <aside className="fixed inset-y-0 left-0 flex w-60 flex-col border-r border-slate-200 bg-surface">
      {/* Logo MAE */}
      <div className="flex items-center gap-3 border-b border-slate-100 px-4 py-4">
        <img
          src="/logo_ame.png"
          alt="MAE Assurances"
          className="h-11 w-11 rounded-full object-cover"
          onError={(e) => { e.currentTarget.style.display = "none"; }}
        />
        <div>
          <p className="text-sm font-bold leading-tight text-ink">MAE Assurances</p>
          <p className="text-[11px] leading-tight text-brand-600 font-medium">SecureZone SOC</p>
        </div>
      </div>

      {/* Badge rôle admin */}
      {isAdmin && (
        <div className="mx-3 mb-1 flex items-center gap-1.5 rounded-md bg-red-50 border border-red-200 px-3 py-1.5">
          <Crown className="h-3.5 w-3.5 text-red-600" />
          <span className="text-xs font-semibold text-red-700">Mode Administrateur</span>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-3 py-2">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              clsx("nav-item", isActive && "nav-item-active")
            }
          >
            <Icon className="h-[18px] w-[18px]" strokeWidth={2} />
            {label}
            {to === "/admin" && (
              <span className="ml-auto rounded text-[10px] font-bold px-1.5 py-0.5 bg-red-100 text-red-700">
                ADMIN
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Utilisateur + déconnexion */}
      <div className="border-t border-slate-200 p-3">
        <div className="flex items-center gap-3 rounded-lg px-3 py-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-100 text-xs font-semibold text-brand-600">
            {(user?.full_name || user?.username || "?")
              .split(" ")
              .map((s) => s[0])
              .slice(0, 2)
              .join("")
              .toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-ink">
              {user?.full_name || user?.username}
            </p>
            <span className={clsx("inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold", roleInfo.color)}>
              {roleInfo.text}
            </span>
          </div>
        </div>
        <button onClick={logout} className="nav-item mt-1 w-full">
          <LogOut className="h-[18px] w-[18px]" strokeWidth={2} />
          Déconnexion
        </button>
      </div>
    </aside>
  );
}
