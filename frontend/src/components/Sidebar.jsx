import { NavLink } from "react-router-dom";
import clsx from "clsx";
import {
  LayoutDashboard, ShieldAlert, ScanSearch, FileCheck2,
  Siren, LogOut, ShieldCheck, Fish,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const NAV = [
  { to: "/", label: "Tableau de bord", icon: LayoutDashboard, end: true },
  { to: "/alerts", label: "Alertes (SIEM)", icon: ShieldAlert },
  { to: "/vulnerabilities", label: "Vulnérabilités", icon: ScanSearch },
  { to: "/phishing", label: "Phishing", icon: Fish },
  { to: "/compliance", label: "Conformité", icon: FileCheck2 },
  { to: "/incidents", label: "Incidents", icon: Siren },
];

export default function Sidebar() {
  const { user, logout } = useAuth();

  return (
    <aside className="fixed inset-y-0 left-0 flex w-60 flex-col border-r border-slate-200 bg-surface">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-600">
          <ShieldCheck className="h-5 w-5 text-white" strokeWidth={2} />
        </div>
        <div>
          <p className="text-sm font-bold leading-tight text-ink">SecureZone</p>
          <p className="text-[11px] leading-tight text-ink-subtle">Security Platform</p>
        </div>
      </div>

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
          </NavLink>
        ))}
      </nav>

      {/* Utilisateur + déconnexion */}
      <div className="border-t border-slate-200 p-3">
        <div className="flex items-center gap-3 rounded-lg px-3 py-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-100 text-xs font-semibold text-brand-700">
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
            <p className="truncate text-[11px] capitalize text-ink-subtle">
              {user?.role}
            </p>
          </div>
        </div>
        <button
          onClick={logout}
          className="nav-item mt-1 w-full"
        >
          <LogOut className="h-[18px] w-[18px]" strokeWidth={2} />
          Déconnexion
        </button>
      </div>
    </aside>
  );
}
