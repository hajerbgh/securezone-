import { Outlet, useNavigate, useSearchParams } from "react-router-dom";
import { Search, Bell } from "lucide-react";
import { useState, useEffect } from "react";
import Sidebar from "./Sidebar";

export default function Layout() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") || "");

  // Sync input when URL changes (ex: navigating between pages)
  useEffect(() => {
    setQuery(searchParams.get("q") || "");
  }, [searchParams]);

  const handleSearch = (e) => {
    const val = e.target.value;
    setQuery(val);
    // Navigate to vulnerabilities with ?q= param — debounce via onChange
    navigate(val ? `/vulnerabilities?q=${encodeURIComponent(val)}` : "/vulnerabilities");
  };

  return (
    <div className="min-h-screen bg-surface-page">
      <Sidebar />

      {/* Zone principale décalée de la largeur de la sidebar */}
      <div className="pl-60">
        {/* Header */}
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
          <button
            className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-ink-muted transition hover:bg-surface-hover"
            aria-label="Notifications"
          >
            <Bell className="h-[18px] w-[18px]" strokeWidth={2} />
            <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-sev-high" />
          </button>
        </header>

        {/* Contenu de la page */}
        <main className="p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
