// Helpers de formatage partagés.

export function formatNumber(n) {
  if (n === null || n === undefined) return "—";
  return new Intl.NumberFormat("fr-FR").format(n);
}

export function formatRelativeTime(date) {
  if (!date) return "—";
  const diff = (Date.now() - new Date(date).getTime()) / 1000;
  if (diff < 60) return `il y a ${Math.floor(diff)}s`;
  if (diff < 3600) return `il y a ${Math.floor(diff / 60)} min`;
  if (diff < 86400) return `il y a ${Math.floor(diff / 3600)} h`;
  return `il y a ${Math.floor(diff / 86400)} j`;
}

export function formatDate(date) {
  if (!date) return "—";
  return new Intl.DateTimeFormat("fr-FR", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(date));
}

// Couleurs de sévérité — cohérentes avec tailwind.config.js
export const SEVERITY_COLORS = {
  critical: "#991B1B",
  high: "#DC2626",
  medium: "#D97706",
  low: "#0F766E",
  info: "#0284C7",
};

export const SEVERITY_LABELS = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  info: "Info",
};

// Palette pour les graphiques (donut, aires)
export const CHART_PALETTE = [
  "#4F46E5", "#0EA5E9", "#10B981", "#F59E0B",
  "#EF4444", "#8B5CF6", "#EC4899", "#14B8A6",
];
