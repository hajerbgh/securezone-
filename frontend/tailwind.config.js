/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          50:  "#F0FDF4",
          100: "#DCFCE7",
          400: "#4ADE80",
          500: "#22C55E",
          600: "#16A34A",
          700: "#15803D",
          900: "#14532D",
        },
        ink: {
          DEFAULT: "#0F172A",
          muted: "#64748B",
          subtle: "#94A3B8",
        },
        surface: {
          DEFAULT: "#FFFFFF",
          page: "#F7F8FA",
          hover: "#F1F5F9",
        },
        sev: {
          critical: "#991B1B",
          high: "#DC2626",
          medium: "#D97706",
          low: "#0F766E",
          info: "#0284C7",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      fontSize: {
        kpi: ["2.5rem", { lineHeight: "1", fontWeight: "700" }],
      },
      borderRadius: {
        card: "14px",
      },
      boxShadow: {
        card: "0 1px 3px rgba(15, 23, 42, 0.04), 0 1px 2px rgba(15, 23, 42, 0.06)",
        "card-hover": "0 4px 12px rgba(15, 23, 42, 0.08)",
      },
    },
  },
  plugins: [],
};
