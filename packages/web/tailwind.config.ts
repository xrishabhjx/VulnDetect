import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Severity palette — reused across badges, bars, and score rings
        crit: "#ef4444",
        high: "#f97316",
        med: "#eab308",
        low: "#3b82f6",
        ok: "#22c55e",
      },
    },
  },
  plugins: [],
};

export default config;
