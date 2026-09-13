/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#08080a",
          900: "#0e0e11",
          850: "#131317",
          800: "#18181c",
          750: "#1e1e23",
          700: "#26262d",
          650: "#30303a",
          600: "#3b3b45",
        },
        edge: {
          0: "#1f1f24",
          1: "#2a2a31",
          2: "#37373f",
          3: "#4a4a55",
        },
        violet2: {
          400: "#a78bfa",
          500: "#8b5cf6",
          600: "#7c3aed",
        },
      },
      fontFamily: {
        sans: ["Inter var", "Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["'JetBrains Mono'", "'Fira Code'", "ui-monospace", "monospace"],
      },
      boxShadow: {
        "glow-violet": "0 0 0 1px rgba(139,92,246,.4), 0 0 24px -4px rgba(139,92,246,.55)",
        "glow-emerald": "0 0 0 1px rgba(16,185,129,.4), 0 0 24px -4px rgba(16,185,129,.5)",
        "panel": "0 1px 0 0 rgba(255,255,255,.04) inset, 0 24px 48px -24px rgba(0,0,0,.85)",
        "float": "0 20px 48px -12px rgba(0,0,0,.7), 0 2px 8px -2px rgba(0,0,0,.5)",
      },
      animation: {
        "fade-in": "fadeIn .2s ease-out",
        "slide-up": "slideUp .28s cubic-bezier(.16,1,.3,1)",
        "slide-in-right": "slideInRight .3s cubic-bezier(.16,1,.3,1)",
        "pop": "pop .18s cubic-bezier(.16,1,.3,1)",
        "shimmer": "shimmer 2.5s linear infinite",
        "pulse-ring": "pulseRing 1.6s cubic-bezier(.4,0,.6,1) infinite",
        "dash": "dash 1.2s linear infinite",
        "float-slow": "floatSlow 6s ease-in-out infinite",
      },
      keyframes: {
        fadeIn:   { from: { opacity: 0 }, to: { opacity: 1 } },
        slideUp:  { from: { opacity: 0, transform: "translateY(8px)" }, to: { opacity: 1, transform: "none" } },
        slideInRight: { from: { opacity: 0, transform: "translateX(16px)" }, to: { opacity: 1, transform: "none" } },
        pop:      { from: { opacity: 0, transform: "scale(.96)" }, to: { opacity: 1, transform: "scale(1)" } },
        shimmer:  { "0%": { backgroundPosition: "-200% 0" }, "100%": { backgroundPosition: "200% 0" } },
        pulseRing:{ "0%": { transform: "scale(.9)", opacity: .8 }, "100%": { transform: "scale(1.4)", opacity: 0 } },
        dash:     { to: { strokeDashoffset: "-20" } },
        floatSlow:{ "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-6px)" } },
      },
      backgroundImage: {
        "grid-fine": "radial-gradient(rgba(255,255,255,.045) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};