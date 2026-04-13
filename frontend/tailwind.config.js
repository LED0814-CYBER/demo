/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      boxShadow: {
        neon: "0 0 0 1px rgba(34,211,238,.3), 0 0 40px rgba(14,116,144,.25)",
      },
      keyframes: {
        "terminal-fade": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "terminal-fade": "terminal-fade .35s ease-out",
      },
    },
  },
  plugins: [],
};
