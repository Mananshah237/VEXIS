/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: "#0A0E14",
          secondary: "#111820",
          elevated: "#1A2230",
        },
        border: "#1E2A3A",
        text: {
          primary: "#E6EDF3",
          secondary: "#8B949E",
          muted: "#484F58",
        },
        severity: {
          critical: "#FF1744",
          high: "#FF6D00",
          medium: "#FFD600",
          low: "#448AFF",
          info: "#636E7B",
          safe: "#00E676",
        },
        accent: {
          primary: "#00E5FF",
          secondary: "#7C4DFF",
        },
      },
      fontFamily: {
        code: ["JetBrains Mono", "Fira Code", "monospace"],
        display: ["Space Grotesk", "Outfit", "sans-serif"],
        body: ["IBM Plex Sans", "Noto Sans", "sans-serif"],
      },
    },
  },
  plugins: [],
};
