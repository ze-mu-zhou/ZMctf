/** @type {import("tailwindcss").Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "hsl(var(--zm-bg))",
        panel: "hsl(var(--zm-panel))",
        border: "hsl(var(--zm-border))",
        text: "hsl(var(--zm-text))",
        muted: "hsl(var(--zm-muted))",
        accent: "hsl(var(--zm-accent))",
        cyan: "hsl(var(--zm-cyan))",
        magenta: "hsl(var(--zm-magenta))",
      },
      boxShadow: {
        glow: "0 0 0 1px hsl(var(--zm-border)), 0 0 24px hsl(var(--zm-accent) / 0.12)",
        glowStrong:
          "0 0 0 1px hsl(var(--zm-border)), 0 0 32px hsl(var(--zm-accent) / 0.18)",
      },
    },
  },
  plugins: [],
};
