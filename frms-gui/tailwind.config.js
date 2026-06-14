/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0f1d',
          darker: '#05070c',
          card: '#11192e',
          cardLight: '#182544',
          border: '#1e2d54',
          text: '#e2e8f0',
          textMuted: '#94a3b8',
          emerald: '#10b981',
          cyan: '#06b6d4',
          rose: '#f43f5e',
          amber: '#f59e0b',
        }
      },
      boxShadow: {
        glow: '0 0 15px rgba(16, 185, 129, 0.15)',
        'glow-cyan': '0 0 15px rgba(6, 182, 212, 0.15)',
        'glow-rose': '0 0 15px rgba(244, 63, 94, 0.15)',
        'glow-amber': '0 0 15px rgba(245, 158, 11, 0.15)',
      }
    },
  },
  plugins: [],
}
