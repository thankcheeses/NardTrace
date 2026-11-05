/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: { 950: '#070B14', 900: '#0B1220', 800: '#101A2E', 700: '#162238', 600: '#1E2D48' },
        line: { DEFAULT: '#1E2D48', strong: '#2A3C5C' },
        trace: '#22D3EE', confirmed: '#34D399', intel: '#60A5FA', assume: '#FBBF24', unk: '#94A3B8', danger: '#FB7185', warn: '#FB923C',
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'Inter', 'system-ui', 'sans-serif'],
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: { glow: '0 0 0 1px rgba(34,211,238,.35), 0 0 24px rgba(34,211,238,.18)', card: '0 1px 0 rgba(255,255,255,.03) inset, 0 8px 30px rgba(0,0,0,.25)' },
    },
  },
  plugins: [],
}
