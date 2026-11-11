import type { CapacitorConfig } from '@capacitor/cli';

// Native shell for the browser edition. The web assets in `dist` are built with
// `npm run build:app` (VITE_NARDTRACE_MODE=browser), so analysis runs on-device and
// cases live in the app's own IndexedDB. Only DNS-over-HTTPS / RDAP / ipinfo lookups go out.
const config: CapacitorConfig = {
  appId: 'com.nardtrace.app',
  appName: 'NardTrace',
  webDir: 'dist',
  android: {
    // Serve from https://localhost so WebCrypto (SHA-256 hashing) and IndexedDB are available.
    allowMixedContent: false,
  },
};

export default config;
