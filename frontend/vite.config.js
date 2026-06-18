import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// During local `vite dev`, proxy API + WS to the backend so the SPA works
// without nginx. In production the nginx container handles proxying.
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
});
