import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/admin-console/',
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:3000',
      '/v1': 'http://localhost:4000',
    },
  },
  build: {
    outDir: '../web-app/public/admin-console',
    emptyOutDir: true,
  },
});
