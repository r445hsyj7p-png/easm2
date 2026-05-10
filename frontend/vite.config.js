import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      // Im Dev-Modus: API-Calls direkt an den API-Container proxyen
      '/api': {
        target: process.env.VITE_API_URL || 'http://api:8000',
        changeOrigin: true,
      },
    },
  },

  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        // Code-Splitting für besseres Caching
        manualChunks: {
          react:  ['react', 'react-dom'],
          vendor: ['axios'],
        },
      },
    },
  },
});
