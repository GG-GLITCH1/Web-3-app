// vite.config.js
export default {
  server: {
    proxy: {
      '/api': {
        target: 'https://web-3-app-3.onrender.com',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/api/, '')
      }
    }
  }
};

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000
  },
  build: {
    rollupOptions: {
      external: []  // Explicitly empty to fix the warning
    }
  }
})
