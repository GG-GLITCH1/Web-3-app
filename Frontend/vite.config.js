import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// ✅ Update this to your Render backend URL
const backendURL = 'https://web-3-app-3.onrender.com'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      // Any request starting with /api will go to your backend
      '/api': {
        target: backendURL,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, '') // remove /api prefix before sending to backend
      }
    }
  },
  define: {
    'import.meta.env.VITE_API_BASE_URL': JSON.stringify(
      process.env.NODE_ENV === 'production'
        ? backendURL
        : '/api'
    ),
  },
  build: {
    rollupOptions: {
      external: [] // Fixes Vite warnings for external modules
    },
  },
})
