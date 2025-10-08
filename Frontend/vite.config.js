import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// ✅ Your backend on Render
const backendURL = 'https://web-3-app-3.onrender.com'

export default defineConfig({
  base: './', // 👈 Important for Vercel static hosting
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: backendURL,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, '') // remove /api prefix
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
      external: [] // silence axios warnings
    },
  },
})
