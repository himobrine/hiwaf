import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 开发时把 /api 代理到控制面 API（默认 8090）；生产构建产物由 FastAPI 直接托管。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8090',
    },
  },
  build: { outDir: 'dist', chunkSizeWarningLimit: 1500 },
})
