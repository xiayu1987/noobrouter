import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Dev: proxy /api to a local agent (dry_run on 127.0.0.1:18090 by default; override with AGENT_URL).
const agent = process.env.AGENT_URL || 'http://127.0.0.1:18090'

export default defineConfig({
  plugins: [vue()],
  server: { port: 5173, proxy: { '/api': { target: agent, changeOrigin: true } } },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 1500,
  },
})
