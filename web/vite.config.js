import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) {
            return
          }
          if (id.includes('@element-plus/icons-vue')) {
            return 'vendor-element-icons'
          }
          if (
            id.includes('dayjs') ||
            id.includes('async-validator') ||
            id.includes('@floating-ui') ||
            id.includes('lodash') ||
            id.includes('lodash-unified') ||
            id.includes('@vueuse')
          ) {
            return 'vendor-element-deps'
          }
          if (id.includes('echarts') || id.includes('zrender') || id.includes('vue-echarts')) {
            return 'vendor-echarts'
          }
          if (id.includes('element-plus')) {
            return 'vendor-element'
          }
          if (id.includes('/vue/') || id.includes('vue-router') || id.includes('pinia')) {
            return 'vendor-vue'
          }
          if (id.includes('axios')) {
            return 'vendor-axios'
          }
          return 'vendor-misc'
        },
      },
    },
  },
})
