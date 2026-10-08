/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { VitePWA } from 'vite-plugin-pwa';
import path from 'node:path';

export default defineConfig({
  plugins: [
    vue(),
    VitePWA({
      registerType: 'autoUpdate',
      filename: 'service-worker.js',
      manifest: {
        name: 'admino',
        short_name: 'admino',
        start_url: '/',
        display: 'standalone',
        theme_color: '#075E54',
        background_color: '#F7F4EE',
        icons: [
          { src: 'icons/icon-192.png', sizes: '192x192', type: 'image/png' },
          { src: 'icons/icon-512.png', sizes: '512x512', type: 'image/png' },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,woff2,ttf,png,svg,json}'],
        navigateFallbackDenylist: [/^\/api\//],
        skipWaiting: true,
        clientsClaim: true,
      },
    }),
  ],
  resolve: { alias: { '@': path.resolve(__dirname, 'src') } },
  build: {
    outDir: path.resolve(__dirname, '../static'),
    emptyOutDir: true,
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          if (/\.(woff2?|ttf|otf)$/i.test(assetInfo.name ?? '')) {
            return 'fonts/[name][extname]';
          }
          return 'assets/[name]-[hash][extname]';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
    },
  },
  // Frontend logic tests (`npm run test`): stores, composables, services and
  // API clients, never UI. happy-dom supplies the DOM that DOMPurify needs;
  // tests never touch the network.
  test: {
    environment: 'happy-dom',
    include: ['src/__tests__/**/*.test.ts'],
    restoreMocks: true,
    unstubGlobals: true,
    // happy-dom nodeName shim for DOMPurify >= 3.4.8 (GH-289 Decision 8).
    setupFiles: ['src/__tests__/setup/happyDomNodeName.ts'],
  },
});
