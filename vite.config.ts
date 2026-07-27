import { defineConfig } from 'vite';

export default defineConfig({
  root: 'frontend',
  base: '/',
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8787',
        ws: true,
      },
    },
  },
  esbuild: {
    // xterm 6 is already optimized; syntax minification can break DECRQM handling.
    minifySyntax: false,
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
});
