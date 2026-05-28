import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { writeFileSync } from 'node:fs'

// emptyOutDir wipes dist/ (including the committed .gitkeep that keeps the dir
// present on fresh clones so `//go:embed all:dist` compiles). Re-create it after
// each build so it never shows up as a spurious deletion in git.
function preserveDistPlaceholder() {
  return {
    name: 'preserve-dist-placeholder',
    closeBundle() {
      try { writeFileSync('dist/.gitkeep', '') } catch { /* ignore */ }
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), preserveDistPlaceholder()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    // Allow the web root plus the repo-root wiki/ (for ?raw markdown imports),
    // without exposing the rest of the parent directory over the dev server.
    fs: { allow: ['.', '../wiki'] },
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
