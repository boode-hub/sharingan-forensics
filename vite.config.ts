import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  // Relative base: the same build works at / or at /<repo>/ on Pages.
  base: './',
  plugins: [react()],
  // The parsers ship two large generated tables: 468 EVTX event maps and
  // 14,460 registry-folder GUID names. An ES-module worker lets Vite split
  // them out, so a session that only opens event logs never downloads the
  // GUID table and the other way round.
  worker: { format: 'es' },
  // SQLite's WebAssembly is bundled as bytes (sql-wasm.wasm?inline) so it is
  // never fetched; Vite only inlines a file it treats as an asset.
  assetsInclude: ['**/*.wasm'],
})
