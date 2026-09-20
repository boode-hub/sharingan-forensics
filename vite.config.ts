import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  // Relative base: the same build works at / or at /<repo>/ on Pages.
  base: './',
  plugins: [react()],
})
