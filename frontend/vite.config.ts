import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Load env file from parent directory
  const env = loadEnv(mode, '../', '')
  
  return {
    plugins: [
      react(),
      nodePolyfills({
        // Whether to polyfill `node:` protocol imports.
        protocolImports: true,
      }),
    ],
    resolve: {
      alias: {
        buffer: 'buffer',
      },
    },
    define: {
      global: 'globalThis',
      // Make DEPLOYER_SECRET available as VITE_DEPLOYER_SECRET
      'import.meta.env.VITE_DEPLOYER_SECRET': JSON.stringify(env.DEPLOYER_SECRET),
    },
    envDir: '../', // Load .env from parent directory
  }
})
