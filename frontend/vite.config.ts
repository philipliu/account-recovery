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
      // Make FACTORY_CONTRACT_ID available as VITE_FACTORY_CONTRACT_ID
      'import.meta.env.VITE_FACTORY_CONTRACT_ID': JSON.stringify(env.FACTORY_CONTRACT_ID || 'CCLN4GLYSIRHUY7Q4Q73TUJXQYD4COXDDFCYHKRGOZOZOTTTLXCX46KL'),
    },
    envDir: '../', // Load .env from parent directory
  }
})
