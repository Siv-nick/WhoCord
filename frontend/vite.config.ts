import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "tailwindcss";
import autoprefixer from "autoprefixer";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  css: {
    postcss: {
      plugins: [tailwindcss(), autoprefixer()],
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Forward all API + pipeline calls to the Flask backend in dev
      "/api": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/run": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/config": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/get_config": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/stop": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/upgrade_tools": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/shutdown": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/report": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
          router: ["react-router-dom"],
        },
      },
    },
  },
});
