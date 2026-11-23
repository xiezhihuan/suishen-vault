import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: "localhost" },
  // 不内联脚本与样式，配合严格 CSP
  build: { target: "es2022", assetsInlineLimit: 0, sourcemap: false },
});
