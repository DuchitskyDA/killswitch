import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

// Сборка окна встраивается в бинарник: её каталог — internal/window/dist (входит в репозиторий).
export default defineConfig({
  plugins: [svelte()],
  // Относительные пути к ресурсам: страница не знает своего адреса.
  base: "./",
  build: {
    outDir: "../internal/window/dist",
    emptyOutDir: true,
  },
});
