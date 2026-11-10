import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Класс стилей — по их содержимому, а не по пути файла: сборка одинакова на любой машине.
    cssHash: ({ hash, css }) => `svelte-${hash(css)}`,
  },
};
