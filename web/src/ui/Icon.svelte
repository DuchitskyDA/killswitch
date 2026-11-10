<script lang="ts">
  // Только общепринятые знаки действия: питание, настройки, вперёд, назад, убрать, поиск.
  type Name = "power" | "gear" | "next" | "back" | "remove" | "search";
  let { name, size = 16 }: { name: Name; size?: number } = $props();

  const icons: Record<Name, { box: number; d: string }> = {
    power: { box: 24, d: "M12 3.2v8M7.4 6.2a7.4 7.4 0 1 0 9.2 0" },
    gear: {
      box: 24,
      d:
        "M10.38 4.98 10.69 2.69h2.62l.31 2.29 2.2.91 1.84-1.4 1.85 1.85-1.4 1.84.91 2.2 2.29.31v2.62l-2.29.31-.91 2.2 " +
        "1.4 1.84-1.85 1.85-1.84-1.4-2.2.91-.31 2.29h-2.62l-.31-2.29-2.2-.91-1.84 1.4-1.85-1.85 1.4-1.84-.91-2.2" +
        "-2.29-.31v-2.62l2.29-.31.91-2.2-1.4-1.84 1.85-1.85 1.84 1.4ZM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z",
    },
    next: { box: 16, d: "M6 3.4 10.6 8 6 12.6" },
    back: { box: 16, d: "M10 3.4 5.4 8 10 12.6" },
    remove: { box: 16, d: "M4 4l8 8M12 4l-8 8" },
    search: { box: 16, d: "M7 2.6a4.4 4.4 0 1 0 0 8.8 4.4 4.4 0 0 0 0-8.8ZM10.2 10.2l3.4 3.4" },
  };

  const icon = $derived(icons[name]);
</script>

<svg
  class="icon"
  width={size}
  height={size}
  viewBox="0 0 {icon.box} {icon.box}"
  stroke-width={icon.box / 10.5}
  aria-hidden="true"
>
  <path d={icon.d} />
</svg>

<style>
  .icon {
    flex: none;
    fill: none;
    stroke: currentColor;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
</style>
