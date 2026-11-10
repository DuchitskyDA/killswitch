<script lang="ts">
  import type { Warning } from "../lib/api";

  // Замечания о состоянии: каждое — одной строкой, полный текст — в подсказке.
  let { warnings }: { warnings: Warning[] } = $props();
</script>

{#each warnings as w}
  <p class="note one" class:note-open={w.level === "warn"} class:note-leak={w.level === "leak"} title={w.text}>
    {w.text}
  </p>
{/each}

<style>
  .one {
    overflow: hidden;
    font-size: 13px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
