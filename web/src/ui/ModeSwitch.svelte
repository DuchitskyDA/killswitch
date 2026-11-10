<script lang="ts">
  import type { Kind } from "../lib/screen";

  // Переключатель режима под кнопкой питания: что она включает.
  let {
    kind,
    repairOk = true,
    disabled = false,
    onkind,
  }: {
    kind: Kind;
    /** Починка есть только в Windows. */
    repairOk?: boolean;
    disabled?: boolean;
    onkind: (kind: Kind) => void;
  } = $props();
</script>

<div class="seg" role="radiogroup" aria-label="Режим">
  <button
    class="pos"
    class:on={kind === "full"}
    role="radio"
    aria-checked={kind === "full"}
    {disabled}
    onclick={() => onkind("full")}
  >
    Полная
  </button>
  <button
    class="pos"
    class:on={kind === "repair"}
    role="radio"
    aria-checked={kind === "repair"}
    disabled={disabled || !repairOk}
    onclick={() => onkind("repair")}
  >
    Починка
    {#if !repairOk}<span class="only">только Windows</span>{/if}
  </button>
</div>

<style>
  .seg {
    display: inline-grid;
    grid-template-columns: 1fr 1fr;
    gap: 3px;
    padding: 3px;
    border: 1px solid var(--line);
    border-radius: 9px;
    background: var(--surface);
  }

  .pos {
    display: grid;
    align-content: center;
    justify-items: center;
    min-width: 104px;
    min-height: 32px;
    padding: 2px 12px;
    border: 0;
    border-radius: var(--r-control);
    background: none;
    font: 600 13px/1.25 var(--font-ui);
    cursor: pointer;
  }

  .pos.on {
    background: var(--ink);
    color: var(--on-ink);
  }

  .pos:disabled {
    color: var(--ink-2);
    cursor: not-allowed;
  }

  .pos.on:disabled {
    background: var(--surface-2);
    box-shadow: inset 0 0 0 1px var(--line);
  }

  .only {
    font-size: 12px;
    font-weight: 400;
  }
</style>
