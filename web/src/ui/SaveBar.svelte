<script lang="ts">
  // Сохранение настроек: появляется, когда есть правки или ошибка сохранения.
  let {
    dirty,
    saving = false,
    error = "",
    note = "",
    onsave,
    oncancel,
  }: {
    /** Есть несохранённые правки. */
    dirty: boolean;
    saving?: boolean;
    /** Текст ошибки сервера. */
    error?: string;
    /** Что сервер всё же сделал, если файл записан. */
    note?: string;
    onsave: () => void;
    oncancel: () => void;
  } = $props();
</script>

<div class="save">
  {#if error}
    <div class="note note-leak small err">
      <p class="text">{error}</p>
      {#if note}<p class="text">{note}</p>{/if}
    </div>
  {/if}
  {#if dirty}
    <button class="btn btn-quiet" disabled={saving} onclick={oncancel}>Отменить</button>
    <button class="btn btn-primary" class:running={saving} disabled={saving} aria-busy={saving} onclick={onsave}>
      {saving ? "Сохраняю…" : "Применить и сохранить"}
    </button>
  {/if}
</div>

<style>
  .save {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
  }

  .err {
    flex: 1 1 100%;
    overflow-wrap: anywhere;
  }

  .text::first-letter {
    text-transform: uppercase;
  }
</style>
