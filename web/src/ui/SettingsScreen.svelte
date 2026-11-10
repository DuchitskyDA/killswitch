<script lang="ts">
  import type { ComponentProps } from "svelte";
  import { changed } from "../lib/settings";
  import Icon from "./Icon.svelte";
  import SettingsBody from "./SettingsBody.svelte";

  // Экран настроек: стрелка «назад», заголовок и список «название — значение».
  let props: ComponentProps<typeof SettingsBody> = $props();

  const count = $derived(changed(props.saved, props.draft, props.profiles).length);
</script>

<div class="ss">
  <header class="s-head">
    <a class="s-back" href="#main" aria-label="Назад"><Icon name="back" size={18} /></a>
    <h1 class="s-title">Настройки</h1>
    {#if count}<span class="tag tag-open">изменено: {count}</span>{/if}
  </header>
  <SettingsBody {...props} />
</div>

<style>
  .ss {
    display: grid;
    gap: 12px;
    align-content: start;
    min-width: 0;
  }

  .s-head {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 36px;
  }

  .s-back {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    margin-left: -8px;
    border-radius: var(--r-control);
    color: var(--ink);
  }

  .s-back:hover {
    background: var(--surface-2);
  }

  .s-title {
    font: 650 18px/1.2 var(--font-display);
  }

  .s-head :global(.tag) {
    margin-left: auto;
  }
</style>
