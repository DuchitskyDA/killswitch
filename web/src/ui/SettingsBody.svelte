<script lang="ts">
  import type { ComponentProps } from "svelte";
  import type { Config, Profile } from "../lib/api";
  import {
    changed,
    clientUnset,
    effective,
    errorSection,
    sectionTitle,
    sectionValue,
    SECTIONS,
    setLan,
    type SectionId,
  } from "../lib/settings";
  import Icon from "./Icon.svelte";
  import SaveBar from "./SaveBar.svelte";
  import SectionEditor from "./SectionEditor.svelte";

  type Editor = ComponentProps<typeof SectionEditor>;

  // Настройки: список «название — значение» и отдельно открытый пункт.
  let {
    saved,
    draft,
    profiles,
    repairOk,
    trustKinds,
    selected,
    opened = false,
    view = "ready",
    readError = "",
    saving = false,
    saveError = "",
    saveNote = "",
    findNote = "",
    running = null,
    runningError = "",
    adder = null,
    picked = [],
    onedit,
    onsave,
    oncancel,
    onfind,
    onrunning,
    onretry,
  }: {
    /** Сохранённые настройки и черновик с правками. */
    saved: Config;
    draft: Config;
    profiles: Profile[];
    repairOk: boolean;
    trustKinds: string[];
    /** Открытый пункт. В широком окне он виден рядом со списком. */
    selected: Exclude<SectionId, "lan">;
    /** В узком окне: открыт пункт, а не список. */
    opened?: boolean;
    view?: "ready" | "loading" | "error";
    readError?: string;
    saving?: boolean;
    saveError?: string;
    saveNote?: string;
    findNote?: Editor["findNote"];
    running?: Editor["running"];
    runningError?: Editor["runningError"];
    adder?: Editor["adder"];
    picked?: Editor["picked"];
    onedit: Editor["onedit"];
    onsave: () => void;
    oncancel: () => void;
    onfind: Editor["onfind"];
    onrunning: Editor["onrunning"];
    /** Настройки не прочитаны: прочитать ещё раз. */
    onretry: () => void;
  } = $props();

  const s = $derived(effective(draft, profiles));
  const dirty = $derived(changed(saved, draft, profiles));
  const failed = $derived(saveError ? errorSection(saveError) : null);
</script>

{#if view === "loading"}
  <div class="sb" aria-busy="true"><div class="skeleton h-list list"></div></div>
{:else if view === "error"}
  <!-- Настройки не прочитаны: править нечего, сохранение затёрло бы файл. -->
  <div class="note note-leak unread">
    <p class="small text">{readError}</p>
    <button class="btn" onclick={onretry}>Повторить</button>
  </div>
{:else}
  <div class="sb" class:opened>
    <ul class="panel list">
      {#each SECTIONS as id (id)}
        <li>
          {#snippet mark()}
            {#if failed === id}
              <span class="tag tag-leak">ошибка</span>
            {:else if dirty.includes(id)}
              <span class="tag tag-open">изменено</span>
            {/if}
          {/snippet}
          {#if id === "lan"}
            <div class="item">
              <span class="i-title">{sectionTitle[id]}</span>
              {@render mark()}
              <button
                class="switch"
                role="switch"
                aria-checked={s.lan}
                aria-label={sectionTitle[id]}
                onclick={() => onedit((c) => setLan(c, !s.lan))}
              ></button>
            </div>
          {:else}
            <a
              class="item"
              class:sel={id === selected}
              href="#settings/{id}"
              aria-current={id === selected ? "true" : undefined}
            >
              <span class="i-title">{sectionTitle[id]}</span>
              {@render mark()}
              <span class="i-value" class:unset={id === "client" && clientUnset(s)}>
                {sectionValue(s, profiles, id, repairOk)}
              </span>
              <Icon name="next" />
            </a>
          {/if}
        </li>
      {/each}
    </ul>

    <section class="panel detail" class:bad={failed === selected}>
      <a class="link small up" href="#settings"><Icon name="back" size={14} /> Все настройки</a>
      <h2 class="title">{sectionTitle[selected]}</h2>
      {#key selected}
        <SectionEditor
          id={selected}
          {draft}
          {profiles}
          {repairOk}
          {trustKinds}
          invalid={failed === selected}
          {findNote}
          {running}
          {runningError}
          {adder}
          {picked}
          {onedit}
          {onfind}
          {onrunning}
        />
      {/key}
    </section>

    {#if dirty.length || saveError}
      <div class="save">
        <SaveBar dirty={dirty.length > 0} {saving} error={saveError} note={saveNote} {onsave} {oncancel} />
      </div>
    {/if}
  </div>
{/if}

<style>
  .sb {
    display: grid;
    gap: 12px;
    align-items: start;
    min-width: 0;
  }

  /* Узкое окно: либо список, либо открытый пункт. */
  .sb .detail,
  .sb.opened .list {
    display: none;
  }

  .sb.opened .detail {
    display: grid;
  }

  @container (min-width: 720px) {
    .sb {
      grid-template-columns: 340px minmax(0, 1fr);
      gap: 16px;
    }

    .sb .detail {
      display: grid;
    }

    .sb.opened .list {
      display: block;
    }

    .save {
      grid-column: 1 / -1;
    }

    .up {
      display: none !important;
    }

    .item.sel {
      background: var(--surface-2);
    }
  }

  .list {
    padding: 0;
    overflow: hidden;
  }

  .list li + li {
    border-top: 1px solid var(--line);
  }

  .item {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 48px;
    padding: 0 12px 0 16px;
    color: inherit;
    text-decoration: none;
  }

  .item :global(.icon) {
    color: var(--ink-2);
  }

  .i-title {
    flex: none;
    font-weight: 600;
  }

  .i-value {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    color: var(--ink-2);
    font-size: 13px;
    text-align: right;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .i-value.unset {
    color: var(--open);
    font-weight: 600;
  }

  .item .switch {
    margin-left: auto;
  }

  .detail {
    gap: 12px;
    min-width: 0;
  }

  .detail.bad {
    border-color: var(--leak);
  }

  .up {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    justify-self: start;
    color: var(--ink-2);
  }

  .title {
    font: 650 16px/1.2 var(--font-ui);
  }

  .unread {
    display: grid;
    justify-items: start;
    gap: 10px;
    overflow-wrap: anywhere;
  }

  .text::first-letter {
    text-transform: uppercase;
  }

  .h-list {
    height: 342px;
    border-radius: var(--r-panel);
  }
</style>
