<script lang="ts">
  import { classWord, verdictTone, verdictWord, type CheckView } from "../lib/check";
  import { busyWord } from "../lib/screen";

  // Проверка утечек: кнопка и итог одной карточкой внизу окна — слово и одна строка; таблица проб — по «Подробнее».
  let {
    view: c,
    open = false,
    busy = false,
    disabled = false,
    oncheck,
    ontoggle,
  }: {
    view: CheckView | null;
    open?: boolean;
    busy?: boolean;
    disabled?: boolean;
    oncheck: () => void;
    ontoggle: () => void;
  } = $props();
</script>

<section class="check tone-{c ? verdictTone[c.verdict] : 'none'}" class:has={c !== null}>
  <button class="btn go" class:running={busy} disabled={disabled || busy} aria-busy={busy} onclick={oncheck}>
    {busy ? busyWord.check : "Проверить утечки"}
  </button>

  {#if c}
    <div class="res v-{c.verdict}">
      <div class="top">
        <div class="what">
          <p class="verdict">{verdictWord[c.verdict]}</p>
          <p class="line small">{c.line}</p>
        </div>
        <button class="link small" aria-expanded={open} onclick={ontoggle}>{open ? "Свернуть" : "Подробнее"}</button>
      </div>

      {#if open}
        {#if c.note}<p class="small about">{c.note}</p>{/if}
        {#if c.findings.length}
          <ul class="findings small">
            {#each c.findings as f}<li>{f}</li>{/each}
          </ul>
        {/if}
        {#if c.rows.length || c.skipped.length}
          <table class="matrix">
            <thead>
              <tr>
                <th scope="col">Адаптер</th>
                {#each c.columns as col (col)}<th scope="col">{col}</th>{/each}
              </tr>
            </thead>
            <tbody>
              {#each c.rows as row (row.iface)}
                <tr>
                  <th scope="row" class="mono">{row.iface}</th>
                  {#each row.cells as cell}
                    <td><span class="cell o-{cell}">{classWord[cell]}</span></td>
                  {/each}
                </tr>
              {/each}
              {#each c.skipped as k (k.iface)}
                <tr class="skip">
                  <th scope="row" class="mono">{k.iface}</th>
                  <td colspan={c.columns.length}>пропущен{k.why ? `: ${k.why}` : ""}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
        {#if c.targets.length}
          <p class="muted small">
            {c.targets.length > 1 ? "Серверы проверки" : "Сервер проверки"}
            <span class="mono">{c.targets.join(", ")}</span>
          </p>
        {/if}
      {/if}
    </div>
  {/if}
</section>

<style>
  .check {
    display: grid;
    gap: 12px;
    width: 100%;
    min-width: 0;
    padding: 12px;
    border: 1px solid var(--line);
    border-radius: var(--r-panel);
    background: var(--surface);
  }

  /* Итог есть: карточка обведена его цветом по всему контуру. */
  .check.has {
    border-color: var(--tone);
  }

  .check:has(.v-leak) {
    background: var(--leak-bg);
  }

  .go {
    width: 100%;
    min-height: 40px;
  }

  /* Недоступная кнопка сбрасывает фон: штриховку «выполняется» возвращаем. */
  .go.running:disabled {
    background-image: repeating-linear-gradient(
      -45deg,
      transparent 0 6px,
      color-mix(in srgb, currentColor 16%, transparent) 6px 12px
    );
    background-size: 34px 100%;
  }

  .res {
    display: grid;
    gap: 10px;
    padding: 0 2px;
    text-align: left;
  }

  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .what {
    display: grid;
    gap: 2px;
    min-width: 0;
  }

  .verdict {
    font: 650 20px/1.2 var(--font-display);
  }

  .about {
    overflow-wrap: anywhere;
  }

  .about::first-letter {
    text-transform: uppercase;
  }

  .line {
    color: var(--ink-2);
  }

  .v-blocked .verdict {
    color: var(--guard);
  }

  .v-leak .verdict {
    color: var(--leak);
  }

  .v-leak .line {
    color: var(--ink);
    font-weight: 600;
  }

  .findings {
    display: grid;
    gap: 2px;
    overflow-wrap: anywhere;
  }

  .matrix {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  .matrix th,
  .matrix td {
    padding: 6px 8px 6px 0;
    border-top: 1px solid var(--line);
    text-align: left;
    font-weight: 400;
  }

  .matrix thead th {
    border-top: 0;
    padding-top: 0;
    font-size: 12px;
    color: var(--ink-2);
  }

  .cell {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 4px;
    font-size: 12px;
  }

  .o-blocked {
    background: var(--guard-bg);
    color: var(--guard);
  }

  .o-leak {
    background: var(--leak);
    color: var(--on-ink);
    font-weight: 650;
  }

  .o-unsure {
    outline: 1px dashed var(--ink-2);
    outline-offset: -1px;
    color: var(--ink-2);
  }

  .skip,
  .skip th {
    color: var(--ink-2);
    font-size: 12px;
  }
</style>
