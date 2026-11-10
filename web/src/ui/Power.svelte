<script lang="ts">
  import type { Face } from "../lib/screen";
  import Icon from "./Icon.svelte";

  // Кнопка питания в кольце цвета состояния: включает и выключает защиту. Главный элемент окна.
  let {
    face,
    busy = false,
    blocked = false,
    onpress,
  }: {
    face: Face;
    /** Действие выполняется: кольцо движется. */
    busy?: boolean;
    /** Нажимать пока нечего: например, клиент туннеля не выбран. */
    blocked?: boolean;
    onpress: () => void;
  } = $props();

  const on = $derived(face.power === "on");
</script>

<button
  class="power tone-{face.tone}"
  class:on
  class:alert={face.alert}
  class:busy
  disabled={face.power === "disabled" || blocked || busy}
  aria-pressed={on}
  aria-busy={busy}
  aria-label={on ? "Выключить защиту" : "Включить защиту"}
  onclick={onpress}
>
  <span class="core">
    <Icon name="power" size={30} />
    {#each face.inside as line (line)}<span class="word">{line}</span>{/each}
    {#if face.sub}<span class="sub">{face.sub}</span>{/if}
  </span>
</button>

<style>
  .power {
    --ring: var(--line);
    --ring-w: 1.5px;
    --halo: var(--surface-2);
    --glyph: var(--ink-2);

    position: relative;
    display: grid;
    place-items: center;
    flex: none;
    width: 188px;
    height: 188px;
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: none;
    cursor: pointer;
  }

  .power.on {
    --ring: var(--tone);
    --ring-w: 3px;
    --halo: var(--tone-bg);
    --glyph: var(--tone);
  }

  .power.alert {
    --ring: var(--tone);
    --ring-w: 3px;
  }

  /* Кольцо. */
  .power::before {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: 50%;
    background: var(--ring);
    mask: radial-gradient(farthest-side, transparent calc(100% - var(--ring-w)), #000 calc(100% - var(--ring-w) + 0.5px));
  }

  /* Поле между кольцом и кнопкой. */
  .power::after {
    content: "";
    position: absolute;
    inset: 9px;
    border-radius: 50%;
    background: var(--halo);
  }

  .core {
    position: relative;
    z-index: 1;
    display: grid;
    place-content: center;
    justify-items: center;
    gap: 3px;
    width: calc(100% - 44px);
    height: calc(100% - 44px);
    border: 1px solid var(--line);
    border-radius: 50%;
    background: var(--surface);
    box-shadow: 0 8px 18px -8px rgb(0 0 0 / 0.28);
    color: var(--glyph);
    transition: box-shadow 120ms;
  }

  .power.on .core {
    border-color: color-mix(in srgb, var(--tone) 45%, var(--line));
  }

  .power:hover:not(:disabled) .core {
    box-shadow: 0 10px 22px -8px rgb(0 0 0 / 0.36);
  }

  .core :global(.icon) {
    margin-bottom: 3px;
  }

  .word {
    font: 650 13px/1.2 var(--font-ui);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--tone);
  }

  .sub {
    font-size: 12px;
    line-height: 1.2;
    color: var(--ink-2);
  }

  .power:disabled {
    cursor: not-allowed;
  }

  .power:disabled:not(.busy) .core {
    background: var(--surface-2);
    box-shadow: none;
    color: var(--line);
  }

  /* Выполняется: по кольцу бежит дуга. */
  .power.busy {
    cursor: progress;
  }

  .power.busy::before {
    --ring-w: 3px;
    background: conic-gradient(var(--ink) 0 28%, var(--line) 28% 100%);
    animation: turn 900ms linear infinite;
  }

  @keyframes turn {
    to {
      transform: rotate(1turn);
    }
  }
</style>
