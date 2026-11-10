<script lang="ts">
  import type { AppState, Profile } from "../lib/api";
  import type { CheckView } from "../lib/check";
  import { faceOf, kindOf, type Busy, type Kind, type Link } from "../lib/screen";
  import Check from "./Check.svelte";
  import Client from "./Client.svelte";
  import Icon from "./Icon.svelte";
  import ModeSwitch from "./ModeSwitch.svelte";
  import Notes from "./Notes.svelte";
  import Power from "./Power.svelte";
  import Tunnel from "./Tunnel.svelte";

  // Главный экран, одна колонка: кнопка питания со словом состояния внутри, под ней туннель и режим, внизу проверка.
  // Без настроек он же — первый запуск: вместо туннеля — выбор клиента.
  let {
    link,
    status,
    busy = null,
    pick = "full",
    error = "",
    report = null,
    details = false,
    profiles = [],
    chosen = null,
    seeking = false,
    onpower,
    onkind,
    oncheck,
    ondetails,
    onretry,
    onchoose,
    onfind,
    onother,
  }: {
    link: Link;
    status: AppState | null;
    busy?: Busy | null;
    /** Положение переключателя режима, выбранное при выключенной защите. */
    pick?: Kind;
    /** Ошибка действия или чтения состояния. */
    error?: string;
    report?: CheckView | null;
    /** «Подробнее» у итога проверки раскрыто. */
    details?: boolean;
    /** Первый запуск: клиенты туннеля, выбранный и идёт ли поиск. */
    profiles?: Profile[];
    chosen?: string | null;
    seeking?: boolean;
    onpower: () => void;
    onkind: (kind: Kind) => void;
    oncheck: () => void;
    ondetails: () => void;
    onretry: () => void;
    onchoose: (name: string) => void;
    onfind: () => void;
    onother: () => void;
  } = $props();

  const face = $derived(faceOf(link, status, busy));
  const live = $derived(link === "ok" && status !== null);
  const first = $derived(live && status !== null && !status.configured);
  const acting = $derived(busy === "on" || busy === "off");
  const stopped = $derived(face.power === "disabled");
</script>

<div class="main">
  <header class="bar">
    <a class="gear" href="#settings" aria-label="Настройки"><Icon name="gear" size={22} /></a>
  </header>

  <div class="hero">
    <Power {face} busy={acting} blocked={first && chosen === null} onpress={onpower} />

    {#if link === "lost"}
      <div class="note note-leak stop">
        <p class="stop-word">{face.word}</p>
        <button class="btn" onclick={onretry}>Повторить</button>
      </div>
    {:else if link === "closed"}
      <div class="note stop">
        <p class="stop-word calm">{face.word}</p>
        <p class="small">{face.advice}</p>
      </div>
    {:else if !live || status === null}
      <span class="skeleton line" aria-hidden="true"></span>
    {:else if first}
      <Client {profiles} {chosen} {seeking} {onchoose} {onfind} {onother} />
    {:else}
      <Tunnel tunnels={status.tunnels} />
    {/if}

    {#if live && status !== null}
      <Notes warnings={status.warnings} />
      {#if error}<p class="note note-leak small fail">{error}</p>{/if}
    {/if}

    {#if !first}
      <ModeSwitch
        kind={status ? kindOf(status, pick) : "full"}
        repairOk={status?.capabilities.repair ?? true}
        disabled={stopped || acting}
        {onkind}
      />
    {/if}
  </div>

  {#if !first}
    <Check
      view={stopped ? null : report}
      open={details}
      busy={busy === "check"}
      disabled={stopped || acting}
      {oncheck}
      ontoggle={ondetails}
    />
  {/if}
</div>

<style>
  .main {
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 460px;
    min-height: var(--fill);
    margin: 0 auto;
  }

  .bar {
    display: flex;
    align-items: center;
    min-height: 36px;
  }

  .gear {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    margin-left: -6px;
    border-radius: var(--r-control);
    color: var(--ink);
  }

  .gear:hover {
    background: var(--surface-2);
  }

  /* Кнопка с подписями — посередине свободного места. */
  .hero {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 14px;
    min-width: 0;
    padding-bottom: 8px;
  }

  .hero > :global(.note) {
    max-width: 100%;
  }

  .hero > :global(.seg) {
    margin-top: 6px;
  }

  .stop {
    display: grid;
    justify-items: center;
    gap: 6px;
    min-width: 280px;
    padding: 12px 16px;
    text-align: center;
  }

  .stop-word {
    font: 650 18px/1.25 var(--font-display);
    color: var(--leak);
  }

  .calm {
    color: var(--ink);
  }

  .fail {
    overflow-wrap: anywhere;
  }

  .fail::first-letter {
    text-transform: uppercase;
  }

  .line {
    width: 180px;
    height: 20px;
  }
</style>
