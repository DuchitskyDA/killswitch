<script lang="ts">
  import type { Config, Profile, Program } from "../lib/api";
  import {
    addItem,
    addTrust,
    baseName,
    clientTitle,
    clientUnset,
    DNS_MODES,
    dnsTitle,
    effective,
    inherit,
    overridden,
    pickerRows,
    removeItem,
    removeTrust,
    setDnsMode,
    setHealth,
    setProfile,
    setStrict,
    trustTo,
    type Inherited,
    type ListKey,
    type SectionId,
    type TrustTo,
  } from "../lib/settings";
  import Icon from "./Icon.svelte";

  // Редактор одного пункта настроек: поля с примером в самом поле. Правка уходит наверх функцией над черновиком.
  let {
    id,
    draft,
    profiles,
    repairOk,
    trustKinds,
    invalid = false,
    findNote = "",
    running = null,
    runningError = "",
    adder = null,
    picked = [],
    onedit,
    onfind,
    onrunning,
  }: {
    id: Exclude<SectionId, "lan">;
    draft: Config;
    profiles: Profile[];
    /** Починка есть на этой ОС. */
    repairOk: boolean;
    /** Виды доверенных на этой ОС. */
    trustKinds: string[];
    /** Сохранение отвергнуто из-за этого пункта. */
    invalid?: boolean;
    /** Итог поиска клиента. */
    findNote?: string;
    /** Запущенные программы; null — список ещё читается. */
    running?: Program[] | null;
    runningError?: string;
    /** «Закрыты в починке»: открытый способ добавить программу и отмеченные среди запущенных. */
    adder?: "name" | "running" | "path" | null;
    picked?: string[];
    onedit: (change: (c: Config) => Config) => void;
    onfind: () => void;
    onrunning: () => void;
  } = $props();

  const OTHER = "*";
  const kindTitle: Record<string, string> = { program: "Программа", user: "Пользователь", cgroup: "Группа cgroup", mark: "Метка" };
  const kindExample: Record<string, string> = {
    program: "C:\\Program Files\\WireGuard\\wireguard.exe",
    user: "root",
    cgroup: "system.slice/tunnel.service",
    mark: "0x2a",
  };
  const toTitle: Record<TrustTo, string> = { any: "куда угодно", endpoints: "только к серверам туннеля" };

  /** Текст в поле добавления. */
  let text = $state("");
  let query = $state("");
  let kindPick = $state("");
  let toPick = $state<TrustTo>("any");

  const s = $derived(effective(draft, profiles));
  const rows = $derived(running ? pickerRows(running, s, query) : []);

  const kind = $derived(kindPick || trustKinds[0] || "program");
  const to = $derived<TrustTo>(s.strict ? "endpoints" : toPick);

  function put(key: ListKey) {
    onedit((c) => addItem(c, profiles, key, text));
    text = "";
  }

  function putTrust() {
    onedit((c) => addTrust(c, profiles, { kind, value: text, to }));
    text = "";
  }

  function pickClient(e: Event & { currentTarget: HTMLSelectElement }) {
    const name = e.currentTarget.value;
    onedit((c) => setProfile(c, profiles, name === OTHER ? "" : name));
  }

  function open(next: typeof adder) {
    adder = adder === next ? null : next;
    text = "";
    if (adder === "running") {
      picked = [];
      query = "";
      onrunning();
    }
  }

  function toggle(name: string) {
    picked = picked.includes(name) ? picked.filter((n) => n !== name) : [...picked, name];
  }

  function putPicked() {
    const names = picked;
    onedit((c) => names.reduce((acc, name) => addItem(acc, profiles, "names", name), c));
    adder = null;
    picked = [];
  }

  const enter = (run: () => void) => (e: KeyboardEvent) => {
    if (e.key === "Enter") run();
  };
</script>

{#snippet list(key: ListKey)}
  {#if s[key].length}
    <ul class="items">
      {#each s[key] as v (v)}
        <li>
          <span class="mono">{v}</span>
          <button class="x" aria-label="Убрать {v}" onclick={() => onedit((c) => removeItem(c, profiles, key, v))}>
            <Icon name="remove" size={14} />
          </button>
        </li>
      {/each}
    </ul>
  {/if}
{/snippet}

{#snippet add(key: ListKey, example: string, label: string, bad = false)}
  <div class="row">
    <input
      class="field mono"
      bind:value={text}
      placeholder={example}
      aria-label={label}
      aria-invalid={bad}
      onkeydown={enter(() => put(key))}
    />
    <button class="btn" onclick={() => put(key)}>Добавить</button>
  </div>
{/snippet}

{#snippet asProfile(key: Inherited)}
  {#if overridden(draft, profiles, key)}
    <button class="link small own" onclick={() => onedit((c) => inherit(c, key))}>Как в профиле</button>
  {/if}
{/snippet}

<div class="ed">
  {#if id === "client"}
    <div class="row">
      <select
        class="field"
        aria-label="Клиент туннеля"
        value={s.profile || (clientUnset(s) ? "" : OTHER)}
        onchange={pickClient}
      >
        {#if clientUnset(s)}<option value="" disabled>Не выбран</option>{/if}
        {#each profiles as p (p.name)}<option value={p.name}>{clientTitle(profiles, p.name)}</option>{/each}
        {#if s.profile && !profiles.some((p) => p.name === s.profile)}<option value={s.profile}>{s.profile}</option>{/if}
        <option value={OTHER}>Другой</option>
      </select>
      <button class="btn" onclick={onfind}>Найти</button>
    </div>
    {#if findNote}<p class="muted small">{findNote}</p>{/if}
    <div class="label-row">
      <h3 class="label">Адаптеры туннеля</h3>
      {@render asProfile("interfaces")}
    </div>
    {@render list("interfaces")}
    {@render add("interfaces", "WireGuard Tunnel*", "Адаптер туннеля", invalid)}
  {:else if id === "dns"}
    <div class="radios" role="radiogroup" aria-label="DNS мимо туннеля">
      {#each DNS_MODES as m (m)}
        <label class="radio">
          <input type="radio" name="dns" checked={s.dns === m} onchange={() => onedit((c) => setDnsMode(c, m))} />
          <span>{dnsTitle[m]}</span>
        </label>
        {#if m === "tunnel-up" && s.dns === m}
          <div class="nested">
            <input
              class="field mono"
              value={s.health}
              placeholder="http://10.8.0.1:80/"
              aria-label="Адрес проверки туннеля"
              aria-invalid={invalid}
              oninput={(e) => onedit((c) => setHealth(c, e.currentTarget.value))}
            />
          </div>
        {/if}
        {#if m === "resolvers" && s.dns === m}
          <div class="nested">
            {@render list("resolvers")}
            {@render add("resolvers", "1.1.1.1", "Сервер DNS", invalid)}
          </div>
        {/if}
      {/each}
    </div>
  {:else if id === "strict"}
    <div class="toggle">
      <button
        class="switch"
        role="switch"
        aria-checked={s.strict}
        aria-label="Строгий режим"
        onclick={() => onedit((c) => setStrict(c, !s.strict))}
      ></button>
      <span>Доверенным — только к серверам туннеля</span>
    </div>
    <h3 class="label">Серверы туннеля</h3>
    {@render list("endpoints")}
    {@render add("endpoints", "203.0.113.5:51820/udp", "Сервер туннеля", invalid)}
  {:else if id === "trusted"}
    {#if s.trust.length}
      <ul class="items">
        {#each s.trust as t (t.kind + " " + t.value)}
          <li>
            <span class="two">
              <span class="mono">{t.value}</span>
              <span class="muted small">
                {trustKinds.length > 1 ? `${kindTitle[t.kind] ?? t.kind} · ` : ""}{toTitle[trustTo(t, s.strict)]}
              </span>
            </span>
            <button class="x" aria-label="Убрать {t.value}" onclick={() => onedit((c) => removeTrust(c, profiles, t))}>
              <Icon name="remove" size={14} />
            </button>
          </li>
        {/each}
      </ul>
    {/if}
    {@render asProfile("trust")}
    <div class="row wrap">
      <input
        class="field mono"
        bind:value={text}
        placeholder={kindExample[kind] ?? ""}
        aria-label={kindTitle[kind] ?? kind}
        aria-invalid={invalid}
        onkeydown={enter(putTrust)}
      />
      {#if trustKinds.length > 1}
        <select class="field" aria-label="Вид доверенного" value={kind} onchange={(e) => (kindPick = e.currentTarget.value)}>
          {#each trustKinds as k (k)}<option value={k}>{kindTitle[k] ?? k}</option>{/each}
        </select>
      {/if}
      <select
        class="field"
        aria-label="Куда можно"
        value={to}
        onchange={(e) => (toPick = e.currentTarget.value === "endpoints" ? "endpoints" : "any")}
      >
        <option value="any" disabled={s.strict}>Куда угодно</option>
        <option value="endpoints">Только к серверам туннеля</option>
      </select>
      <button class="btn" onclick={putTrust}>Добавить</button>
    </div>
  {:else if id === "repair"}
    {#if repairOk}
      {#if s.names.length || s.programs.length}
        <ul class="items">
          {#each s.names as name (name)}
            <li>
              <span class="two">
                <strong>{name}</strong>
                <span class="muted small">по имени</span>
              </span>
              <button class="x" aria-label="Убрать {name}" onclick={() => onedit((c) => removeItem(c, profiles, "names", name))}>
                <Icon name="remove" size={14} />
              </button>
            </li>
          {/each}
          {#each s.programs as path (path)}
            <li>
              <span class="two">
                <strong>{baseName(path)}</strong>
                <span class="mono muted small">{path}</span>
              </span>
              <button
                class="x"
                aria-label="Убрать {baseName(path)}"
                onclick={() => onedit((c) => removeItem(c, profiles, "programs", path))}
              >
                <Icon name="remove" size={14} />
              </button>
            </li>
          {/each}
        </ul>
      {/if}
      {@render asProfile("programs")}
      <div class="adders" role="group" aria-label="Добавить программу">
        <button class="btn" class:pressed={adder === "name"} aria-pressed={adder === "name"} onclick={() => open("name")}>
          По имени
        </button>
        <button
          class="btn"
          class:pressed={adder === "running"}
          aria-pressed={adder === "running"}
          onclick={() => open("running")}
        >
          Из запущенных
        </button>
        <button class="btn" class:pressed={adder === "path"} aria-pressed={adder === "path"} onclick={() => open("path")}>
          Указать путь
        </button>
      </div>
      {#if adder === "name"}
        {@render add("names", "chrome", "Имя программы", invalid)}
      {:else if adder === "path"}
        {@render add("programs", "C:\\Program Files\\App\\app.exe", "Путь программы", invalid)}
      {:else if adder === "running"}
        <div class="picker">
          <div class="search">
            <Icon name="search" />
            <input class="field" bind:value={query} placeholder="chrome" aria-label="Поиск среди запущенных" />
          </div>
          {#if running === null}
            <p class="muted small" aria-busy="true">Читаю список программ…</p>
          {:else if runningError}
            <p class="err small">{runningError}</p>
          {:else if rows.length === 0}
            <p class="muted small">Ничего не найдено</p>
          {:else}
            <ul class="running-list">
              {#each rows as p (p.name)}
                <li class:added={p.added}>
                  <label>
                    <input
                      type="checkbox"
                      checked={p.added || picked.includes(p.name)}
                      disabled={p.added}
                      onchange={() => toggle(p.name)}
                    />
                    <strong>{p.name}</strong>
                  </label>
                  {#if p.added}<span class="tag">в списке</span>{/if}
                </li>
              {/each}
            </ul>
          {/if}
          <div class="row end">
            <button class="btn btn-quiet" onclick={() => open("running")}>Отмена</button>
            <button class="btn btn-primary" disabled={picked.length === 0} onclick={putPicked}>
              Добавить: {picked.length}
            </button>
          </div>
        </div>
      {/if}
    {:else}
      <p class="muted">Только в Windows</p>
    {/if}
  {:else if id === "targets"}
    {@render list("targets")}
    {@render add("targets", "198.51.100.20", "Адрес сервера проверки", invalid)}
  {/if}
</div>

<style>
  .ed,
  .nested,
  .picker {
    display: grid;
    gap: 8px;
    min-width: 0;
  }

  .label-row {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 8px;
    margin-top: 6px;
  }

  .label {
    margin-top: 6px;
    font: 600 12px/1.3 var(--font-ui);
    color: var(--ink-2);
  }

  .label-row .label {
    margin-top: 0;
  }

  .own {
    justify-self: start;
    color: var(--ink-2);
  }

  .row {
    display: flex;
    gap: 8px;
    min-width: 0;
  }

  .row .field {
    flex: 1;
    min-width: 0;
  }

  .row .btn {
    flex: none;
  }

  .row.wrap {
    flex-wrap: wrap;
  }

  .row.wrap .field:first-child {
    flex-basis: 100%;
  }

  .row.end {
    justify-content: flex-end;
  }

  .items {
    display: grid;
    border: 1px solid var(--line);
    border-radius: var(--r-control);
    font-size: 13px;
  }

  .items li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    min-height: 36px;
    padding: 6px 6px 6px 10px;
    border-top: 1px solid var(--line);
  }

  .items li:first-child {
    border-top: 0;
  }

  .two {
    display: grid;
    flex: 1;
    gap: 2px;
    min-width: 0;
  }

  .err {
    color: var(--leak);
    font-weight: 600;
  }

  .x {
    display: grid;
    place-items: center;
    flex: none;
    width: 24px;
    height: 24px;
    border: 0;
    border-radius: 4px;
    background: none;
    color: var(--ink-2);
    cursor: pointer;
  }

  .toggle,
  .radio,
  .running-list label {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 600;
  }

  .radio,
  .running-list label {
    cursor: pointer;
  }

  .radios {
    display: grid;
    gap: 10px;
  }

  .radio input,
  .running-list input {
    flex: none;
    width: 16px;
    height: 16px;
    margin: 0;
    accent-color: var(--ink);
  }

  .nested {
    margin-left: 26px;
  }

  .adders {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .adders .btn {
    flex: 1 1 auto;
  }

  .btn.pressed {
    border-color: var(--ink);
    box-shadow: inset 0 0 0 1px var(--ink);
  }

  .picker {
    padding: 10px;
    border: 1px solid var(--ink);
    border-radius: var(--r-control);
    background: var(--surface-2);
  }

  .search {
    position: relative;
    display: flex;
    align-items: center;
  }

  .search :global(.icon) {
    position: absolute;
    left: 10px;
    color: var(--ink-2);
  }

  .search .field {
    padding-left: 32px;
    background: var(--surface);
  }

  .running-list {
    display: grid;
    font-size: 13px;
  }

  .running-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    min-height: 32px;
    border-top: 1px solid var(--line);
  }

  .running-list li:first-child {
    border-top: 0;
  }

  .added {
    color: var(--ink-2);
  }
</style>
