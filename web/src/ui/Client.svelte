<script lang="ts">
  import type { Profile } from "../lib/api";
  import { clientTitle } from "../lib/settings";

  // Первый запуск: одна строка с найденным клиентом туннеля; не найден — выбор из списка.
  let {
    profiles,
    chosen,
    seeking = false,
    onchoose,
    onfind,
    onother,
  }: {
    profiles: Profile[];
    /** Выбранный клиент; null — ещё не выбран. */
    chosen: string | null;
    /** Идёт поиск клиента. */
    seeking?: boolean;
    onchoose: (name: string) => void;
    onfind: () => void;
    /** «Другой»: адаптеры задаются в настройках. */
    onother: () => void;
  } = $props();

  const OTHER = "*";
  let changing = $state(false);

  function pick(e: Event & { currentTarget: HTMLSelectElement }) {
    const name = e.currentTarget.value;
    if (name === OTHER) return onother();
    changing = false;
    onchoose(name);
  }
</script>

{#if seeking}
  <p class="client muted" aria-busy="true">Ищу клиент туннеля…</p>
{:else if chosen !== null && !changing}
  <p class="client">
    <span class="muted">Клиент туннеля</span>
    <b>{clientTitle(profiles, chosen)}</b>
    <button class="link small" onclick={() => (changing = true)}>Изменить</button>
  </p>
{:else}
  <div class="client pick">
    <p>{chosen === null ? "Клиент туннеля не найден" : "Клиент туннеля"}</p>
    <div class="row">
      <select class="field" aria-label="Клиент туннеля" value={chosen ?? ""} onchange={pick}>
        {#if chosen === null}<option value="" disabled>Выберите клиент</option>{/if}
        {#each profiles as p (p.name)}<option value={p.name}>{clientTitle(profiles, p.name)}</option>{/each}
        <option value={OTHER}>Другой</option>
      </select>
      <button class="btn" onclick={onfind}>Найти снова</button>
    </div>
  </div>
{/if}

<style>
  .client {
    text-align: center;
  }

  p.client {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    justify-content: center;
    gap: 6px;
  }

  b {
    font-weight: 650;
  }

  .pick {
    display: grid;
    gap: 8px;
    width: 100%;
    max-width: 340px;
  }

  .row {
    display: flex;
    gap: 8px;
  }

  .row .btn {
    flex: none;
    white-space: nowrap;
  }
</style>
