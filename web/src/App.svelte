<script lang="ts">
  import { onMount, untrack } from "svelte";
  import { api } from "./lib/api";
  import { Store } from "./lib/app.svelte";
  import { SECTIONS, type SectionId } from "./lib/settings";
  import Main from "./ui/Main.svelte";
  import SettingsScreen from "./ui/SettingsScreen.svelte";

  // Страница окна: главный экран и настройки (#settings, #settings/<пункт>), опрос состояния и сигнал жизни.
  type Detail = Exclude<SectionId, "lan">;

  const POLL_MS = 5_000;
  const ALIVE_MS = 20_000;

  const app = new Store();

  function parse(hash: string): { settings: boolean; detail: Detail | null } {
    const [page, section] = hash.replace(/^#/, "").split("/");
    const detail = SECTIONS.find((id): id is Detail => id === section && id !== "lan");
    return { settings: page === "settings", detail: detail ?? null };
  }

  let route = $state(parse(location.hash));

  function onhash() {
    route = parse(location.hash);
  }

  // Один раз на страницу: таймеры не зависят от состояния и не перезапускаются при его смене.
  onMount(() => {
    void app.poll();
    const poll = setInterval(() => void app.poll(), POLL_MS);
    // Сигнал жизни идёт и во время долгой проверки: без него сервер окна завершится.
    const alive = setInterval(() => void app.alive(), ALIVE_MS);
    const onshow = () => {
      if (document.visibilityState === "visible") void app.poll();
    };
    document.addEventListener("visibilitychange", onshow);
    window.addEventListener("pagehide", api.closing);
    return () => {
      clearInterval(poll);
      clearInterval(alive);
      document.removeEventListener("visibilitychange", onshow);
      window.removeEventListener("pagehide", api.closing);
    };
  });

  // Без связи и без сеанса настройки не показать: остаётся главный экран с этим состоянием.
  const shown = $derived(route.settings && (app.link === "ok" || app.link === "loading"));
  // Каждый вход на экран настроек при живой связи (и её возврат) открывает настройки заново.
  const entered = $derived(route.settings && app.link === "ok");
  $effect(() => {
    if (entered) untrack(() => void app.openSettings());
  });
</script>

<svelte:window onhashchange={onhash} />

<main class="window">
  <div class="cq">
    {#if shown}
      <SettingsScreen
        saved={app.saved}
        draft={app.draft}
        profiles={app.clients}
        repairOk={app.status?.capabilities.repair ?? false}
        trustKinds={app.status?.capabilities.trust_kinds ?? []}
        selected={route.detail ?? "client"}
        opened={route.detail !== null}
        view={app.settings === "ready" ? "ready" : app.settings === "error" ? "error" : "loading"}
        readError={app.readError}
        saving={app.saving}
        saveError={app.saveError}
        saveNote={app.saveNote}
        findNote={app.findNote}
        running={app.running}
        runningError={app.runningError}
        onedit={(change) => app.edit(change)}
        onsave={() => void app.save()}
        oncancel={() => app.cancel()}
        onfind={() => void app.findInSettings()}
        onrunning={() => void app.loadRunning()}
        onretry={() => void app.openSettings()}
      />
    {:else}
      <Main
        link={app.link}
        status={app.status}
        busy={app.busy}
        pick={app.pick}
        error={app.error || app.pollError}
        report={app.report}
        details={app.details}
        profiles={app.clients}
        chosen={app.chosen}
        seeking={app.seeking}
        onpower={() => void app.power()}
        onkind={(kind) => void app.setKind(kind)}
        oncheck={() => void app.check()}
        ondetails={() => (app.details = !app.details)}
        onretry={() => void app.retry()}
        onchoose={(name) => (app.chosen = name)}
        onfind={() => void app.findClients()}
        onother={() => (location.hash = "settings/client")}
      />
    {/if}
  </div>
</main>
