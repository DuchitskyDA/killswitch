// Состояние страницы и её разговор с сервером окна: опрос, переходы, проверка, первый запуск, настройки.
// Решения о том, что показать и что послать, — в screen.ts, check.ts и settings.ts; здесь только порядок вызовов.

import { api, ApiError, parseConfig, type AppState, type Config, type Mode, type Profile, type Program } from "./api";
import { checkView, clock, type CheckView } from "./check";
import { kindOf, powerSends, switchSends, type Busy, type Kind, type Link } from "./screen";
import { changed, firstRunConfig, setProfile } from "./settings";

/** Сеанса больше нет: окно нужно открыть заново, повтор не поможет. */
const closed = (e: unknown) => e instanceof ApiError && e.status === 401;

/** Сервер не ответил или не признал запрос своим: связи нет. */
const lost = (e: unknown) => e instanceof ApiError && (e.status === 0 || e.status === 403);

const textOf = (e: unknown) => (e instanceof ApiError ? e.message || `Ошибка ${e.status}` : String(e));

export class Store {
  #link = $state<Link>("loading");
  /** Связь с сервером окна. Пишется в одном месте: «окно закрыто» — навсегда, без нового сеанса обратно нет. */
  get link(): Link {
    return this.#link;
  }
  #setLink(next: Link) {
    if (this.#link !== "closed") this.#link = next;
  }

  status = $state.raw<AppState | null>(null);
  busy = $state<Busy | null>(null);
  /** Положение переключателя режима при выключенной защите. */
  pick = $state<Kind>("full");
  /** Ошибка последнего действия. */
  error = $state("");
  /** Ошибка чтения состояния; уходит с первым удачным ответом. */
  pollError = $state("");
  report = $state.raw<CheckView | null>(null);
  details = $state(false);

  clients = $state.raw<Profile[]>([]);
  seeking = $state(false);
  /** Клиент, выбранный на первом запуске. */
  chosen = $state<string | null>(null);

  settings = $state<"idle" | "loading" | "ready" | "error">("idle");
  readError = $state("");
  saved = $state.raw<Config>(parseConfig(null));
  draft = $state.raw<Config>(parseConfig(null));
  saving = $state(false);
  saveError = $state("");
  saveNote = $state("");
  findNote = $state("");
  running = $state.raw<Program[] | null>(null);
  runningError = $state("");

  // Номер последнего запроса состояния: ответ более раннего запроса не затирает более поздний.
  #seq = 0;
  #sought = false;

  #accept(s: AppState) {
    this.status = s;
    this.#setLink("ok");
    this.pollError = "";
    this.pick = kindOf(s, this.pick);
    if (!s.configured && !this.#sought) void this.findClients();
  }

  /** Ошибка говорит, что окно не работает: связь потеряна или сеанса больше нет. */
  #down(e: unknown): boolean {
    if (closed(e)) this.#setLink("closed");
    else if (lost(e)) this.#setLink("lost");
    else return false;
    return true;
  }

  /** Опрос состояния. Во время действия не идёт: ответ действия несёт состояние сам. Без сеанса — бесполезен. */
  async poll() {
    if (this.busy !== null || this.link === "closed") return;
    const n = ++this.#seq;
    try {
      const s = await api.state();
      if (n === this.#seq) this.#accept(s);
    } catch (e) {
      if (n !== this.#seq) return;
      if (!this.#down(e)) this.pollError = textOf(e);
    }
  }

  retry() {
    this.#setLink("loading");
    return this.poll();
  }

  /** Сигнал жизни: без него сервер окна завершится. Его отказ говорит о связи то же, что отказ любого запроса. */
  async alive() {
    if (this.link === "closed") return;
    try {
      await api.alive();
    } catch (e) {
      this.#down(e);
    }
  }

  async #act(busy: Busy, run: () => Promise<void>) {
    if (this.busy !== null || this.status === null) return;
    this.busy = busy;
    this.error = "";
    let failed = false;
    try {
      await run();
    } catch (e) {
      failed = true;
      // 409 — настроек нет: свежее состояние ниже покажет первый запуск.
      if (!this.#down(e) && !(e instanceof ApiError && e.status === 409)) this.error = textOf(e);
    } finally {
      this.busy = null;
    }
    if (failed && this.link === "ok") await this.poll();
  }

  #go(mode: Mode) {
    return this.#act(mode === "off" ? "off" : "on", async () => {
      ++this.#seq;
      const s = await api.mode(mode);
      // Итог проверки относился к прежнему режиму.
      this.report = null;
      this.#accept(s);
    });
  }

  power() {
    const s = this.status;
    if (s === null) return;
    return s.configured ? this.#go(powerSends(s, this.pick)) : this.#firstRun();
  }

  /** Переключатель режима: при включённой защите шлёт переход, при выключенной — запоминает положение. */
  setKind(kind: Kind) {
    const s = this.status;
    if (s === null) return;
    const mode = switchSends(s, kind);
    if (mode !== null) return this.#go(mode);
    this.pick = kindOf(s, kind);
  }

  check() {
    return this.#act("check", async () => {
      this.report = checkView(await api.check(), clock(new Date()));
      this.details = false;
      ++this.#seq;
      this.#accept(await api.state());
    });
  }

  // --- первый запуск ---

  async findClients() {
    this.#sought = true;
    this.seeking = true;
    try {
      const list = await api.clients();
      this.clients = list;
      if (this.chosen === null || !list.some((p) => p.name === this.chosen)) {
        this.chosen = list.find((p) => p.detected)?.name ?? null;
      }
    } catch (e) {
      if (!this.#down(e)) this.error = textOf(e);
    } finally {
      this.seeking = false;
    }
  }

  #firstRun() {
    const name = this.chosen;
    if (name === null) return;
    return this.#act("on", async () => {
      await api.save(firstRunConfig(name));
      ++this.#reading;
      this.settings = "idle";
      ++this.#seq;
      this.#accept(await api.mode("on"));
    });
  }

  // --- настройки ---

  /** Номер чтения настроек: ответ чтения, которое сменилось следующим, отбрасывается. */
  #reading = 0;

  /** Вход на экран настроек и «Повторить». Несохранённые правки остаются черновиком; иначе настройки
   *  читаются заново при каждом входе: файл могли изменить мимо страницы. */
  async openSettings() {
    const edited = this.settings === "ready" && changed(this.saved, this.draft, this.clients).length > 0;
    if (edited) return;
    const mine = ++this.#reading;
    this.settings = "loading";
    this.readError = "";
    this.saveError = this.saveNote = this.findNote = "";
    try {
      const [config, clients] = await Promise.all([api.config(), api.clients()]);
      if (mine !== this.#reading) return;
      this.clients = clients;
      this.saved = this.draft = config;
      this.settings = "ready";
    } catch (e) {
      if (mine !== this.#reading) return;
      if (this.#down(e)) {
        this.settings = "idle";
        return;
      }
      this.readError = textOf(e);
      this.saved = this.draft = parseConfig(null);
      this.settings = "error";
    }
  }

  edit(change: (c: Config) => Config) {
    this.draft = change(this.draft);
    this.saveError = this.saveNote = this.findNote = "";
  }

  cancel() {
    this.draft = this.saved;
    this.saveError = this.saveNote = "";
  }

  async save() {
    if (this.saving) return;
    this.saving = true;
    this.saveError = this.saveNote = "";
    const sent = this.draft;
    try {
      await api.save(sent);
      this.saved = sent;
    } catch (e) {
      if (!this.#down(e)) {
        this.saveError = textOf(e);
        // Файл записан, но правила не применились: настройки новые, защита в прежнем состоянии.
        if (e instanceof ApiError && e.saved) {
          this.saved = sent;
          this.saveNote = e.note;
        }
      }
    } finally {
      this.saving = false;
    }
    void this.poll();
  }

  /** «Найти» в настройках: выбрать клиент, найденный на машине. */
  async findInSettings() {
    this.findNote = "";
    try {
      const list = await api.clients();
      this.clients = list;
      const found = list.find((p) => p.detected);
      if (found === undefined) this.findNote = "Клиент туннеля не найден";
      else if (found.name !== this.draft.profile) this.edit((c) => setProfile(c, list, found.name));
    } catch (e) {
      if (!this.#down(e)) this.findNote = textOf(e);
    }
  }

  async loadRunning() {
    this.running = null;
    this.runningError = "";
    try {
      this.running = await api.programs();
    } catch (e) {
      this.running = [];
      this.runningError = this.#down(e) ? "" : textOf(e);
    }
  }
}
