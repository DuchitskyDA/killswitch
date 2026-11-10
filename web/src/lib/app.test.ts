// Разговор страницы с сервером окна: что она считает связью и когда перечитывает настройки. Сеть — подставной fetch.

import { afterEach, describe, expect, test, vi } from "vitest";

import { render } from "svelte/server";

import SettingsBody from "../ui/SettingsBody.svelte";
import { Store } from "./app.svelte";
import { errorSection, setLan } from "./settings";

type Reply = { status?: number; body?: unknown; broken?: boolean; gate?: Promise<void> };

/** Подставной сервер: ответ по «МЕТОД путь»; broken — тело оборвалось после заголовков; gate — ответ ждёт. */
function serve(replies: Record<string, Reply>) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (path: string, init?: RequestInit) => {
    const key = `${init?.method ?? "GET"} ${path}`;
    calls.push(key);
    const r = replies[key];
    if (r === undefined) throw new TypeError("нет связи");
    await r.gate;
    const status = r.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => {
        if (r.broken) throw new TypeError("тело оборвалось");
        return r.body;
      },
    };
  });
  return calls;
}

const state = { os: "windows", configured: true, mode: "on", active: true, tunnels: [], warnings: [], capabilities: {} };
const clients = { profiles: [] };

afterEach(() => vi.unstubAllGlobals());

describe("связь с сервером окна", () => {
  test("ответ пришёл — связь есть", async () => {
    serve({ "GET /api/state": { body: state } });
    const app = new Store();
    await app.poll();
    expect(app.link).toBe("ok");
    expect(app.status?.configured).toBe(true);
  });

  test("тело ответа оборвалось — «Нет связи», а не первый запуск", async () => {
    serve({ "GET /api/state": { broken: true } });
    const app = new Store();
    await app.poll();
    expect(app.link).toBe("lost");
    expect(app.status).toBeNull();
  });

  test("401 — сеанса больше нет: окно закрыто, опрос больше не идёт", async () => {
    const calls = serve({ "GET /api/state": { status: 401, body: { error: "нет сеанса" } } });
    const app = new Store();
    await app.poll();
    expect(app.link).toBe("closed");
    await app.poll();
    expect(calls).toHaveLength(1);
  });

  test("401 без JSON — тоже окно закрыто", async () => {
    serve({ "GET /api/state": { status: 401, broken: true } });
    const app = new Store();
    await app.poll();
    expect(app.link).toBe("closed");
  });

  test("401 на действие — окно закрыто", async () => {
    const replies: Record<string, Reply> = { "GET /api/state": { body: state } };
    serve(replies);
    const app = new Store();
    await app.poll();
    replies["POST /api/mode"] = { status: 401, body: { error: "нет сеанса" } };
    await app.power();
    expect(app.link).toBe("closed");
  });

  test("окно закрыто — поздний ответ раньше начатого запроса связь не возвращает", async () => {
    let release = () => {};
    const gate = new Promise<void>((done) => (release = done));
    serve({
      "GET /api/state": { body: state, gate },
      "GET /api/config": { status: 401, body: { error: "нет сеанса" } },
      "GET /api/clients": { status: 401, body: { error: "нет сеанса" } },
    });
    const app = new Store();
    const polling = app.poll();
    await app.openSettings();
    expect(app.link).toBe("closed");
    release();
    await polling;
    expect(app.link).toBe("closed");
  });

  test("окно закрыто — поздний обрыв раньше начатого запроса не превращает его в «Нет связи»", async () => {
    let release = () => {};
    const gate = new Promise<void>((done) => (release = done));
    serve({
      "GET /api/state": { broken: true, gate },
      "GET /api/config": { status: 401, body: { error: "нет сеанса" } },
      "GET /api/clients": { status: 401, body: { error: "нет сеанса" } },
    });
    const app = new Store();
    const polling = app.poll();
    await app.openSettings();
    release();
    await polling;
    expect(app.link).toBe("closed");
  });

  test("401 на сигнал жизни — окно закрыто", async () => {
    serve({ "GET /api/state": { body: state }, "POST /api/alive": { status: 401, body: { error: "нет сеанса" } } });
    const app = new Store();
    await app.poll();
    await app.alive();
    expect(app.link).toBe("closed");
  });

  test("сигнал жизни дошёл — связь как была", async () => {
    serve({ "GET /api/state": { body: state }, "POST /api/alive": { body: {} } });
    const app = new Store();
    await app.poll();
    await app.alive();
    expect(app.link).toBe("ok");
  });

  test("403 — «Нет связи»", async () => {
    serve({ "GET /api/state": { status: 403, body: { error: "чужая страница" } } });
    const app = new Store();
    await app.poll();
    expect(app.link).toBe("lost");
  });

  test("настройки с оборванным телом не считаются прочитанными", async () => {
    serve({ "GET /api/config": { broken: true }, "GET /api/clients": { body: clients } });
    const app = new Store();
    await app.openSettings();
    expect(app.settings).not.toBe("ready");
  });
});

describe("чтение настроек", () => {
  test("файл не читается — строка ошибки сервера; «Повторить» читает заново", async () => {
    const replies: Record<string, Reply> = {
      "GET /api/config": { status: 500, body: { error: "config.toml: строка 12: ожидалось значение" } },
      "GET /api/clients": { body: clients },
    };
    serve(replies);
    const app = new Store();
    await app.openSettings();
    expect(app.settings).toBe("error");
    expect(app.readError).toBe("config.toml: строка 12: ожидалось значение");

    replies["GET /api/config"] = { body: { profile: "wireguard" } };
    await app.openSettings();
    expect(app.settings).toBe("ready");
    expect(app.readError).toBe("");
    expect(app.saved.profile).toBe("wireguard");
  });
});

describe("ошибка сохранения", () => {
  test("пункт по тексту не определить — ошибка всё равно стоит строкой у «Применить и сохранить»", async () => {
    const text = "не сохранено: неизвестная беда";
    serve({
      "GET /api/config": { body: { profile: "wireguard", lan: true } },
      "GET /api/clients": { body: clients },
      "PUT /api/config": { status: 422, body: { error: text, saved: false } },
    });
    const app = new Store();
    await app.openSettings();
    app.edit((c) => setLan(c, false));
    await app.save();
    expect(errorSection(app.saveError)).toBeNull();

    const noop = () => {};
    const { body } = render(SettingsBody, {
      props: {
        saved: app.saved,
        draft: app.draft,
        profiles: app.clients,
        repairOk: true,
        trustKinds: [],
        selected: "client",
        saveError: app.saveError,
        onedit: noop,
        onsave: noop,
        oncancel: noop,
        onfind: noop,
        onrunning: noop,
        onretry: noop,
      },
    });
    expect(body).toContain(text);
    expect(body.indexOf(text)).toBeLessThan(body.indexOf("Применить и сохранить"));
  });
});

describe("настройки при повторном входе", () => {
  test("без правок — читаются заново: чужое изменение файла не затирается", async () => {
    const replies: Record<string, Reply> = {
      "GET /api/config": { body: { profile: "wireguard", lan: true } },
      "GET /api/clients": { body: clients },
    };
    serve(replies);
    const app = new Store();
    await app.openSettings();

    replies["GET /api/config"] = { body: { profile: "wireguard", lan: false, dns: { mode: "tunnel-up" } } };
    await app.openSettings();
    expect(app.saved.lan).toBe(false);
    expect(app.draft.dns.mode).toBe("tunnel-up");
  });

  test("вошли снова, пока прежнее чтение не кончилось, — его поздний ответ отброшен", async () => {
    let release = () => {};
    const gate = new Promise<void>((done) => (release = done));
    const replies: Record<string, Reply> = {
      "GET /api/config": { body: { profile: "wireguard", lan: true }, gate },
      "GET /api/clients": { body: clients },
    };
    const calls = serve(replies);
    const app = new Store();
    const reading = app.openSettings();

    replies["GET /api/config"] = { body: { profile: "wireguard", lan: false } };
    await app.openSettings();
    release();
    await reading;
    expect(calls.filter((c) => c === "GET /api/config")).toHaveLength(2);
    expect(app.settings).toBe("ready");
    expect(app.saved.lan).toBe(false);
  });

  test("ушли, пока настройки сохранялись, — после сохранения вход читает их заново", async () => {
    let release = () => {};
    const gate = new Promise<void>((done) => (release = done));
    const replies: Record<string, Reply> = {
      "GET /api/config": { body: { profile: "wireguard", lan: true } },
      "GET /api/clients": { body: clients },
      "PUT /api/config": { body: { saved: true, message: "" }, gate },
    };
    const calls = serve(replies);
    const app = new Store();
    await app.openSettings();
    app.edit((c) => setLan(c, false));
    const saving = app.save();
    release();
    await saving;

    replies["GET /api/config"] = { body: { profile: "wireguard", lan: false, dns: { mode: "tunnel-up" } } };
    await app.openSettings();
    expect(calls.filter((c) => c === "GET /api/config")).toHaveLength(2);
    expect(app.draft.dns.mode).toBe("tunnel-up");
  });

  test("с несохранёнными правками — черновик остаётся", async () => {
    const calls = serve({
      "GET /api/config": { body: { profile: "wireguard", lan: true } },
      "GET /api/clients": { body: clients },
    });
    const app = new Store();
    await app.openSettings();
    app.edit((c) => setLan(c, false));
    await app.openSettings();
    expect(app.draft.lan).toBe(false);
    expect(calls.filter((c) => c === "GET /api/config")).toHaveLength(1);
  });
});
