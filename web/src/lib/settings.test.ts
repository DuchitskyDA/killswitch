import { describe, expect, test } from "vitest";

import { parseClients, parseConfig, parsePrograms } from "./api";
import {
  addItem,
  addTrust,
  changed,
  clientTitle,
  effective,
  errorSection,
  firstRunConfig,
  inherit,
  overridden,
  pickerRows,
  removeItem,
  removeTrust,
  sectionValue,
  setDnsMode,
  setHealth,
  setLan,
  setProfile,
  setStrict,
  trimExe,
  trustTo,
} from "./settings";

const client = "C:\\Program Files\\Tunnel\\client.exe";

// Ответ GET /api/clients, как его отдаёт сервер.
const profiles = parseClients({
  profiles: [
    {
      name: "wireguard",
      description: "WireGuard: адаптер WireGuard Tunnel / wg* / utun*",
      detected: true,
      interfaces: ["WireGuard Tunnel*"],
      trust: [{ kind: "program", value: client, destinations: "" }],
      repair_programs: [],
    },
    {
      name: "sing-box",
      description: "sing-box: адаптер sing-tun Tunnel",
      detected: false,
      interfaces: ["sing-tun*"],
      trust: [],
      repair_programs: ["C:\\Tools\\updater.exe"],
    },
  ],
});

// Ответ GET /api/config: ключа нет — null.
const wire = (patch: Record<string, unknown> = {}) => parseConfig({ profile: "wireguard", ...patch });

describe("настройки из файла → действующие значения", () => {
  test("файла нет — умолчания", () => {
    expect(effective(parseConfig(null), profiles)).toMatchObject({
      profile: "",
      interfaces: [],
      lan: true,
      dns: "open",
      strict: false,
      trust: [],
      targets: [],
    });
  });

  test("ключа нет — действует список клиента", () => {
    const s = effective(wire(), profiles);
    expect(s.interfaces).toEqual(["WireGuard Tunnel*"]);
    expect(s.trust).toEqual([{ kind: "program", value: client, destinations: "" }]);
  });

  test("свой ключ заменяет список клиента целиком, пустой — тоже", () => {
    expect(effective(wire({ tunnel: { interfaces: ["wg0"] } }), profiles).interfaces).toEqual(["wg0"]);
    expect(effective(wire({ trust: [] }), profiles).trust).toEqual([]);
  });
});

describe("правка списка → структура для PUT /api/config", () => {
  test("первая правка начинается с действующего списка, нетронутые ключи остаются null", () => {
    const c = addItem(wire(), profiles, "interfaces", " wg0 ");
    expect(c).toEqual({
      profile: "wireguard",
      lan: null,
      trust_mode: null,
      tunnel: { interfaces: ["WireGuard Tunnel*", "wg0"], endpoints: null },
      trust: null,
      dns: { mode: null, resolvers: null, health: null },
      repair: { programs: null, names: null },
      check: { targets: null },
    });
  });

  test("пустое и повтор не добавляются", () => {
    const c = wire();
    expect(addItem(c, profiles, "targets", "   ")).toBe(c);
    expect(addItem(c, profiles, "interfaces", "WireGuard Tunnel*")).toBe(c);
  });

  test("убран последний из списка клиента — ключ остаётся пустым списком", () => {
    expect(removeItem(wire(), profiles, "interfaces", "WireGuard Tunnel*").tunnel.interfaces).toEqual([]);
  });

  test("пустой список без списка клиента — ключа нет", () => {
    const own = addItem(wire(), profiles, "targets", "198.51.100.20");
    expect(own.check.targets).toEqual(["198.51.100.20"]);
    expect(removeItem(own, profiles, "targets", "198.51.100.20").check.targets).toBeNull();
    const bare = wire({ profile: "", tunnel: { interfaces: ["wg0"] } });
    expect(removeItem(bare, profiles, "interfaces", "wg0").tunnel.interfaces).toBeNull();
  });

  test("«Как в профиле» убирает свой ключ", () => {
    const c = addItem(wire(), profiles, "interfaces", "wg0");
    expect(overridden(c, profiles, "interfaces")).toBe(true);
    expect(inherit(c, "interfaces").tunnel.interfaces).toBeNull();
    expect(overridden(wire({ profile: "", tunnel: { interfaces: ["wg0"] } }), profiles, "interfaces")).toBe(false);
  });

  test("«Как в профиле» не предлагается, если клиент списка не даёт: ссылка стёрла бы свой список", () => {
    const own = wire({ repair: { programs: ["C:\Apps\app.exe"] }, trust: [] });
    expect(overridden(own, profiles, "programs")).toBe(false);
    expect(overridden(own, profiles, "trust")).toBe(true);
    expect(overridden({ ...own, profile: "sing-box" }, profiles, "programs")).toBe(true);
    expect(overridden({ ...own, profile: "sing-box" }, profiles, "trust")).toBe(false);
  });

  test("имя программы починки — без .exe и без повтора в другом регистре", () => {
    expect(trimExe("Chrome.EXE")).toBe("Chrome");
    const c = addItem(wire(), profiles, "names", "chrome.exe");
    expect(c.repair.names).toEqual(["chrome"]);
    expect(addItem(c, profiles, "names", "Chrome")).toBe(c);
  });
});

describe("смена клиента", () => {
  test("списки, равные списку прежнего клиента, сбрасываются; свои остаются", () => {
    const c = wire({ tunnel: { interfaces: ["WireGuard Tunnel*"] }, trust: [{ kind: "program", value: "C:\\my.exe" }] });
    const next = setProfile(c, profiles, "sing-box");
    expect(next.profile).toBe("sing-box");
    expect(next.tunnel.interfaces).toBeNull();
    expect(next.trust).toEqual([{ kind: "program", value: "C:\\my.exe", destinations: "" }]);
    expect(effective(next, profiles).interfaces).toEqual(["sing-tun*"]);
  });

  test("«Другой» делает действующие списки своими, пустые — тоже", () => {
    const next = setProfile(wire(), profiles, "");
    expect(next).toMatchObject({ profile: "", tunnel: { interfaces: ["WireGuard Tunnel*"] } });
    expect(next.trust).toEqual([{ kind: "program", value: client, destinations: "" }]);
    expect(next.repair.programs).toEqual([]);
  });

  test("тот же клиент — настройки не меняются", () => {
    const c = wire({ tunnel: { interfaces: ["WireGuard Tunnel*"] } });
    expect(setProfile(c, profiles, "wireguard")).toBe(c);
    const none = wire({ profile: "" });
    expect(setProfile(none, profiles, "")).toBe(none);
  });

  test("клиента не было: пустой свой список равен списку «никакого клиента» и убирается", () => {
    const c = wire({ profile: "", tunnel: { interfaces: [] }, repair: { programs: ["C:\\Tools\\my.exe"] } });
    const next = setProfile(c, profiles, "sing-box");
    expect(next.tunnel.interfaces).toBeNull();
    expect(next.repair.programs).toEqual(["C:\\Tools\\my.exe"]);
    expect(effective(next, profiles).interfaces).toEqual(["sing-tun*"]);
  });

  test("доверенные сравниваются целиком: другое «куда» — уже свой список", () => {
    const own = [{ kind: "program", value: client, destinations: "endpoints" }];
    expect(setProfile(wire({ trust: own }), profiles, "sing-box").trust).toEqual(own);
    const asProfile = wire({ trust: [{ kind: "program", value: client, destinations: "" }] });
    expect(setProfile(asProfile, profiles, "sing-box").trust).toBeNull();
  });
});

describe("выключатели и режимы", () => {
  test("тронутый ключ записывается явно", () => {
    expect(setLan(wire(), false).lan).toBe(false);
    expect(setStrict(wire(), true).trust_mode).toBe("strict");
    expect(setStrict(wire({ trust_mode: "strict" }), false).trust_mode).toBe("compat");
  });

  test("уход с режима «Только мои серверы» убирает список серверов", () => {
    const c = addItem(setDnsMode(wire(), "resolvers"), profiles, "resolvers", "1.1.1.1");
    expect(c.dns).toEqual({ mode: "resolvers", resolvers: ["1.1.1.1"], health: null });
    expect(setDnsMode(c, "open").dns).toEqual({ mode: "open", resolvers: null, health: null });
  });

  test("адрес проверки туннеля: пустой — ключа нет", () => {
    expect(setHealth(wire(), " http://10.8.0.1:80/ ").dns.health).toBe("http://10.8.0.1:80/");
    expect(setHealth(wire({ dns: { health: "x" } }), "").dns.health).toBeNull();
  });
});

describe("доверенные", () => {
  test("выбор, совпавший с режимом, хранится пустым — следует за режимом", () => {
    const c = addTrust(wire({ trust: [] }), profiles, { kind: "program", value: " C:\\a.exe ", to: "any" });
    expect(c.trust).toEqual([{ kind: "program", value: "C:\\a.exe", destinations: "" }]);
    expect(trustTo(c.trust![0], false)).toBe("any");
    expect(trustTo(c.trust![0], true)).toBe("endpoints");
  });

  test("выбор против режима хранится явно", () => {
    const c = addTrust(wire(), profiles, { kind: "program", value: "C:\\a.exe", to: "endpoints" });
    expect(c.trust).toEqual([
      { kind: "program", value: client, destinations: "" },
      { kind: "program", value: "C:\\a.exe", destinations: "endpoints" },
    ]);
  });

  test("повтор не добавляется, убранный последний — пустой список поверх списка клиента", () => {
    const c = wire();
    expect(addTrust(c, profiles, { kind: "program", value: client, to: "any" })).toBe(c);
    expect(removeTrust(c, profiles, effective(c, profiles).trust[0]).trust).toEqual([]);
  });
});

describe("несохранённые правки по пунктам", () => {
  test("правок нет — пусто; правка и её отмена руками — тоже пусто", () => {
    const saved = wire();
    expect(changed(saved, saved, profiles)).toEqual([]);
    expect(changed(saved, setLan(setLan(saved, false), true), profiles)).toEqual([]);
  });

  test("изменённые пункты названы", () => {
    const saved = wire();
    const draft = setStrict(setHealth(setDnsMode(saved, "tunnel-up"), "http://10.8.0.1:80/"), true);
    expect(changed(saved, draft, profiles)).toEqual(["dns", "strict"]);
    expect(changed(saved, addItem(saved, profiles, "names", "chrome"), profiles)).toEqual(["repair"]);
    expect(changed(saved, addItem(saved, profiles, "interfaces", "wg0"), profiles)).toEqual(["client"]);
  });
});

describe("ошибка сохранения → пункт настроек", () => {
  test.each([
    ["не сохранено: trust_mode = strict: нужен хотя бы один tunnel.endpoints", "strict"],
    ['не сохранено: endpoint "x": нужен вид host:port/tcp|udp', "strict"],
    ['не сохранено: trust program="C:\\a.exe": destinations = endpoints без tunnel.endpoints', "trusted"],
    ["не сохранено: tunnel.interfaces: не задан ни один интерфейс туннеля", "client"],
    ['не сохранено: профиль "нет такого" не найден', "client"],
    ["не сохранено: dns.mode = tunnel-up: нужен dns.health", "dns"],
    ['не сохранено: repair.names "a b": пробелы по краям', "repair"],
    ["не сохранено: check.targets: неверный адрес", "targets"],
  ])("%s", (text, section) => {
    expect(errorSection(text)).toBe(section);
  });

  test("незнакомый текст — пункта нет", () => {
    expect(errorSection("файл не записан")).toBeNull();
    expect(errorSection("")).toBeNull();
  });
});

describe("список настроек: значение пункта", () => {
  const value = (patch: Record<string, unknown>, id: Parameters<typeof sectionValue>[2], repairOk = true) =>
    sectionValue(effective(wire(patch), profiles), profiles, id, repairOk);

  test("клиент", () => {
    expect(value({}, "client")).toBe("WireGuard");
    expect(value({ profile: "" }, "client")).toBe("Не выбран");
    expect(value({ profile: "", tunnel: { interfaces: ["wg0"] } }, "client")).toBe("Другой");
    expect(clientTitle(profiles, "нет такого")).toBe("нет такого");
  });

  test("остальные пункты", () => {
    expect(value({}, "lan")).toBe("Разрешена");
    expect(value({ dns: { mode: "tunnel-up" } }, "dns")).toBe("Закрыт, пока туннель жив");
    expect(value({ trust_mode: "strict" }, "strict")).toBe("Включён");
    expect(value({}, "trusted")).toBe("client.exe");
    expect(value({ trust: [] }, "trusted")).toBe("Никого");
    expect(value({ repair: { names: ["chrome", "node"], programs: ["C:\\a.exe"] } }, "repair")).toBe("3 программы");
    expect(value({}, "repair")).toBe("Никто");
    expect(value({}, "repair", false)).toBe("Только Windows");
    expect(value({}, "targets")).toBe("Не заданы");
    expect(value({ check: { targets: ["198.51.100.20"] } }, "targets")).toBe("198.51.100.20");
  });
});

test("запущенные программы: уже добавленные по имени или пути отмечены", () => {
  const running = parsePrograms({
    programs: [
      { name: "Chrome", paths: ["C:\\Program Files\\Chrome\\chrome.exe"] },
      { name: "node", paths: ["C:\\Tools\\Node.exe"] },
      { name: "steam", paths: null },
    ],
  });
  const s = effective(wire({ repair: { names: ["chrome"], programs: ["c:\\tools\\node.exe"] } }), profiles);
  expect(pickerRows(running, s, "")).toEqual([
    { name: "Chrome", added: true },
    { name: "node", added: true },
    { name: "steam", added: false },
  ]);
  expect(pickerRows(running, s, "STE").map((r) => r.name)).toEqual(["steam"]);
});

test("первый запуск сохраняет только выбранный клиент", () => {
  expect(firstRunConfig("wireguard")).toEqual({
    profile: "wireguard",
    lan: null,
    trust_mode: null,
    tunnel: { interfaces: null, endpoints: null },
    trust: null,
    dns: { mode: null, resolvers: null, health: null },
    repair: { programs: null, names: null },
    check: { targets: null },
  });
});
