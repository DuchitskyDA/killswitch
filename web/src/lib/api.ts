// Контракт сервера окна: типы ответов, их разбор на входе и вызовы. Описание — internal/window/API.md.

export type Mode = "on" | "off" | "repair";

export interface Tunnel {
  name: string;
  up: boolean;
}

export interface Warning {
  level: "warn" | "leak";
  text: string;
}

export interface AppState {
  os: string;
  /** Настройки сохранены: без них включать нечего. */
  configured: boolean;
  /** Пусто — защита не включалась. */
  mode: Mode | "";
  /** Правила защиты есть в системе. */
  active: boolean;
  tunnels: Tunnel[];
  warnings: Warning[];
  capabilities: { repair: boolean; trust_kinds: string[] };
}

export type ProbeClass = "blocked" | "leak" | "unsure" | "skipped";

export interface Probe {
  target: string;
  proto: string;
  iface: string;
  class: ProbeClass;
  detail: string;
}

export interface CheckReport {
  result: "clean" | "leak" | "unsure";
  /** Своих адресов проверки нет: шла простая проверка. */
  simple: boolean;
  /** Итог одной строкой; при «нет уверенности» несёт причину после двоеточия. */
  summary: string;
  /** Пояснение к итогу: где утечка или чего простая проверка не проверяла. */
  note: string;
  probes: Probe[];
  structural: { kind: string; detail: string }[];
}

export interface Trust {
  kind: string;
  value: string;
  /** Пусто — по строгому режиму. */
  destinations: string;
}

/** Настройки. null — ключа в файле нет: действует список профиля или умолчание. */
export interface Config {
  profile: string;
  lan: boolean | null;
  trust_mode: string | null;
  tunnel: { interfaces: string[] | null; endpoints: string[] | null };
  trust: Trust[] | null;
  dns: { mode: string | null; resolvers: string[] | null; health: string | null };
  repair: { programs: string[] | null; names: string[] | null };
  check: { targets: string[] | null };
}

export interface Profile {
  name: string;
  description: string;
  /** Клиент найден на этой машине. */
  detected: boolean;
  interfaces: string[];
  trust: Trust[];
  repair_programs: string[];
}

export interface Program {
  name: string;
  paths: string[];
}

/** Ошибка вызова. status 0 — ответа нет (связь оборвана). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    text: string,
    /** Только у PUT /api/config: файл настроек записан, хотя вызов кончился ошибкой. */
    readonly saved = false,
    /** Что сервер всё же сделал (поле message рядом с ошибкой). */
    readonly note = "",
  ) {
    super(text);
  }
}

// --- разбор ответов: пропуск и null вместо списка — пустое значение ---

type Raw = Record<string, unknown>;

const obj = (v: unknown): Raw => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Raw) : {});
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const list = <T>(v: unknown, item: (x: unknown) => T): T[] => (Array.isArray(v) ? v.map(item) : []);
const oneOf = <T extends string>(v: unknown, all: readonly T[], fallback: T): T =>
  all.includes(v as T) ? (v as T) : fallback;
const strings = (v: unknown): string[] => list(v, str);
const stringsOrNull = (v: unknown): string[] | null => (Array.isArray(v) ? strings(v) : null);
const strOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);

const tunnel = (v: unknown): Tunnel => ({ name: str(obj(v).name), up: obj(v).up === true });
const trust = (v: unknown): Trust => {
  const t = obj(v);
  return { kind: str(t.kind), value: str(t.value), destinations: str(t.destinations) };
};

export function parseState(raw: unknown): AppState {
  const s = obj(raw);
  const caps = obj(s.capabilities);
  return {
    os: str(s.os),
    configured: s.configured === true,
    mode: oneOf(s.mode, ["on", "off", "repair", ""] as const, ""),
    active: s.active === true,
    tunnels: list(s.tunnels, tunnel),
    warnings: list(s.warnings, (v) => ({
      level: oneOf(obj(v).level, ["warn", "leak"] as const, "warn"),
      text: str(obj(v).text),
    })),
    capabilities: { repair: caps.repair === true, trust_kinds: strings(caps.trust_kinds) },
  };
}

export function parseCheck(raw: unknown): CheckReport {
  const c = obj(raw);
  return {
    result: oneOf(c.result, ["clean", "leak", "unsure"] as const, "unsure"),
    simple: c.simple === true,
    summary: str(c.summary),
    note: str(c.note),
    probes: list(c.probes, (v) => {
      const p = obj(v);
      return {
        target: str(p.target),
        proto: str(p.proto),
        iface: str(p.iface),
        class: oneOf(p.class, ["blocked", "leak", "unsure", "skipped"] as const, "unsure"),
        detail: str(p.detail),
      };
    }),
    structural: list(c.structural, (v) => ({ kind: str(obj(v).kind), detail: str(obj(v).detail) })),
  };
}

export function parseConfig(raw: unknown): Config {
  const c = obj(raw);
  const [tun, dns, repair, check] = [obj(c.tunnel), obj(c.dns), obj(c.repair), obj(c.check)];
  return {
    profile: str(c.profile),
    lan: typeof c.lan === "boolean" ? c.lan : null,
    trust_mode: strOrNull(c.trust_mode),
    tunnel: { interfaces: stringsOrNull(tun.interfaces), endpoints: stringsOrNull(tun.endpoints) },
    trust: Array.isArray(c.trust) ? list(c.trust, trust) : null,
    dns: { mode: strOrNull(dns.mode), resolvers: stringsOrNull(dns.resolvers), health: strOrNull(dns.health) },
    repair: { programs: stringsOrNull(repair.programs), names: stringsOrNull(repair.names) },
    check: { targets: stringsOrNull(check.targets) },
  };
}

export function parseClients(raw: unknown): Profile[] {
  return list(obj(raw).profiles, (v) => {
    const p = obj(v);
    return {
      name: str(p.name),
      description: str(p.description),
      detected: p.detected === true,
      interfaces: strings(p.interfaces),
      trust: list(p.trust, trust),
      repair_programs: strings(p.repair_programs),
    };
  });
}

export function parsePrograms(raw: unknown): Program[] {
  return list(obj(raw).programs, (v) => ({ name: str(obj(v).name), paths: strings(obj(v).paths) }));
}

// --- вызовы ---

async function call(method: "GET" | "POST" | "PUT", path: string, body?: unknown): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      cache: "no-store",
      headers: method === "GET" ? undefined : { "Content-Type": "application/json" },
      body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
    });
  } catch {
    throw new ApiError(0, "");
  }
  if (!res.ok) {
    // Тело ошибки — JSON с полем error; не разобралось — текста нет.
    const e = obj(await res.json().catch(() => null));
    throw new ApiError(res.status, str(e.error), e.saved === true, str(e.message));
  }
  try {
    return await res.json();
  } catch {
    // Ответ оборвался на середине: данных нет, и это не «пустой ответ».
    throw new ApiError(0, "");
  }
}

export const api = {
  state: async () => parseState(await call("GET", "/api/state")),
  mode: async (mode: Mode) => parseState(await call("POST", "/api/mode", { mode })),
  check: async () => parseCheck(await call("POST", "/api/check")),
  config: async () => parseConfig(await call("GET", "/api/config")),
  save: async (config: Config) => void (await call("PUT", "/api/config", config)),
  clients: async () => parseClients(await call("GET", "/api/clients")),
  programs: async () => parsePrograms(await call("GET", "/api/programs")),
  alive: async () => void (await call("POST", "/api/alive")),
  /** Страница закрывается: сервер ждёт ещё несколько секунд и выходит. Запрос переживает закрытие вкладки. */
  closing: () => {
    void fetch("/api/alive", {
      method: "POST",
      keepalive: true,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ closing: true }),
    }).catch(() => {});
  },
};
