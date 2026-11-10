// Настройки: черновик — та же структура, что уходит в PUT /api/config. Правки — чистые функции над ней.
// Правила те же, что в меню: null — ключа нет (действует список клиента или умолчание), свой ключ заменяет
// список клиента целиком.

import { parseConfig, type Config, type Profile, type Program, type Trust } from "./api";

export type SectionId = "client" | "lan" | "dns" | "strict" | "trusted" | "repair" | "targets";
export type DnsMode = "open" | "tunnel-up" | "resolvers";
export type ListKey = "interfaces" | "endpoints" | "resolvers" | "names" | "programs" | "targets";
/** Списки, которые даёт клиент туннеля. */
export type Inherited = "interfaces" | "programs" | "trust";
/** Куда можно доверенному: куда угодно или только к серверам туннеля. */
export type TrustTo = "any" | "endpoints";

export const SECTIONS: SectionId[] = ["client", "lan", "dns", "strict", "trusted", "repair", "targets"];

export const sectionTitle: Record<SectionId, string> = {
  client: "Клиент туннеля",
  lan: "Локальная сеть",
  dns: "DNS мимо туннеля",
  strict: "Строгий режим",
  trusted: "Доверенные",
  repair: "Закрыты в починке",
  targets: "Адреса проверки",
};

export const DNS_MODES: DnsMode[] = ["open", "tunnel-up", "resolvers"];

export const dnsTitle: Record<DnsMode, string> = {
  open: "Открыт",
  "tunnel-up": "Закрыт, пока туннель жив",
  resolvers: "Только мои серверы",
};

/** Действующие значения: свой ключ, иначе список клиента, иначе умолчание. */
export interface Settings {
  profile: string;
  interfaces: string[];
  lan: boolean;
  dns: DnsMode;
  health: string;
  resolvers: string[];
  strict: boolean;
  endpoints: string[];
  trust: Trust[];
  names: string[];
  programs: string[];
  targets: string[];
}

const profileOf = (profiles: Profile[], name: string) => profiles.find((p) => p.name === name);

export function effective(c: Config, profiles: Profile[]): Settings {
  const p = profileOf(profiles, c.profile);
  return {
    profile: c.profile,
    interfaces: c.tunnel.interfaces ?? p?.interfaces ?? [],
    lan: c.lan ?? true,
    dns: DNS_MODES.find((m) => m === c.dns.mode) ?? "open",
    health: c.dns.health ?? "",
    resolvers: c.dns.resolvers ?? [],
    strict: c.trust_mode === "strict",
    endpoints: c.tunnel.endpoints ?? [],
    trust: c.trust ?? p?.trust ?? [],
    names: c.repair.names ?? [],
    programs: c.repair.programs ?? p?.repair_programs ?? [],
    targets: c.check.targets ?? [],
  };
}

// --- списки ---

const LISTS: Record<ListKey, { get: (c: Config) => string[] | null; set: (c: Config, v: string[] | null) => Config }> = {
  interfaces: { get: (c) => c.tunnel.interfaces, set: (c, v) => ({ ...c, tunnel: { ...c.tunnel, interfaces: v } }) },
  endpoints: { get: (c) => c.tunnel.endpoints, set: (c, v) => ({ ...c, tunnel: { ...c.tunnel, endpoints: v } }) },
  resolvers: { get: (c) => c.dns.resolvers, set: (c, v) => ({ ...c, dns: { ...c.dns, resolvers: v } }) },
  names: { get: (c) => c.repair.names, set: (c, v) => ({ ...c, repair: { ...c.repair, names: v } }) },
  programs: { get: (c) => c.repair.programs, set: (c, v) => ({ ...c, repair: { ...c.repair, programs: v } }) },
  targets: { get: (c) => c.check.targets, set: (c, v) => ({ ...c, check: { targets: v } }) },
};

/** Что клиент даёт для списка. */
function layer(p: Profile | undefined, key: ListKey): string[] {
  if (key === "interfaces") return p?.interfaces ?? [];
  if (key === "programs") return p?.repair_programs ?? [];
  return [];
}

/** Пустой свой список остаётся ключом, только если он заменяет список клиента. */
const kept = <T>(items: T[], fromProfile: T[]): T[] | null => (items.length || fromProfile.length ? items : null);

function store(c: Config, profiles: Profile[], key: ListKey, items: string[]): Config {
  return LISTS[key].set(c, kept(items, layer(profileOf(profiles, c.profile), key)));
}

/** Имя программы починки — без расширения. */
export const trimExe = (name: string) => name.replace(/\.exe$/i, "");

const lower = (s: string) => s.toLowerCase();

export function addItem(c: Config, profiles: Profile[], key: ListKey, raw: string): Config {
  const text = key === "names" ? trimExe(raw.trim()) : raw.trim();
  const now = effective(c, profiles)[key];
  const taken = key === "names" ? now.map(lower).includes(lower(text)) : now.includes(text);
  return text === "" || taken ? c : store(c, profiles, key, [...now, text]);
}

export function removeItem(c: Config, profiles: Profile[], key: ListKey, value: string): Config {
  return store(
    c,
    profiles,
    key,
    effective(c, profiles)[key].filter((v) => v !== value),
  );
}

// --- доверенные ---

/** Куда можно доверенному: своё значение, иначе по строгому режиму. */
export const trustTo = (t: Trust, strict: boolean): TrustTo =>
  t.destinations === "any" || t.destinations === "endpoints" ? t.destinations : strict ? "endpoints" : "any";

const sameTrust = (a: Trust, b: Trust) => a.kind === b.kind && a.value === b.value;

function storeTrust(c: Config, profiles: Profile[], items: Trust[]): Config {
  return { ...c, trust: kept(items, profileOf(profiles, c.profile)?.trust ?? []) };
}

export function addTrust(c: Config, profiles: Profile[], add: { kind: string; value: string; to: TrustTo }): Config {
  const s = effective(c, profiles);
  const value = add.value.trim();
  // Выбор, совпавший с режимом, хранится пустым: запись следует за строгим режимом.
  const item: Trust = { kind: add.kind, value, destinations: add.to === trustTo({ ...add, destinations: "" }, s.strict) ? "" : add.to };
  return value === "" || s.trust.some((t) => sameTrust(t, item)) ? c : storeTrust(c, profiles, [...s.trust, item]);
}

export function removeTrust(c: Config, profiles: Profile[], item: Trust): Config {
  return storeTrust(
    c,
    profiles,
    effective(c, profiles).trust.filter((t) => !sameTrust(t, item)),
  );
}

// --- клиент ---

/** Свой список стоит поверх списка клиента и отличается от него. Клиент списка не даёт — возвращаться не к чему. */
export function overridden(c: Config, profiles: Profile[], key: Inherited): boolean {
  const p = profileOf(profiles, c.profile);
  const own = key === "trust" ? c.trust : LISTS[key].get(c);
  const given = key === "trust" ? (p?.trust ?? []) : layer(p, key);
  return own !== null && given.length > 0 && !same(own, given);
}

/** «Как в профиле»: свой ключ убран, действует список клиента. */
export function inherit(c: Config, key: Inherited): Config {
  return key === "trust" ? { ...c, trust: null } : LISTS[key].set(c, null);
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** Смена клиента — правило меню. Свой список, равный списку прежнего клиента, убирается: его даст новый; другие
 *  свои остаются. Пустое имя — «Другой»: действующие списки становятся своими. Тот же клиент — без изменений. */
export function setProfile(c: Config, profiles: Profile[], name: string): Config {
  if (name === c.profile) return c;
  const prev = profileOf(profiles, c.profile);
  const now = effective(c, profiles);
  if (name === "") {
    return {
      ...c,
      profile: "",
      tunnel: { ...c.tunnel, interfaces: now.interfaces },
      // Доверенных клиент мог не давать вовсе: тогда ключа нет.
      trust: c.trust ?? (now.trust.length ? now.trust : null),
      repair: { ...c.repair, programs: now.programs },
    };
  }
  // Клиента не было — его список пуст.
  const own = <T>(list: T[] | null, was: T[] | undefined) => (list !== null && same(list, was ?? []) ? null : list);
  return {
    ...c,
    profile: name,
    tunnel: { ...c.tunnel, interfaces: own(c.tunnel.interfaces, prev?.interfaces) },
    trust: own(c.trust, prev?.trust),
    repair: { ...c.repair, programs: own(c.repair.programs, prev?.repair_programs) },
  };
}

/** Название клиента: начало описания до двоеточия. */
export function clientTitle(profiles: Profile[], name: string): string {
  const title = profileOf(profiles, name)?.description.split(":")[0].trim();
  return title || name;
}

/** Настройки первого запуска: выбран только клиент, остальное по умолчанию. */
export const firstRunConfig = (profile: string): Config => ({ ...parseConfig(null), profile });

// --- выключатели и режимы: тронутый ключ записывается явно ---

export const setLan = (c: Config, lan: boolean): Config => ({ ...c, lan });

export const setStrict = (c: Config, on: boolean): Config => ({ ...c, trust_mode: on ? "strict" : "compat" });

/** Список своих серверов DNS допустим только в режиме «Только мои серверы». */
export const setDnsMode = (c: Config, mode: DnsMode): Config => ({
  ...c,
  dns: { ...c.dns, mode, resolvers: mode === "resolvers" ? c.dns.resolvers : null },
});

export const setHealth = (c: Config, text: string): Config => ({ ...c, dns: { ...c.dns, health: text.trim() || null } });

// --- список настроек ---

const slices: Record<SectionId, (s: Settings) => unknown> = {
  client: (s) => [s.profile, s.interfaces],
  lan: (s) => s.lan,
  dns: (s) => [s.dns, s.health, s.resolvers],
  strict: (s) => [s.strict, s.endpoints],
  trusted: (s) => s.trust,
  repair: (s) => [s.names, s.programs],
  targets: (s) => s.targets,
};

/** Пункты с несохранёнными правками: действующее значение отличается от сохранённого. */
export function changed(saved: Config, draft: Config, profiles: Profile[]): SectionId[] {
  const [a, b] = [effective(saved, profiles), effective(draft, profiles)];
  return SECTIONS.filter((id) => !same(slices[id](a), slices[id](b)));
}

// Ключи настроек в тексте ошибки сервера → пункт; первый встреченный ключ решает.
const ERROR_KEYS: [RegExp, SectionId][] = [
  [/trust_mode|tunnel\.endpoints|endpoint /, "strict"],
  [/trust /, "trusted"],
  [/tunnel\.interfaces|профиль/, "client"],
  [/dns\./, "dns"],
  [/repair/, "repair"],
  [/check/, "targets"],
];

/** Пункт, к которому относится ошибка сохранения; null — по тексту не определить. */
export function errorSection(text: string): SectionId | null {
  let best: { at: number; id: SectionId } | null = null;
  for (const [re, id] of ERROR_KEYS) {
    const at = text.search(re);
    if (at >= 0 && (best === null || at < best.at)) best = { at, id };
  }
  return best?.id ?? null;
}

export const baseName = (path: string) => path.split(/[\\/]/).pop() || path;

function plural(n: number, one: string, few: string, many: string): string {
  const last = n % 10;
  const teen = n % 100 >= 11 && n % 100 <= 14;
  if (last === 1 && !teen) return `${n} ${one}`;
  if (last >= 2 && last <= 4 && !teen) return `${n} ${few}`;
  return `${n} ${many}`;
}

/** Текущее значение пункта — для списка настроек. */
export function sectionValue(s: Settings, profiles: Profile[], id: SectionId, repairOk: boolean): string {
  switch (id) {
    case "client":
      if (s.profile !== "") return clientTitle(profiles, s.profile);
      return s.interfaces.length ? "Другой" : "Не выбран";
    case "lan":
      return s.lan ? "Разрешена" : "Закрыта";
    case "dns":
      return dnsTitle[s.dns];
    case "strict":
      return s.strict ? "Включён" : "Выключен";
    case "trusted":
      return s.trust.length ? s.trust.map((t) => baseName(t.value)).join(", ") : "Никого";
    case "repair": {
      if (!repairOk) return "Только Windows";
      const n = s.names.length + s.programs.length;
      return n ? plural(n, "программа", "программы", "программ") : "Никто";
    }
    case "targets":
      return s.targets.join(", ") || "Не заданы";
  }
}

/** Клиент не выбран и адаптеров нет: включать нечего. */
export const clientUnset = (s: Settings) => s.profile === "" && s.interfaces.length === 0;

/** Запущенные программы для выбора по имени; added — уже в списке по имени или по пути. */
export function pickerRows(running: Program[], s: Settings, query: string): { name: string; added: boolean }[] {
  const names = s.names.map(lower);
  const paths = s.programs.map(lower);
  return running
    .filter((p) => lower(p.name).includes(lower(query.trim())))
    .map((p) => ({ name: p.name, added: names.includes(lower(p.name)) || p.paths.some((x) => paths.includes(lower(x))) }));
}
