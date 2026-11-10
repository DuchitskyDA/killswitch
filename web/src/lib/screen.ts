// Главный экран: состояние сервера → слово, цвет и кнопка питания; что шлют кнопка и переключатель режима.

import type { AppState, Mode } from "./api";

/** Положение переключателя режима: что включает кнопка питания. */
export type Kind = "full" | "repair";
export type Busy = "on" | "off" | "check";
/** Связь с сервером окна: первого ответа ещё нет, есть, потеряна (повтор может помочь), сеанса больше нет. */
export type Link = "loading" | "ok" | "lost" | "closed";
export type Tone = "guard" | "open" | "leak" | "none";

export interface Face {
  /** Слово состояния. */
  word: string;
  /** Оно же внутри кнопки питания: одна-две короткие строки. */
  inside: string[];
  /** Срок действия состояния. */
  sub: string;
  tone: Tone;
  /** Кнопка питания: включена, приглушена (выключена) или недоступна. */
  power: "on" | "muted" | "disabled";
  /** Кольцо приглушённой кнопки окрашено цветом состояния. */
  alert: boolean;
  /** Что сделать, когда окно больше не работает. */
  advice: string;
}

export const busyWord: Record<Busy, string> = {
  on: "Включаю…",
  off: "Выключаю…",
  check: "Проверяю…",
};

const untilReboot = "до перезагрузки";

const face = (word: string, tone: Tone, power: Face["power"], rest: Partial<Face> = {}): Face => ({
  word,
  inside: [],
  sub: "",
  tone,
  power,
  alert: false,
  advice: "",
  ...rest,
});

/** Режим задан, но правил в системе нет. */
const rulesMissing = (s: AppState) => s.mode === "on" && !s.active;

/** Защита действует: кнопка питания её выключает. */
const engaged = (s: AppState) => s.mode === "repair" || (s.active && s.mode !== "off");

export function faceOf(link: Link, s: AppState | null, busy: Busy | null): Face {
  if (link === "lost") return face("Нет связи", "leak", "disabled");
  if (link === "closed") return face("Окно закрыто", "none", "disabled", { advice: "Откройте killswitch заново" });
  if (link === "loading" || s === null) return face("Читаю состояние…", "none", "disabled", { inside: ["Читаю…"] });
  if (busy === "on" || busy === "off") {
    return face(busyWord[busy], "none", engaged(s) ? "on" : "muted", { inside: [busyWord[busy]] });
  }
  if (!s.configured) return face("Защита не настроена", "none", "muted", { inside: ["Не настроена"] });
  if (s.mode === "repair") return face("Починка", "open", "on", { inside: ["Починка"], sub: untilReboot });
  if (rulesMissing(s)) {
    return face("Правила не загружены", "leak", "muted", { inside: ["Правила", "не загружены"], alert: true });
  }
  if (engaged(s)) {
    return s.tunnels.some((t) => t.up)
      ? face("Защита включена", "guard", "on", { inside: ["Включена"] })
      : face("Всё закрыто", "guard", "on", { inside: ["Всё закрыто"] });
  }
  return face("Выключена", "open", "muted", { inside: ["Выключена"], sub: s.mode === "off" ? untilReboot : "" });
}

/** Положение переключателя: действующий режим, при выключенной защите — выбранное на странице. */
export function kindOf(s: AppState, pick: Kind): Kind {
  if (s.mode === "repair") return "repair";
  if (engaged(s) || rulesMissing(s) || !s.capabilities.repair) return "full";
  return pick;
}

const modeOf = (kind: Kind): Mode => (kind === "repair" ? "repair" : "on");

/** Что шлёт кнопка питания. */
export function powerSends(s: AppState, pick: Kind): Mode {
  return engaged(s) ? "off" : modeOf(kindOf(s, pick));
}

/** Что шлёт переключатель режима; null — запроса нет, положение помнит страница. */
export function switchSends(s: AppState, kind: Kind): Mode | null {
  const live = engaged(s) || rulesMissing(s);
  if (!live || kind === kindOf(s, kind) || (kind === "repair" && !s.capabilities.repair)) return null;
  return modeOf(kind);
}
