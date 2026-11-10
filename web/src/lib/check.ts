// Проверка утечек: ответ сервера → слово итога, одна строка и таблица «адаптер × служба».

import type { CheckReport, Probe, ProbeClass } from "./api";
import type { Tone } from "./screen";

export type Verdict = "blocked" | "leak" | "unsure";

export interface CheckView {
  verdict: Verdict;
  /** Одна строка под словом итога; при утечке называет адаптер. */
  line: string;
  /** Службы, которые проверялись. */
  columns: string[];
  rows: { iface: string; cells: ProbeClass[] }[];
  /** Адаптеры, где не сделано ни одной пробы, с причиной. */
  skipped: { iface: string; why: string }[];
  /** Нарушения правил защиты, найденные без проб. */
  findings: string[];
  /** Пояснение сервера к простой проверке — над таблицей. */
  note: string;
  /** Серверы проверки. */
  targets: string[];
}

export const verdictWord: Record<Verdict, string> = {
  blocked: "Утечек нет",
  leak: "УТЕЧКА",
  unsure: "Нет уверенности",
};

export const verdictTone: Record<Verdict, Tone> = { blocked: "guard", leak: "leak", unsure: "none" };

export const classWord: Record<ProbeClass, string> = {
  blocked: "закрыто",
  leak: "утечка",
  unsure: "неясно",
  skipped: "пропуск",
};

const SERVICES = ["HTTP", "UDP", "DNS"];
const serviceOf: Record<string, string> = { http: "HTTP", "udp-echo": "UDP", "dns-udp": "DNS", "dns-tcp": "DNS" };
const service = (p: Probe) => serviceOf[p.proto] ?? p.proto.toUpperCase();

// Худший итог службы на адаптере: утечка важнее неясного, неясное — закрытого.
const RANK: ProbeClass[] = ["skipped", "blocked", "unsure", "leak"];
const worst = (probes: Probe[]): ProbeClass =>
  probes.reduce<ProbeClass>((w, p) => (RANK.indexOf(p.class) > RANK.indexOf(w) ? p.class : w), "skipped");

const unique = (items: string[]) => [...new Set(items)];

/** Адрес сервера без порта. */
const host = (target: string) => target.replace(/:\d+$/, "").replace(/^\[(.*)\]$/, "$1");

export const clock = (at: Date) =>
  `в ${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;

/** Адаптеры, через которые прошла утечка. */
const leaked = (r: CheckReport) => unique(r.probes.filter((p) => p.class === "leak" && p.iface).map((p) => p.iface));

/** Причина «нет уверенности»: часть итога сервера после двоеточия. */
function unsureWhy(summary: string): string {
  const at = summary.indexOf(": ");
  return at < 0 ? "" : summary.slice(at + 2);
}

/** Что сказать об итоге одной строкой; у «утечек нет» сказать нечего. */
function gist(r: CheckReport, verdict: Verdict): string {
  if (verdict === "leak") {
    const through = leaked(r);
    return through.length ? `через ${through.join(", ")}` : r.note || "правила защиты нарушены";
  }
  return verdict === "unsure" ? unsureWhy(r.summary) || "проверить не удалось" : "";
}

const lineOf = (r: CheckReport, verdict: Verdict, when: string) =>
  [r.simple ? "простая проверка" : "", gist(r, verdict), when].filter(Boolean).join(" · ");

/** Пояснение над таблицей: только у простой проверки и только если его нет в строке итога. */
const noteOf = (r: CheckReport, verdict: Verdict) => (r.simple && gist(r, verdict) !== r.note ? r.note : "");

export function checkView(r: CheckReport, when: string): CheckView {
  const verdict: Verdict = r.result === "clean" ? "blocked" : r.result;
  const present = unique(r.probes.map(service));
  const columns = [...SERVICES.filter((s) => present.includes(s)), ...present.filter((s) => !SERVICES.includes(s))];
  const rows: CheckView["rows"] = [];
  const skipped: CheckView["skipped"] = [];
  for (const iface of unique(r.probes.map((p) => p.iface).filter(Boolean))) {
    const own = r.probes.filter((p) => p.iface === iface);
    if (own.every((p) => p.class === "skipped")) {
      skipped.push({ iface, why: own[0].detail });
    } else {
      rows.push({ iface, cells: columns.map((c) => worst(own.filter((p) => service(p) === c))) });
    }
  }
  return {
    verdict,
    line: lineOf(r, verdict, when),
    columns,
    rows,
    skipped,
    findings: r.structural.map((f) => `${f.kind}: ${f.detail}`),
    note: noteOf(r, verdict),
    targets: unique(r.probes.map((p) => host(p.target)).filter(Boolean)),
  };
}
