import { describe, expect, test } from "vitest";

import { parseCheck } from "./api";
import { checkView, clock } from "./check";

const probe = (iface: string, proto: string, cls: string, detail = "", target = "198.51.100.20:80") => ({
  target,
  family: "v4",
  proto,
  iface,
  class: cls,
  detail,
});

// Ответ POST /api/check, как его отдаёт сервер.
const wire = (patch: Record<string, unknown>) =>
  parseCheck({ result: "clean", code: 0, simple: false, summary: "", note: "", probes: [], structural: [], ...patch });

const full = ["http", "udp-echo", "dns-udp", "dns-tcp"];

describe("ответ проверки → итог на экране", () => {
  test("утечек нет: строка — только время, таблица по адаптерам и службам", () => {
    const v = checkView(
      wire({ probes: ["Ethernet", "Wi-Fi"].flatMap((i) => full.map((p) => probe(i, p, "blocked"))) }),
      "в 14:02",
    );
    expect(v).toMatchObject({ verdict: "blocked", line: "в 14:02", columns: ["HTTP", "UDP", "DNS"], targets: ["198.51.100.20"] });
    expect(v.rows).toEqual([
      { iface: "Ethernet", cells: ["blocked", "blocked", "blocked"] },
      { iface: "Wi-Fi", cells: ["blocked", "blocked", "blocked"] },
    ]);
  });

  test("утечка: строка называет адаптеры, ячейка берёт худший итог службы", () => {
    const v = checkView(
      wire({
        result: "leak",
        summary: "УТЕЧКА",
        note: "адаптер Wi-Fi: http 198.51.100.20:80",
        probes: [
          ...full.map((p) => probe("Ethernet", p, "blocked")),
          probe("Wi-Fi", "http", "leak"),
          probe("Wi-Fi", "udp-echo", "blocked"),
          probe("Wi-Fi", "dns-udp", "blocked"),
          probe("Wi-Fi", "dns-tcp", "leak"),
        ],
      }),
      "в 14:02",
    );
    expect(v.verdict).toBe("leak");
    expect(v.line).toBe("через Wi-Fi · в 14:02");
    expect(v.note).toBe("");
    expect(v.rows[1]).toEqual({ iface: "Wi-Fi", cells: ["leak", "blocked", "leak"] });
  });

  test("утечка без пробы с утечкой — строка берёт пояснение сервера, находки перечислены", () => {
    const leak = { result: "leak", summary: "УТЕЧКА", structural: [{ kind: "pf", detail: "pf выключен" }] };
    const v = checkView(wire({ ...leak, note: "pf: pf выключен" }), "в 14:02");
    expect(v.line).toBe("pf: pf выключен · в 14:02");
    expect(v.findings).toEqual(["pf: pf выключен"]);
    expect(checkView(wire(leak), "в 14:02").line).toBe("правила защиты нарушены · в 14:02");
  });

  test("адаптер, где все пробы пропущены, уходит в пропущенные с причиной", () => {
    const v = checkView(
      wire({
        probes: [
          ...full.map((p) => probe("Ethernet", p, "blocked")),
          ...full.map((p) => probe("vEthernet (nat)", p, "skipped", "нет маршрута по умолчанию v4 через интерфейс")),
        ],
      }),
      "в 14:02",
    );
    expect(v.rows.map((r) => r.iface)).toEqual(["Ethernet"]);
    expect(v.skipped).toEqual([{ iface: "vEthernet (nat)", why: "нет маршрута по умолчанию v4 через интерфейс" }]);
  });

  test("нет уверенности: строка — причина из итога сервера", () => {
    const v = checkView(
      wire({
        result: "unsure",
        summary: "нет уверенности: цель не отвечает через туннель",
        probes: [probe("Ethernet", "http", "unsure", "цель не отвечает через туннель")],
      }),
      "в 14:02",
    );
    expect(v).toMatchObject({ verdict: "unsure", line: "цель не отвечает через туннель · в 14:02", note: "" });
  });

  test("нет уверенности без причины в итоге — строка не пустая", () => {
    expect(checkView(wire({ result: "unsure" }), "в 14:02").line).toBe("проверить не удалось · в 14:02");
  });

  test("простая проверка: строка говорит об этом, пояснение сервера — над таблицей", () => {
    const note = "проверен только TCP; UDP и DNS не проверялись — для полной проверки задайте свои адреса ([check] targets)";
    const v = checkView(
      wire({
        simple: true,
        summary: "утечек не найдено (простая проверка)",
        note,
        probes: [probe("Ethernet", "http", "blocked", "", "93.184.215.14:80")],
      }),
      "в 14:02",
    );
    expect(v.line).toBe("простая проверка · в 14:02");
    expect(v.columns).toEqual(["HTTP"]);
    expect(v.note).toBe(note);
  });

  test("простая проверка с утечкой: строка называет адаптер, пояснение сервера — над таблицей", () => {
    const v = checkView(
      wire({
        result: "leak",
        simple: true,
        summary: "УТЕЧКА (простая проверка)",
        note: "адаптер Wi-Fi: http 93.184.215.14:80",
        probes: [probe("Wi-Fi", "http", "leak", "", "93.184.215.14:80")],
      }),
      "в 14:02",
    );
    expect(v.line).toBe("простая проверка · через Wi-Fi · в 14:02");
    expect(v.note).toBe("адаптер Wi-Fi: http 93.184.215.14:80");
  });

  test("проба без адаптера строки не даёт, адрес сервера — без порта", () => {
    const v = checkView(
      wire({
        result: "unsure",
        simple: true,
        summary: "нет уверенности (простая проверка): имя не разрешилось: адресов нет",
        probes: [
          { ...probe("", "http", "unsure", "имя не разрешилось: адресов нет"), target: "example.com" },
          probe("Ethernet", "http", "blocked", "", "[2001:db8::1]:80"),
        ],
      }),
      "в 14:02",
    );
    expect(v.rows.map((r) => r.iface)).toEqual(["Ethernet"]);
    expect(v.line).toBe("простая проверка · имя не разрешилось: адресов нет · в 14:02");
    expect(v.targets).toEqual(["example.com", "2001:db8::1"]);
  });
});

test("время итога — часы и минуты", () => {
  expect(clock(new Date(2026, 10, 10, 9, 5))).toBe("в 09:05");
});
