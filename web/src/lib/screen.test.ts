import { describe, expect, test } from "vitest";

import { parseState } from "./api";
import { faceOf, kindOf, powerSends, switchSends } from "./screen";

// Ответ GET /api/state, как его отдаёт сервер.
const wire = (patch: Record<string, unknown> = {}) =>
  parseState({
    os: "windows",
    configured: true,
    mode: "on",
    active: true,
    tunnels: [{ name: "wg-home", up: true }],
    warnings: [],
    capabilities: { repair: true, trust_kinds: ["program"] },
    ...patch,
  });

const face = (patch: Record<string, unknown> = {}) => faceOf("ok", wire(patch), null);

describe("ответ состояния → слово и кнопка питания", () => {
  test("защита включена, туннель поднят", () => {
    expect(face()).toMatchObject({ word: "Защита включена", inside: ["Включена"], tone: "guard", power: "on" });
  });

  test("защита включена, туннель опущен или не найден — всё закрыто", () => {
    expect(face({ tunnels: [{ name: "wg-home", up: false }] }).word).toBe("Всё закрыто");
    expect(face({ tunnels: [] }).word).toBe("Всё закрыто");
  });

  test("режим включён, а правил в системе нет", () => {
    expect(face({ active: false })).toMatchObject({
      word: "Правила не загружены",
      tone: "leak",
      power: "muted",
      alert: true,
    });
  });

  test("починка и выключение действуют до перезагрузки", () => {
    expect(face({ mode: "repair" })).toMatchObject({ word: "Починка", tone: "open", power: "on", sub: "до перезагрузки" });
    expect(face({ mode: "off", active: false })).toMatchObject({ word: "Выключена", power: "muted", sub: "до перезагрузки" });
  });

  test("защита не включалась", () => {
    expect(face({ mode: "", active: false })).toMatchObject({ word: "Выключена", power: "muted", sub: "" });
  });

  test("настроек нет", () => {
    expect(face({ configured: false, mode: "", active: false })).toMatchObject({ word: "Защита не настроена", power: "muted" });
  });

  test("ответа ещё нет и связи нет — кнопка недоступна", () => {
    expect(faceOf("loading", null, null)).toMatchObject({ word: "Читаю состояние…", power: "disabled" });
    expect(faceOf("lost", wire(), null)).toMatchObject({ word: "Нет связи", tone: "leak", power: "disabled", advice: "" });
  });

  test("сеанса больше нет — окно закрыто, кнопка недоступна, совет открыть заново", () => {
    expect(faceOf("closed", wire(), null)).toMatchObject({
      word: "Окно закрыто",
      advice: "Откройте killswitch заново",
      power: "disabled",
    });
  });

  test("идёт переход — слово действия, кольцо по прежнему состоянию", () => {
    expect(faceOf("ok", wire({ mode: "off", active: false }), "on")).toMatchObject({ inside: ["Включаю…"], power: "muted" });
    expect(faceOf("ok", wire(), "off")).toMatchObject({ inside: ["Выключаю…"], power: "on" });
  });

  test("ответ без полей не роняет экран", () => {
    expect(faceOf("ok", parseState(null), null).word).toBe("Защита не настроена");
    expect(parseState({ mode: "weird", tunnels: null })).toMatchObject({ mode: "", tunnels: [], warnings: [] });
  });
});

describe("кнопка питания", () => {
  test("включённую защиту и починку выключает", () => {
    expect(powerSends(wire(), "full")).toBe("off");
    expect(powerSends(wire({ mode: "repair" }), "full")).toBe("off");
  });

  test("выключенную включает в выбранном режиме", () => {
    const off = wire({ mode: "off", active: false });
    expect(powerSends(off, "full")).toBe("on");
    expect(powerSends(off, "repair")).toBe("repair");
  });

  test("правила не загружены — включает заново", () => {
    expect(powerSends(wire({ active: false }), "repair")).toBe("on");
  });

  test("ОС без починки включает только полную защиту", () => {
    const linux = wire({ mode: "off", active: false, capabilities: { repair: false, trust_kinds: ["user"] } });
    expect(powerSends(linux, "repair")).toBe("on");
  });
});

describe("переключатель режима", () => {
  test("положение — действующий режим, при выключенной защите — выбранное на странице", () => {
    expect(kindOf(wire(), "repair")).toBe("full");
    expect(kindOf(wire({ mode: "repair" }), "full")).toBe("repair");
    expect(kindOf(wire({ mode: "off", active: false }), "repair")).toBe("repair");
  });

  test("защита включена — смена сразу шлёт переход", () => {
    expect(switchSends(wire(), "repair")).toBe("repair");
    expect(switchSends(wire({ mode: "repair" }), "full")).toBe("on");
  });

  test("защита выключена — запроса нет", () => {
    expect(switchSends(wire({ mode: "off", active: false }), "repair")).toBeNull();
    expect(switchSends(wire({ mode: "", active: false }), "repair")).toBeNull();
  });

  test("то же положение и недоступная починка — запроса нет", () => {
    expect(switchSends(wire(), "full")).toBeNull();
    expect(switchSends(wire({ capabilities: { repair: false, trust_kinds: [] } }), "repair")).toBeNull();
  });
});
