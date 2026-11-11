import { mount } from "svelte";

import App from "./App.svelte";
import "./app.css";
import favicon from "./favicon.ico?url&inline";

// Значок вкладки — data: URI в сборке: файлы окна отдаются только с cookie сеанса, значок от неё не зависит.
// favicon.ico рисует dist/icon (render.sh, gen).
const icon = document.createElement("link");
icon.rel = "icon";
icon.sizes.value = "16x16 32x32 48x48";
icon.href = favicon;
document.head.append(icon);

// Тёмная тема — класс dark на <html>, по системной теме.
const dark = window.matchMedia("(prefers-color-scheme: dark)");
const applyTheme = () => document.documentElement.classList.toggle("dark", dark.matches);
applyTheme();
dark.addEventListener("change", applyTheme);

const target = document.getElementById("app");
if (!target) throw new Error("нет элемента #app");

export default mount(App, { target });
