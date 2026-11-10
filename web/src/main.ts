import { mount } from "svelte";

import App from "./App.svelte";
import "./app.css";

// Тёмная тема — класс dark на <html>, по системной теме.
const dark = window.matchMedia("(prefers-color-scheme: dark)");
const applyTheme = () => document.documentElement.classList.toggle("dark", dark.matches);
applyTheme();
dark.addEventListener("change", applyTheme);

const target = document.getElementById("app");
if (!target) throw new Error("нет элемента #app");

export default mount(App, { target });
