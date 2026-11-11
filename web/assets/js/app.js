import { api } from "./api.js";
import { route, startRouter } from "./router.js";
import { store } from "./store.js";
import { $, hideSplash, initDrawer, plural, splashText } from "./ui.js";
import { workspaceView } from "./views/workspace.js";
import { convertView } from "./views/convert.js";
import { coverageView } from "./views/coverage.js";
import { rulesView } from "./views/rules.js";
import { notFoundView } from "./views/notfound.js";

const THEME_KEY = "sigma-forge-theme";

function readTheme() {
  try {
    return localStorage.getItem(THEME_KEY);
  } catch {
    return null;
  }
}

function applyTheme(theme) {
  if (theme === "light") document.documentElement.setAttribute("data-theme", "light");
  else document.documentElement.removeAttribute("data-theme");
}

function initTheme() {
  applyTheme(readTheme());
  $("#themeToggle").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    applyTheme(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      return;
    }
  });
}

function initHeader() {
  const bar = $("#topbar");
  const onScroll = () => bar.classList.toggle("is-shrunk", window.scrollY > 24);
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
  const toggle = $("#navToggle");
  toggle.addEventListener("click", () => {
    const nav = $("#mainNav");
    const open = nav.classList.toggle("is-open");
    toggle.setAttribute("aria-expanded", String(open));
  });
}

async function updateCount() {
  const rules = await store.all();
  $("#ruleCount").textContent = plural(rules.length, "rule");
}

async function checkEngine() {
  try {
    splashText("Checking the engine");
    await api.health();
  } catch {
    splashText("Server offline");
  }
}

async function boot() {
  const started = Date.now();
  await Promise.all([checkEngine(), updateCount()]);
  startRouter($("#main"));
  const wait = Math.max(0, 900 - (Date.now() - started));
  setTimeout(hideSplash, wait);
}

route("/", "workspace", workspaceView);
route("/convert", "convert", convertView);
route("/coverage", "coverage", coverageView);
route("/rules", "rules", rulesView);
route("*", "notfound", notFoundView);

initTheme();
initHeader();
initDrawer();
store.onChange(updateCount);
boot();
