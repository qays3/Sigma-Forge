import { api } from "./api.js";
import { animateFavicon } from "./favicon.js";
import { route, startRouter } from "./router.js";
import { store } from "./store.js";
import { $, hideSplash, initDrawer, plural, splashText } from "./ui.js";
import { workspaceView } from "./views/workspace.js";
import { convertView } from "./views/convert.js";
import { coverageView } from "./views/coverage.js";
import { rulesView } from "./views/rules.js";
import { editorView } from "./views/editor.js";
import { compareView } from "./views/compare.js";
import { testView } from "./views/test.js";
import { libraryView } from "./views/library.js";
import { mappingsView } from "./views/mappings.js";
import { yaraView } from "./views/yara.js";
import { huntView } from "./views/hunt.js";
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
  const btn = document.getElementById("themeToggle");
  if (btn) {
    btn.setAttribute("aria-checked", String(theme !== "light"));
    btn.setAttribute("aria-label", theme === "light" ? "Light theme" : "Dark theme");
  }
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

const SIDE_KEY = "sigma-forge-side";

function initHeader() {
  const root = document.documentElement;
  try {
    if (localStorage.getItem(SIDE_KEY) === "mini") root.setAttribute("data-side", "mini");
  } catch {
    root.removeAttribute("data-side");
  }
  $("#sideCollapse").addEventListener("click", () => {
    const mini = root.getAttribute("data-side") !== "mini";
    if (mini) root.setAttribute("data-side", "mini");
    else root.removeAttribute("data-side");
    $("#sideCollapse").setAttribute("aria-label", mini ? "Expand menu" : "Collapse menu");
    try {
      localStorage.setItem(SIDE_KEY, mini ? "mini" : "full");
    } catch {
      return;
    }
  });
  const toggle = $("#navToggle");
  const nav = $("#mainNav");
  const setOpen = (open) => {
    nav.classList.toggle("is-open", open);
    toggle.setAttribute("aria-expanded", String(open));
  };
  toggle.addEventListener("click", () => setOpen(!nav.classList.contains("is-open")));
  $("#sideScrim").addEventListener("click", () => setOpen(false));
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
route("/editor", "editor", editorView);
route("/compare", "compare", compareView);
route("/test", "test", testView);
route("/library", "library", libraryView);
route("/mappings", "mappings", mappingsView);
route("/yara", "yara", yaraView);
route("/hunt", "hunt", huntView);
route("*", "notfound", notFoundView);

initTheme();
initHeader();
initDrawer();
store.onChange(updateCount);
boot();
animateFavicon();
