import { $$, closeDrawer } from "./ui.js";

const routes = new Map();
const GUIDE_FOR = {
  workspace: "workspace", convert: "convert", coverage: "coverage", rules: "rules", editor: "editor", compare: "compare", test: "test-logs",
  library: "library", mappings: "mappings", yara: "yara", hunt: "hunt-live", purple: "purple", inventory: "inventory", cases: "cases", firecheck: "fire-check", reviews: "reviews", team: "team",
};
const GUIDE_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5a2 2 0 0 1 2-2h12v16H6a2 2 0 0 0-2 2z"/><path d="M4 21V5M8 7h6M8 11h6"/></svg>';

function addGuideButton(root, name) {
  const id = GUIDE_FOR[name];
  if (!id) return;
  const head = root.querySelector(".page-head__eyebrow, .hero");
  if (!head || root.querySelector(".guide-btn")) return;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "guide-btn";
  btn.title = "How to use this page";
  btn.innerHTML = `${GUIDE_ICON}<span>Guide</span>`;
  btn.addEventListener("click", () => navigate("/guides", { guide: id }));
  head.appendChild(btn);
}
let current = null;
let outlet = null;

export function route(path, name, view) {
  routes.set(path, { name, view });
}

function match(pathname) {
  const clean = pathname.replace(/\/+$/, "") || "/";
  return routes.get(clean) || routes.get("*");
}

async function render() {
  const entry = match(location.pathname);
  if (!entry) return;
  if (current?.destroy) current.destroy();
  closeDrawer();
  $$(".nav__link").forEach((a) => {
    const active = a.dataset.route === entry.name || (a.dataset.also || "").split(" ").includes(entry.name);
    a.classList.toggle("is-active", active);
    if (active) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  document.getElementById("mainNav")?.classList.remove("is-open");
  document.getElementById("navToggle")?.setAttribute("aria-expanded", "false");
  const fresh = outlet.cloneNode(false);
  outlet.replaceWith(fresh);
  outlet = fresh;
  outlet.dataset.route = entry.name;
  const view = outlet;
  const pending = entry.view(view, routeState());
  addGuideButton(view, entry.name);
  current = (await pending) || null;
  addGuideButton(view, entry.name);
  document.title = entry.name === "workspace" ? "Sigma Forge" : `${({ yara: "YARA", firecheck: "Fire check" })[entry.name] || entry.name[0].toUpperCase() + entry.name.slice(1)} | Sigma Forge`;
  window.scrollTo({ top: 0 });
}

function cleanPath(path) {
  return (path.split(/[?#]/)[0].replace(/\/+$/, "")) || "/";
}

export function routeState() {
  return { ...(history.state || {}) };
}

export function trackState(patch) {
  const next = { ...(history.state || {}), ...patch };
  Object.keys(next).forEach((k) => next[k] === undefined && delete next[k]);
  history.replaceState(next, "", location.pathname);
}

export function navigate(path, state = {}) {
  const target = cleanPath(path);
  if (target === location.pathname && !Object.keys(state).length) return;
  history.pushState(state, "", target);
  render();
}

export function startRouter(target) {
  outlet = target;
  document.addEventListener("click", (e) => {
    const link = e.target.closest("a[data-link]");
    if (!link || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(link.getAttribute("href"));
  });
  window.addEventListener("popstate", render);
  if (location.search || location.hash) history.replaceState(history.state || {}, "", cleanPath(location.pathname));
  render();
}
