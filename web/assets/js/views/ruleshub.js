import { trackState } from "../router.js";
import { state } from "../state.js";
import { $, $$, esc, icons } from "../ui.js";
import { rulesView } from "./rules.js";
import { sigmaFilesView } from "./sigmafiles.js";
import { yaraView } from "./yara.js";
import { yaraStore } from "./yarakit.js";

const MODE_KEY = "sigma-forge-sigma-view";
const TABS = [
  ["sigma", "/rules", "Sigma", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1.2"/><circle cx="4.5" cy="12" r="1.2"/><circle cx="4.5" cy="18" r="1.2"/></svg>'],
  ["yara", "/yara", "YARA", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 4 6v6c0 4.5 3.4 8 8 9 4.6-1 8-4.5 8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'],
];

export function rulesHub(tab, forceMode = "") {
  return async (root, route) => {
    let mode = forceMode || route.view || "";
    if (!mode) {
      try {
        mode = localStorage.getItem(MODE_KEY) || "files";
      } catch {
        mode = "files";
      }
    }
    root.innerHTML = `
      <div class="hub">
        <nav class="hub__bar" aria-label="Rules">
          <div class="hub__tabs" role="tablist">${TABS.map(([k, href, label, svg]) => `<a class="hub__tab ${k === tab ? "is-active" : ""}" href="${href}" data-link role="tab" aria-selected="${k === tab}" ${k === tab ? 'aria-current="page"' : ""}>${svg}<span>${esc(label)}<span class="hub__extra"> rules</span></span><span class="hub__count" data-count="${k}"></span></a>`).join("")}</div>
          ${tab === "sigma" ? `<div class="seg hub__mode" id="hubMode" role="tablist" aria-label="Sigma view"><button class="seg__btn" type="button" data-mode="files">Files and editor</button><button class="seg__btn" type="button" data-mode="table">Table</button></div>` : ""}
          <a class="btn btn--sm hub__lib" href="/library" data-link id="hubLib" title="${tab === "yara" ? "Add YARA Forge rules" : "Add SigmaHQ rules"}">${icons.download} ${tab === "yara" ? "YARA library" : "Sigma library"}</a>
        </nav>
        <div class="hub__pane"></div>
      </div>`;
    const counts = async () => {
      const y = $('[data-count="yara"]', root);
      if (y) y.textContent = String(yaraStore.all().length);
      const s = $('[data-count="sigma"]', root);
      if (s) s.textContent = String((await state.rules()).length);
    };
    counts().catch(() => {});
    $("#hubLib", root).addEventListener("click", () => {
      try {
        localStorage.setItem("sigma-forge-library-source", tab === "yara" ? "yara" : "sigma");
      } catch {}
    });
    let view = null;
    const pane = $(".hub__pane", root);
    const show = async (next, r) => {
      view?.destroy?.();
      view = null;
      mode = next;
      $$("#hubMode [data-mode]", root).forEach((b) => b.classList.toggle("is-active", b.dataset.mode === mode));
      try {
        localStorage.setItem(MODE_KEY, mode);
      } catch {}
      view = await (mode === "table" ? rulesView(pane, r) : sigmaFilesView(pane, r));
    };
    if (tab === "yara") {
      view = await yaraView(pane, route);
    } else {
      $("#hubMode", root).addEventListener("click", (e) => {
        const b = e.target.closest("[data-mode]");
        if (!b || b.dataset.mode === mode) return;
        trackState({ view: b.dataset.mode });
        show(b.dataset.mode, {});
      });
      await show(mode === "table" ? "table" : "files", route);
    }
    return {
      destroy() {
        view?.destroy?.();
      },
    };
  };
}
