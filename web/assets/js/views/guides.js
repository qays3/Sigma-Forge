import { GUIDE_GROUPS, GUIDES } from "../guides-data.js";
import { navigate, trackState } from "../router.js";
import { $, debounce, esc, icons } from "../ui.js";

function rich(text) {
  return esc(text).replace(/`([^`]+)`/g, '<code class="guide__code">$1</code>');
}

function byId(id) {
  return GUIDES.find((g) => g.id === id) || GUIDES[0];
}

function article(g) {
  const related = (g.related || []).map(byId).filter(Boolean);
  const i = GUIDES.indexOf(g);
  const prev = GUIDES[i - 1];
  const next = GUIDES[i + 1];
  return `
    <div class="guide__eyebrow">${esc(g.group)}</div>
    <div class="guide__top">
      <h2 class="guide__title">${esc(g.title)}</h2>
      ${g.route ? `<button class="btn btn--primary" type="button" data-go="${esc(g.route)}">${icons.external} Open this tool</button>` : ""}
    </div>
    <p class="guide__summary">${rich(g.summary)}</p>
    <ol class="guide__steps">${g.steps
      .map((s, n) => `<li class="guide__step"><span class="guide__num">${n + 1}</span><div class="guide__body"><div class="guide__stitle">${esc(s.title)}</div><p>${rich(s.text)}</p></div></li>`)
      .join("")}</ol>
    ${g.tips.length ? `<div class="guide__tips"><div class="field__label">Good to know</div><ul>${g.tips.map((t) => `<li>${rich(t)}</li>`).join("")}</ul></div>` : ""}
    ${related.length ? `<div class="guide__related"><div class="field__label">Related guides</div><div class="chips">${related.map((r) => `<button class="chip guide__chip" type="button" data-guide="${esc(r.id)}">${esc(r.title)}</button>`).join("")}</div></div>` : ""}
    <div class="guide__pager">
      ${prev ? `<button class="guide__page" type="button" data-guide="${esc(prev.id)}"><span class="muted">Previous</span><span>${esc(prev.title)}</span></button>` : "<span></span>"}
      ${next ? `<button class="guide__page guide__page--next" type="button" data-guide="${esc(next.id)}"><span class="muted">Next</span><span>${esc(next.title)}</span></button>` : "<span></span>"}
    </div>`;
}

export async function guidesView(root, route) {
  let current = byId(route.guide || "quick-start");
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Guides</div>
          <h1>How to use Sigma Forge</h1>
          <p>Step by step guides for every page and tool. Pick a topic, follow the steps, and open the tool from the guide.</p>
        </div>
      </div>
      <div class="guides">
        <aside class="guides__nav">
          <input class="input" type="search" id="gdQ" placeholder="Search guides" aria-label="Search guides">
          <select class="select guides__pick" id="gdPick" aria-label="Guide">${GUIDE_GROUPS.map((grp) => `<optgroup label="${esc(grp)}">${GUIDES.filter((g) => g.group === grp).map((g) => `<option value="${esc(g.id)}">${esc(g.title)}</option>`).join("")}</optgroup>`).join("")}</select>
          <nav class="guides__list" id="gdList" aria-label="Guides"></nav>
        </aside>
        <article class="card guide" id="gdBody"></article>
      </div>
    </section>`;

  const list = $("#gdList", root);
  const body = $("#gdBody", root);
  const paintList = () => {
    const q = $("#gdQ", root).value.trim().toLowerCase();
    const match = (g) => !q || `${g.title} ${g.summary} ${g.steps.map((s) => `${s.title} ${s.text}`).join(" ")}`.toLowerCase().includes(q);
    list.innerHTML = GUIDE_GROUPS.map((grp) => {
      const items = GUIDES.filter((g) => g.group === grp && match(g));
      if (!items.length) return "";
      return `<div class="guides__group">${esc(grp)}</div>${items.map((g) => `<button class="guides__item ${g.id === current.id ? "is-active" : ""}" type="button" data-guide="${esc(g.id)}">${esc(g.title)}</button>`).join("")}`;
    }).join("") || '<p class="muted">No guide matches.</p>';
  };
  const show = (id, scroll = true) => {
    current = byId(id);
    body.innerHTML = article(current);
    $("#gdPick", root).value = current.id;
    trackState({ guide: current.id });
    paintList();
    if (scroll && window.innerWidth < 1000) body.scrollIntoView({ block: "start" });
  };
  show(current.id, false);
  $("#gdQ", root).addEventListener("input", debounce(paintList, 120));
  $("#gdPick", root).addEventListener("change", (e) => show(e.target.value));
  root.addEventListener("click", (e) => {
    const g = e.target.closest("[data-guide]");
    if (g) {
      show(g.dataset.guide);
      if (g.closest(".guide")) window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    const go = e.target.closest("[data-go]");
    if (go) navigate(go.dataset.go);
  });
  return null;
}
