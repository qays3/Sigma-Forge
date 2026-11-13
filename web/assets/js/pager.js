const SIZE = 200;
const seen = new WeakMap();
const live = new Set();
const ARROW_L = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 18l-6-6 6-6"/></svg>';
const ARROW_R = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18l6-6-6-6"/></svg>';

export function pageList(page, pages) {
  const want = new Set([1, pages, page - 1, page, page + 1]);
  if (page <= 3) [2, 3, 4].forEach((n) => want.add(n));
  if (page >= pages - 2) [pages - 1, pages - 2, pages - 3].forEach((n) => want.add(n));
  const nums = [...want].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b);
  const out = [];
  nums.forEach((n, i) => {
    if (i && n - nums[i - 1] > 1) out.push(0);
    out.push(n);
  });
  return out;
}

export function pagerHtml(page, pages, total, size = SIZE) {
  const from = (page - 1) * size + 1;
  const to = Math.min(total, page * size);
  const btn = (n) => (n ? `<button class="pager__btn ${n === page ? "is-active" : ""}" type="button" data-page="${n}" ${n === page ? 'aria-current="page"' : ""}>${n}</button>` : '<span class="pager__gap">…</span>');
  return `<button class="pager__btn" type="button" data-page="${page - 1}" ${page === 1 ? "disabled" : ""} aria-label="Previous page">${ARROW_L}</button>${pageList(page, pages).map(btn).join("")}<button class="pager__btn" type="button" data-page="${page + 1}" ${page === pages ? "disabled" : ""} aria-label="Next page">${ARROW_R}</button><div class="pager__info">${from.toLocaleString()} to ${to.toLocaleString()} of ${total.toLocaleString()}</div>`;
}

function show(tbody, st, scroll) {
  const rows = [...tbody.rows];
  const pages = Math.max(1, Math.ceil(rows.length / SIZE));
  st.page = Math.min(Math.max(1, st.page), pages);
  const start = (st.page - 1) * SIZE;
  rows.forEach((tr, i) => tr.classList.toggle("is-paged-out", i < start || i >= start + SIZE));
  st.pager.innerHTML = pagerHtml(st.page, pages, rows.length);
  if (scroll) {
    const table = tbody.closest("table");
    if (table.getBoundingClientRect().top < 0) table.scrollIntoView({ block: "start", behavior: "smooth" });
  }
}

function apply(table) {
  const tbody = table.tBodies[0];
  if (!tbody) return;
  const rows = tbody.rows;
  let st = seen.get(tbody);
  if (rows.length <= SIZE) {
    if (st) {
      [...rows].forEach((tr) => tr.classList.remove("is-paged-out"));
      st.pager.remove();
      seen.delete(tbody);
      live.delete(st);
    }
    return;
  }
  const first = rows[0];
  if (st && st.first === first && st.count === rows.length && st.pager.isConnected) return;
  if (!st) {
    const pager = document.createElement("nav");
    pager.className = "pager";
    pager.setAttribute("aria-label", "Pages");
    st = { page: 1, pager, tbody };
    live.add(st);
    pager.addEventListener("click", (e) => {
      const b = e.target.closest("[data-page]");
      if (!b || b.disabled) return;
      st.page = Number(b.dataset.page);
      show(tbody, st, true);
    });
    seen.set(tbody, st);
  } else if (st.first !== first) {
    st.page = 1;
  }
  st.first = first;
  st.count = rows.length;
  if (!st.pager.isConnected) (table.closest(".table-wrap") || table).after(st.pager);
  show(tbody, st, false);
}

let queued = false;
function scan() {
  queued = false;
  live.forEach((st) => {
    if (!st.tbody.isConnected) {
      st.pager.remove();
      live.delete(st);
      seen.delete(st.tbody);
    }
  });
  document.querySelectorAll("table.table").forEach(apply);
}

export function startPager() {
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(scan);
  }).observe(document.body, { childList: true, subtree: true });
  scan();
}
