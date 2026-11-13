import { diffHtml, lineDiff, openInEditor } from "../shared.js";
import { store } from "../store.js";
import { can, teamApi, teamState } from "../team.js";
import { $, $$, emptyState, esc, icons, skeleton, toast } from "../ui.js";

const STATUS = { pending: ["Waiting", "warn"], approved: ["Approved", "ok"], changes: ["Changes asked", "bad"] };

export async function reviewsView(root) {
  root.innerHTML = `
    <section class="view">
      <div class="page-head">
        <div>
          <div class="page-head__eyebrow">Reviews</div>
          <h1>Rule reviews</h1>
          <p>A teammate checks every change before it goes live. Ask for a review from the editor, then a reviewer approves it or asks for changes. ${teamState.requireReview ? "<strong>This server only deploys approved rules.</strong>" : "Turn on SIGMA_FORGE_REQUIRE_REVIEW=1 to block deploys of rules that are not approved."}</p>
        </div>
      </div>
      <div class="cases">
        <aside class="cases__side">
          <div class="seg seg--full" id="rvSeg"><button class="seg__btn is-active" type="button" data-s="pending">Waiting</button><button class="seg__btn" type="button" data-s="changes">Changes</button><button class="seg__btn" type="button" data-s="approved">Approved</button><button class="seg__btn" type="button" data-s="">All</button></div>
          <ul class="list cases__list mt-4" id="rvList">${skeleton.rows(4)}</ul>
        </aside>
        <div class="cases__main" id="rvMain"></div>
      </div>
    </section>`;
  if (!teamState.auth) {
    $("#rvMain", root).innerHTML = `<div class="card">${emptyState("Team mode is off", "Reviews need users. Start Sigma Forge with SIGMA_FORGE_AUTH=1 and sign in.")}</div>`;
    $("#rvList", root).innerHTML = "";
    return null;
  }
  let items = [];
  let filter = "pending";
  let current = "";
  const load = async () => {
    items = (await teamApi.get("/api/team/reviews")).reviews;
  };
  const paintList = () => {
    const list = items.filter((r) => !filter || r.status === filter);
    $("#rvList", root).innerHTML = list.length
      ? list.map((r) => `<li class="list__item cases__item ${r.name === current ? "is-active" : ""}" data-n="${esc(r.name)}"><div class="list__main"><div class="list__title mono">${esc(r.name)}</div><div class="list__meta">${esc(r.requested_by)} · ${esc(r.requested)}${r.outdated ? " · edited since" : ""}</div></div><span class="badge badge--${STATUS[r.status][1]}">${STATUS[r.status][0]}</span></li>`).join("")
      : '<li class="list__item muted">Nothing here.</li>';
  };
  const paintMain = () => {
    const r = items.find((x) => x.name === current);
    const main = $("#rvMain", root);
    if (!r) {
      main.innerHTML = `<div class="card">${emptyState("Pick a review", "Open the editor and press Request review to start one.")}</div>`;
      return;
    }
    const mine = r.requested_by === teamState.user.username;
    const decide = can("review") && !(mine);
    main.innerHTML = `
      <div class="card"><div class="card__body">
        <div class="row"><span class="badge badge--${STATUS[r.status][1]}">${STATUS[r.status][0]}</span><span class="list__title mono">${esc(r.name)}</span><div class="spacer"></div><button class="btn btn--sm" type="button" id="rvOpen">${icons.file} Open in editor</button></div>
        <p class="muted mt-4">Asked by ${esc(r.requested_by)} on ${esc(r.requested)}${r.decided_by ? `. ${esc(r.status === "approved" ? "Approved" : "Changes asked")} by ${esc(r.decided_by)} on ${esc(r.decided)}` : ""}.</p>
        ${r.outdated ? '<div class="notice notice--warn mt-4">The rule was edited after this review was asked. The approval does not cover the new version, so ask again.</div>' : ""}
        ${!r.in_workspace ? '<div class="notice mt-4">This rule is no longer in the team workspace.</div>' : ""}
      </div></div>
      <div class="card mt-4"><div class="card__head"><span class="card__title">${r.previous ? "Changes since the last approval" : "New rule"}</span></div><div class="card__body">${r.previous ? diffHtml(lineDiff(r.previous, r.content)) : `<pre class="code">${esc(r.content)}</pre>`}</div></div>
      <div class="card mt-4"><div class="card__head"><span class="card__title">Conversation</span></div><div class="card__body">
        <ul class="case__notes">${r.thread.map((t) => `<li><span class="mono muted">${esc(t.time)} · ${esc(t.user)} · ${esc({ request: "asked for review", approved: "approved", changes: "asked for changes", comment: "commented" }[t.kind] || t.kind)}</span>${t.text ? `<p>${esc(t.text)}</p>` : ""}</li>`).join("")}</ul>
        <textarea class="textarea mt-4 rv__text" id="rvText" rows="3" placeholder="Write a comment or the reason for your decision"></textarea>
        <div class="row mt-4"><button class="btn" type="button" id="rvComment">Comment</button><div class="spacer"></div>
          ${decide ? `<button class="btn btn--danger" type="button" data-d="changes">Ask for changes</button><button class="btn btn--primary" type="button" data-d="approved" ${r.outdated ? "disabled" : ""}>${icons.check} Approve</button>` : `<span class="muted">${mine ? "Another reviewer has to decide on your change." : "Only reviewers and admins decide."}</span>`}
        </div>
      </div></div>`;
    $("#rvOpen", main).addEventListener("click", async () => {
      const rules = await store.all();
      const f = rules.find((x) => x.name === r.name);
      openInEditor(r.name, f ? f.content : r.content, f?.id || "");
    });
    $("#rvComment", main).addEventListener("click", async () => {
      const text = $("#rvText", main).value.trim();
      if (!text) return;
      try {
        await teamApi.post("/api/team/reviews/comment", { name: r.name, text });
        await load();
        paintMain();
      } catch (err) {
        toast(err.message, "bad");
      }
    });
    $$("[data-d]", main).forEach((b) =>
      b.addEventListener("click", async () => {
        try {
          await teamApi.post("/api/team/reviews/decide", { name: r.name, decision: b.dataset.d, note: $("#rvText", main).value.trim() });
          await load();
          paintList();
          paintMain();
          await store.refresh();
          toast(b.dataset.d === "approved" ? "Approved" : "Changes asked", "ok");
        } catch (err) {
          toast(err.message, "bad");
        }
      }),
    );
  };
  try {
    await load();
  } catch (err) {
    $("#rvMain", root).innerHTML = `<div class="notice notice--bad">${esc(err.message)}</div>`;
    return null;
  }
  current = items.find((r) => r.status === "pending")?.name || items[0]?.name || "";
  paintList();
  paintMain();
  $("#rvSeg", root).addEventListener("click", (e) => {
    const b = e.target.closest("[data-s]");
    if (!b) return;
    filter = b.dataset.s;
    $$("#rvSeg [data-s]", root).forEach((x) => x.classList.toggle("is-active", x === b));
    paintList();
  });
  $("#rvList", root).addEventListener("click", (e) => {
    const li = e.target.closest("[data-n]");
    if (!li) return;
    current = li.dataset.n;
    paintList();
    paintMain();
  });
  return null;
}
