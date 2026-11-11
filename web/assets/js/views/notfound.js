import { emptyState } from "../ui.js";

export async function notFoundView(root) {
  root.innerHTML = `<section class="view"><div class="card">${emptyState("Page not found", "This page does not exist in Sigma Forge.", '<a class="btn btn--primary" href="/" data-link>Back to workspace</a>')}</div></section>`;
  return null;
}
