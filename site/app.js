const $ = (id) => document.getElementById(id);
const RANK = { UNKNOWN: 0, NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };
const PAGE = 50;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let all = [], view = [], page = 0, loaded = false;

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sevOf = (c) => (RANK[c.severity] ? c.severity : "UNKNOWN");
const minSev = () => Number(document.querySelector('input[name="sev"]:checked').value);

async function load() {
  try {
    const r = await fetch("/data/cves.json", { cache: "no-cache" });
    if (!r.ok) throw new Error(r.status);
    const j = await r.json();
    all = j.cves;
    loaded = true;
    const when = new Date(j.generated).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
    $("meta").textContent = `${j.count.toLocaleString()} CVEs monitored &bull; Updated ${when}`;
  } catch {
    $("meta").textContent = "CVE threat intelligence stream is not available yet. Please check back soon.";
  }
  render();
}

function overview() {
  const count = (f) => all.filter(f).length;
  const n = { CRITICAL: count((x) => x.severity === "CRITICAL"), HIGH: count((x) => x.severity === "HIGH"), MEDIUM: count((x) => x.severity === "MEDIUM"), LOW: count((x) => x.severity === "LOW") };
  n.UNKNOWN = all.length - n.CRITICAL - n.HIGH - n.MEDIUM - n.LOW;
  const kev = count((x) => x.kev);
  const day = count((x) => Date.now() - Date.parse(x.published) < 864e5);
  const parts = [["CRITICAL", "Critical", "--crit"], ["HIGH", "High", "--high"], ["MEDIUM", "Medium", "--med"], ["LOW", "Low", "--low"], ["UNKNOWN", "Unscored", "--unk"]];
  const bar = $("sevbar");
  if (!bar.dataset.built || !bar.children.length) {
    bar.innerHTML = parts.map(([k, , v]) => `<span style="background:var(${v})"></span>`).join("");
    bar.dataset.built = "1";
  }
  [...bar.children].forEach((el, i) => el.style.setProperty("--grow", String(n[parts[i][0]])));
  bar.setAttribute("aria-label", "Severity distribution: " + parts.map(([k, l]) => `${n[k].toLocaleString()} ${l.toLowerCase()}`).join(", "));
  if (reducedMotion) bar.classList.add("ready"); else requestAnimationFrame(() => requestAnimationFrame(() => bar.classList.add("ready")));
  $("stats").innerHTML =
    parts.map(([k, l, v]) => `<li><b>${n[k].toLocaleString()}</b><span><i style="--dot:var(${v})"></i>${l}</span></li>`).join("") +
    `<li class="sep"><b>${kev.toLocaleString()}</b><span><i style="--dot:var(--crit)"></i>Known exploited</span></li>` +
    `<li><b>${day.toLocaleString()}</b><span><i style="--dot:var(--accent-color)"></i>Last 24 hours</span></li>`;
}

function apply() {
  const q = $("q").value.trim().toLowerCase();
  const kev = $("kev").checked;
  const epss = Number($("epss").value || 0) / 100;
  const cwe = $("cwe").value.trim().toUpperCase();
  const sort = $("sort").value;
  const min = minSev();
  view = all.filter((c) =>
    (RANK[c.severity] ?? 0) >= min && (!kev || c.kev) && (c.epss ?? 0) >= epss && (!cwe || c.cwes.includes(cwe)) &&
    (!q || c.id.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q) || c.vendors.some((v) => v.includes(q)) || c.products.some((p) => p.includes(q))));
  const key = { published: (c) => c.published, modified: (c) => c.modified, score: (c) => c.score ?? -1, epss: (c) => c.epss ?? -1 }[sort];
  view.sort((a, b) => (key(a) < key(b) ? 1 : key(a) > key(b) ? -1 : 0));
}

const isFiltered = () => $("q").value.trim() !== "" || minSev() !== 0 || $("kev").checked || Number($("epss").value || 0) > 0 || $("cwe").value.trim() !== "";

function item(c) {
  const sev = sevOf(c);
  const scored = c.score != null;
  const snippet = c.desc.length > 160 ? c.desc.slice(0, 160).trimEnd() + "\u2026" : c.desc;

  const vendorTags = c.vendors.slice(0, 6).map((v) => `<span class="tech-tag">${esc(v)}</span>`).join("");
  const productTags = c.products.slice(0, 6).map((p) => `<span class="tech-tag">${esc(p)}</span>`).join("");
  const cweTags = c.cwes.slice(0, 4).map((w) => `<span class="tech-tag tech-tag-cwe">${esc(w)}</span>`).join("");
  const tagsHtml = (vendorTags || productTags || cweTags) ? `<div class="tech-tags">${vendorTags}${productTags}${cweTags}</div>` : "";

  const refs = c.refs.filter((u) => /^https?:\/\//.test(u)).map((u) => {
    let host = u; try { host = new URL(u).hostname.replace(/^www\./, ""); } catch {}
    return `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer" class="ref-link"><span>${esc(host)}</span><span style="font-size: 0.72rem; opacity: 0.8;">&#8599;</span></a>`;
  }).join("");

  return `
  <li class="cve sev-${sev.toLowerCase()}">
    <div class="score" aria-label="${scored ? `CVSS ${c.score}, ` : ""}${esc(LABEL[sev] || "Unscored")} severity">
      <b>${scored ? esc(c.score) : "&ndash;"}</b>
      <span>${esc(LABEL[sev] || "Unscored")}</span>
    </div>
    <div class="body">
      <div class="head">
        <a class="id" href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener noreferrer">${esc(c.id)}</a>
        ${c.kev ? '<span class="kevtag" title="Listed in the CISA Known Exploited Vulnerabilities catalog"><span class="status-dot" style="background:#fca5a5; box-shadow:0 0 6px #ef4444; width:5px; height:5px;"></span>Known exploited</span>' : ""}
        <span class="when">Published ${esc(c.published.slice(0, 10))}</span>
      </div>

      <p class="cve-summary">${esc(snippet)}</p>

      <details class="more-desc">
        <summary class="cve-expand-trigger">
          <span class="trigger-label trigger-expand">
            <svg class="trigger-chevron" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
            <span>Technical Advisory &amp; Scope</span>
          </span>
          <span class="trigger-label trigger-collapse">
            <svg class="trigger-chevron" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="transform: rotate(180deg);"><polyline points="6 9 12 15 18 9"></polyline></svg>
            <span>Collapse Advisory</span>
          </span>
        </summary>
        <div class="cve-drawer">
          <div class="drawer-section">
            <span class="drawer-label">Full Vulnerability Analysis</span>
            <p class="full">${esc(c.desc)}</p>
          </div>
          ${tagsHtml ? `
          <div class="drawer-section">
            <span class="drawer-label">Affected Ecosystem &amp; Identifiers</span>
            ${tagsHtml}
          </div>` : ""}
          ${refs ? `
          <div class="drawer-section">
            <span class="drawer-label">Official Advisory References</span>
            <div class="refs">${refs}</div>
          </div>` : ""}
          <div class="drawer-collapse-hint">
            <span>Tap card to collapse</span>
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="transform: rotate(180deg);"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
        </div>
      </details>
    </div>
    <div class="side">${c.epss != null ? `<b>${(c.epss * 100).toFixed(1)}%</b>` : "<b>&ndash;</b>"}EPSS</div>
  </li>`;
}

function render() {
  overview();
  apply();
  const pages = Math.max(1, Math.ceil(view.length / PAGE));
  page = Math.min(page, pages - 1);
  const start = page * PAGE;
  const slice = view.slice(start, start + PAGE);
  $("rows").innerHTML = slice.map(item).join("") ||
    `<li class="empty">${loaded ? "No CVEs match these filters. Try lowering the severity or clearing the search." : "CVE threat intelligence stream is not available yet."}</li>`;
  $("count").textContent = view.length
    ? `Showing ${(start + 1).toLocaleString()}\u2013${(start + slice.length).toLocaleString()} of ${view.length.toLocaleString()} CVEs`
    : "0 CVEs";
  $("page").textContent = `Page ${page + 1} of ${pages}`;
  $("prev").disabled = page === 0;
  $("next").disabled = page >= pages - 1;
  $("reset").hidden = !isFiltered();
}

const toTop = () => $("feed").scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "start" });
for (const id of ["q", "kev", "epss", "cwe", "sort"]) $(id).addEventListener("input", () => { page = 0; render(); });
$("sev").addEventListener("change", () => { page = 0; render(); });
$("prev").onclick = () => { page--; render(); toTop(); };
$("next").onclick = () => { page++; render(); toTop(); };
$("reset").onclick = () => {
  $("q").value = ""; $("kev").checked = false; $("epss").value = "0"; $("cwe").value = "";
  document.querySelector('input[name="sev"][value="0"]').checked = true;
  page = 0; render(); $("q").focus();
};

// Floating "Get alerts" button on small screens: hide it while the form is on screen.
if ("IntersectionObserver" in window) {
  new IntersectionObserver(([e]) => $("fab").classList.toggle("is-hidden", e.isIntersecting), { threshold: 0.05 }).observe($("subscribe"));
}

function toggleDetailsSmooth(details, summary) {
  if (reducedMotion) {
    details.open = !details.open;
    return;
  }

  if (details.dataset.animating === "true") return;

  if (details.open) {
    // Smooth collapse
    details.dataset.animating = "true";
    details.style.overflow = "hidden";
    const startHeight = details.offsetHeight;
    const endHeight = summary ? summary.offsetHeight : 36;

    const animation = details.animate(
      [
        { height: `${startHeight}px`, opacity: 1 },
        { height: `${endHeight}px`, opacity: 0.85 }
      ],
      {
        duration: 320,
        easing: "cubic-bezier(0.2, 0.8, 0.2, 1)"
      }
    );

    animation.onfinish = () => {
      details.open = false;
      details.dataset.animating = "false";
      details.style.height = "";
      details.style.overflow = "";
    };
    animation.oncancel = () => {
      details.dataset.animating = "false";
      details.style.height = "";
      details.style.overflow = "";
    };
  } else {
    // Smooth expand
    details.dataset.animating = "true";
    details.style.overflow = "hidden";
    const startHeight = summary ? summary.offsetHeight : 36;
    details.open = true;
    const endHeight = details.offsetHeight;

    const animation = details.animate(
      [
        { height: `${startHeight}px`, opacity: 0.7 },
        { height: `${endHeight}px`, opacity: 1 }
      ],
      {
        duration: 360,
        easing: "cubic-bezier(0.16, 1, 0.3, 1)"
      }
    );

    animation.onfinish = () => {
      details.dataset.animating = "false";
      details.style.height = "";
      details.style.overflow = "";
    };
    animation.oncancel = () => {
      details.dataset.animating = "false";
      details.style.height = "";
      details.style.overflow = "";
    };
  }
}

// Butter-smooth accordion expand & collapse animation for all details elements and cards
function initSmoothAccordion() {
  document.addEventListener("click", (e) => {
    // 1. If clicking any link or interactive form element, allow normal behavior
    if (e.target.closest("a, input, select, textarea, button:not(.cve-expand-trigger)")) {
      return;
    }

    // 2. Ignore if user is selecting/highlighting text
    const selection = window.getSelection();
    if (selection && selection.toString().trim().length > 0) {
      return;
    }

    // 3. If clicking anywhere on or inside a .cve card, toggle its details
    const cveCard = e.target.closest(".cve");
    if (cveCard) {
      const details = cveCard.querySelector(".more-desc");
      if (details) {
        const summary = details.querySelector("summary");
        e.preventDefault();
        toggleDetailsSmooth(details, summary);
        return;
      }
    }

    // 4. Fallback for other standalone details elements like .more in filters or subscribe
    const summary = e.target.closest("summary");
    if (summary && summary.parentElement && summary.parentElement.classList.contains("more")) {
      e.preventDefault();
      toggleDetailsSmooth(summary.parentElement, summary);
    }
  });
}

// ---- Subscribe form ----
let tsWidget = null;
async function initTurnstile() {
  try {
    const { turnstileSiteKey } = await (await fetch("/api/config")).json();
    const t0 = Date.now();
    const timer = setInterval(() => {
      if (window.turnstile) { clearInterval(timer); tsWidget = window.turnstile.render("#ts", { sitekey: turnstileSiteKey, size: "flexible", theme: "auto" }); }
      else if (Date.now() - t0 > 10000) clearInterval(timer);
    }, 200);
  } catch { /* the form reports a CAPTCHA error on submit */ }
}
const list = (s) => String(s || "").split(",").map((x) => x.trim()).filter(Boolean);

$("subform").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const msg = $("subMsg"), btn = $("subbtn");
  msg.className = "msg";
  msg.textContent = "Submitting\u2026";
  btn.disabled = true;
  const body = {
    email: f.get("email"),
    turnstile: window.turnstile && tsWidget !== null ? window.turnstile.getResponse(tsWidget) : "",
    filters: {
      minSeverity: f.get("minSeverity"), kevOnly: f.get("kevOnly") === "on", minEpss: Number(f.get("minEpss") || 0) / 100,
      vendors: list(f.get("vendors")), keywords: list(f.get("keywords")), cwes: list(f.get("cwes")),
    },
  };
  try {
    const r = await fetch("/api/subscribe", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    msg.textContent = j.message || j.error || "Something went wrong. Please try again.";
    msg.className = "msg " + (j.ok ? "ok" : "err");
    if (j.ok) ev.target.reset();
  } catch { msg.textContent = "Network error. Check your connection and try again."; msg.className = "msg err"; }
  btn.disabled = false;
  if (window.turnstile && tsWidget !== null) window.turnstile.reset(tsWidget);
});

load();
initTurnstile();
initSmoothAccordion();

// Support (Patreon) dialog
{
  const dlg = $("supportDlg");
  if (dlg && typeof dlg.showModal === "function") {
    document.querySelectorAll("[data-support]").forEach((b) => b.addEventListener("click", () => dlg.showModal()));
    $("supportClose").addEventListener("click", () => dlg.close());
    dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
  } else {
    document.querySelectorAll("[data-support]").forEach((b) => b.addEventListener("click", () => window.open("https://www.patreon.com/Infomity", "_blank", "noopener,noreferrer")));
  }
}
