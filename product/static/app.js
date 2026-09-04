const state = { tab: "findings", rows: [], summary: null };

const COLS = {
  findings: [
    ["severity", "Severity"],
    ["ref_id", "Ref"],
    ["name", "Name"],
    ["description", "Description"],
    ["status", "Status"],
  ],
  assets: [
    ["type", "Type"],
    ["ref_id", "Ref"],
    ["name", "Name"],
    ["description", "Description"],
    ["filtering_labels", "Labels"],
  ],
  vulns: [
    ["severity", "Severity"],
    ["ref_id", "Ref"],
    ["name", "Name"],
    ["description", "Description"],
    ["assets", "Assets"],
  ],
  proposed: [
    ["severity", "Severity"],
    ["ref_id", "Ref"],
    ["name", "Name"],
    ["likelihood", "Likelihood"],
    ["impact", "Impact"],
    ["source", "Source"],
  ],
  evidence: [
    ["name", "Name"],
    ["description", "Description"],
  ],
};

const ENDPOINTS = {
  findings: "/api/findings",
  assets: "/api/assets",
  vulns: "/api/vulnerabilities",
  proposed: "/api/proposed",
  evidence: "/api/evidences",
};

function $(id) {
  return document.getElementById(id);
}

async function getJson(url) {
  const res = await fetch(url, { cache: "no-store" });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function fmt(n) {
  return n == null ? "—" : String(n);
}

function renderKpis(estate) {
  const s = estate.summary || {};
  const sev = estate.severity || {};
  const items = [
    [s.assets, "Assets", ""],
    [s.findings, "Findings", ""],
    [sev.critical, "Critical", "crit"],
    [sev.high, "High", "high"],
    [s.vulnerabilities, "Vulns", ""],
    [s.evidences, "Evidence", ""],
    [s.risks_proposed, "Proposed", ""],
  ];
  $("kpis").innerHTML = items
    .map(
      ([n, label, cls]) =>
        `<div class="kpi ${cls}"><b>${fmt(n)}</b><span>${label}</span></div>`
    )
    .join("");
}

function matches(row, q, sev) {
  if (sev) {
    const val = String(row.severity || row.Severity || "").toLowerCase();
    if (val !== sev) return false;
  }
  if (!q) return true;
  return Object.values(row).some((v) => String(v ?? "").toLowerCase().includes(q));
}

function cell(key, row) {
  const raw = row[key];
  const text = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
  if (key === "severity") {
    const cls = text.toLowerCase();
    return `<td><span class="sev ${cls}">${text}</span></td>`;
  }
  return `<td>${escapeHtml(text)}</td>`;
}

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderTable() {
  const q = $("q").value.trim().toLowerCase();
  const sev = $("sev").value;
  const cols = COLS[state.tab];
  const rows = state.rows.filter((r) => matches(r, q, sev));
  $("proposed-note").classList.toggle("hidden", state.tab !== "proposed");
  if (!rows.length) {
    $("table-wrap").innerHTML = "<p>No rows match.</p>";
    return;
  }
  const head = cols.map(([, label]) => `<th>${label}</th>`).join("");
  const body = rows
    .map((row) => `<tr>${cols.map(([key]) => cell(key, row)).join("")}</tr>`)
    .join("");
  $("table-wrap").innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

async function loadTab() {
  state.rows = await getJson(ENDPOINTS[state.tab]);
  renderTable();
}

async function boot() {
  try {
    const estate = await getJson("/api/summary");
    state.summary = estate;
    $("demo-pill").classList.toggle("hidden", !estate.demo);
    const when = estate.summary && estate.summary.generated_at ? estate.summary.generated_at : "unknown";
    $("status-bar").textContent = estate.ready
      ? `Ready · ${estate.summary.canonical} canonical records · generated ${when}`
      : "No estate yet. Click Refresh estate.";
    $("status-bar").classList.toggle("bad", !estate.ready);
    renderKpis(estate);
    $("paths").textContent = `${estate.out_dir}  ·  ${estate.repo}`;
    await loadTab();
  } catch (err) {
    $("status-bar").textContent = String(err.message || err);
    $("status-bar").classList.add("bad");
  }
}

document.querySelectorAll(".tabs button").forEach((btn) => {
  btn.addEventListener("click", async () => {
    document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("on"));
    btn.classList.add("on");
    state.tab = btn.dataset.tab;
    $("q").value = "";
    await loadTab();
  });
});

$("q").addEventListener("input", renderTable);
$("sev").addEventListener("change", renderTable);

$("btn-refresh").addEventListener("click", async () => {
  const btn = $("btn-refresh");
  btn.disabled = true;
  $("status-bar").textContent = "Refreshing collectors + loader (local files only)…";
  try {
    await fetch("/api/refresh", { method: "POST" }).then(async (res) => {
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    });
    await boot();
  } catch (err) {
    $("status-bar").textContent = String(err.message || err);
    $("status-bar").classList.add("bad");
  } finally {
    btn.disabled = false;
  }
});

boot();
