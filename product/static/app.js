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
  poam: [
    ["severity", "Severity"],
    ["weakness", "Weakness"],
    ["asset", "Asset"],
    ["framework_refs", "Framework"],
    ["recommended_fix", "Recommended fix"],
    ["status", "Status"],
  ],
};

const ENDPOINTS = {
  findings: "/api/findings",
  assets: "/api/assets",
  vulns: "/api/vulnerabilities",
  proposed: "/api/proposed",
  evidence: "/api/evidences",
  poam: "/api/poam",
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

function isReload(estate) {
  if (!estate) return false;
  return (
    estate.refresh_mode === "reload" ||
    !!estate.lab ||
    !!estate.use_existing_in ||
    (estate.ready && !estate.demo)
  );
}

function applyHonesty(estate) {
  const lab = !!estate.lab;
  const sample = !!estate.sample;
  const demo = !!estate.demo;
  $("lab-pill").classList.toggle("hidden", !lab);
  $("sample-pill").classList.toggle("hidden", !sample);
  $("demo-pill").classList.toggle("hidden", !demo);
  $("client-pill").classList.toggle("hidden", estate.client !== false);
  const btn = $("btn-refresh");
  btn.textContent = isReload(estate) ? "Reload from disk" : "Refresh estate";
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
  const poamNote = $("poam-note");
  if (poamNote) poamNote.classList.toggle("hidden", state.tab !== "poam");
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

function optionLabel(run) {
  const pref = run.preferred ? " · latest lab-prove" : "";
  return `${run.stamp} · ${run.honesty_label}${pref}`;
}

async function loadRuns() {
  const wrap = $("run-picker-wrap");
  const sel = $("run-picker");
  if (!wrap || !sel) return;
  try {
    const data = await getJson("/api/runs");
    const runs = Array.isArray(data.runs) ? data.runs : [];
    wrap.classList.toggle("hidden", runs.length === 0);
    const current = data.active_stamp || (state.summary && state.summary.active_stamp) || "";
    sel.innerHTML = runs
      .map((run) => {
        const stamp = escapeHtml(String(run.stamp || ""));
        const selected = run.active || run.stamp === current ? " selected" : "";
        return `<option value="${stamp}"${selected}>${escapeHtml(optionLabel(run))}</option>`;
      })
      .join("");
  } catch (err) {
    wrap.classList.add("hidden");
  }
}

async function boot() {
  try {
    const estate = await getJson("/api/summary");
    state.summary = estate;
    applyHonesty(estate);
    const when = estate.summary && estate.summary.generated_at ? estate.summary.generated_at : "unknown";
    const label = estate.honesty_label || "not a client estate";
    const canonical = estate.summary && estate.summary.canonical != null ? estate.summary.canonical : "—";
    if (estate.ready) {
      const mode = isReload(estate)
        ? "reload from disk only (collectors not run)"
        : "Refresh re-runs DEMO collectors";
      $("status-bar").textContent = `${label} · ${mode} · ${canonical} canonical · generated ${when}`;
    } else if (estate.lab || estate.use_existing_in) {
      $("status-bar").textContent = `${label} · Reload from disk only — collectors not run.`;
    } else {
      $("status-bar").textContent = "No estate yet. Click Refresh estate.";
    }
    $("status-bar").classList.toggle("bad", !estate.ready);
    renderKpis(estate);
    $("paths").textContent = `${estate.out_dir}  ·  ${estate.repo}`;
    await loadRuns();
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

const runPicker = $("run-picker");
if (runPicker) {
  runPicker.addEventListener("change", async () => {
    const stamp = runPicker.value;
    if (!stamp) return;
    $("status-bar").textContent = `Switching Active out/ to ${stamp}…`;
    try {
      const res = await fetch("/api/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ stamp }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      await boot();
    } catch (err) {
      $("status-bar").textContent = String(err.message || err);
      $("status-bar").classList.add("bad");
    }
  });
}

$("btn-refresh").addEventListener("click", async () => {
  const btn = $("btn-refresh");
  btn.disabled = true;
  $("status-bar").textContent = isReload(state.summary)
    ? "Reloading OUT_DIR from disk (collectors not run)…"
    : "Refreshing collectors + loader (local files only)…";
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
