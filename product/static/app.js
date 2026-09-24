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
    ["path", "Path"],
    ["size", "Size"],
  ],
  controls: [
    ["ref_id", "Ref"],
    ["name", "Name"],
    ["description", "Description"],
    ["status", "Status"],
    ["category", "Category"],
    ["priority", "Priority"],
    ["csf_function", "CSF"],
  ],
  scenarios: [
    ["current_risk", "Risk"],
    ["ref_id", "Ref"],
    ["name", "Name"],
    ["description", "Description"],
    ["assets", "Assets"],
    ["treatment", "Treatment"],
    ["additional_controls", "Controls"],
  ],
  coverage: [
    ["token", "Token"],
    ["family", "Family"],
    ["poam", "POA&M"],
    ["findings", "Findings"],
    ["controls", "Controls"],
    ["total", "Total"],
  ],
  poam: [
    ["severity", "Severity"],
    ["weakness", "Weakness"],
    ["asset", "Asset"],
    ["framework_refs", "Framework"],
    ["recommended_fix", "Recommended fix"],
    ["owner", "Owner"],
    ["due", "Due"],
    ["status", "Status"],
  ],
};

const POAM_SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

const ENDPOINTS = {
  findings: "/api/findings",
  assets: "/api/assets",
  vulns: "/api/vulnerabilities",
  proposed: "/api/proposed",
  evidence: "/api/evidences",
  poam: "/api/poam",
  controls: "/api/controls",
  scenarios: "/api/scenarios",
  coverage: "/api/coverage",
};

const FAMILY_LABELS = {
  nist_csf: "NIST CSF",
  cisa_cpg: "CISA CPG",
  cis: "CIS",
  iso: "ISO",
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
    renderPoamKpis(estate.poam || {});
    renderCoverageKpis(estate.coverage || {});
    renderSinkKpis(estate);
}

function renderPoamKpis(poam) {
  const el = $("poam-kpis");
  if (!el) return;
  const items = [
    [poam.open, "POA&M open", ""],
    [poam.critical, "Critical", "crit"],
    [poam.high, "High", "high"],
    [poam.medium, "Medium", ""],
    [poam.low, "Low", ""],
    [poam.blank_owner, "Blank owner", "blank"],
    [poam.blank_due, "Blank due", "blank"],
  ];
  el.innerHTML = items
    .map(
      ([n, label, cls]) =>
        `<div class="kpi ${cls}"><b>${fmt(n)}</b><span>${label}</span></div>`
    )
    .join("");
}

function sinkSource(raw) {
  const src = String(raw || "").trim();
  if (src === "product-lab/drop") return "product-lab/drop";
  if (src === "out") return "out";
  return src || "missing";
}

function sinkSourceKpiLabel(src) {
  if (src === "product-lab/drop") return "source=product-lab/drop";
  if (src === "out") return "source=out";
  return src ? `source=${src}` : "source=missing";
}

function sinkSourceHonesty(ogSource, proboSource) {
  const same = ogSource === proboSource;
  const srcText = same
    ? sinkSourceKpiLabel(ogSource)
    : `OpenGRC ${sinkSourceKpiLabel(ogSource)} · Probo ${sinkSourceKpiLabel(proboSource)}`;
  if (ogSource === "product-lab/drop" || proboSource === "product-lab/drop") {
    return `${srcText} · SAMPLE packaged ≠ LAB dest_in`;
  }
  if (ogSource === "out" || proboSource === "out") {
    return `${srcText} · LAB dest_in (not SAMPLE packaged)`;
  }
  return srcText;
}

function renderSinkKpis(estate) {
  const el = $("sink-kpis");
  if (!el) return;
  const og = estate.opengrc || {};
  const probo = estate.probo || {};
  const ogc = og.counts || {};
  const pc = probo.counts || {};
  const ogSource = sinkSource(og.source);
  const proboSource = sinkSource(probo.source);
  const items = [
    [ogSource, "OpenGRC source", ogSource === "product-lab/drop" ? "sample" : ""],
    [ogc.risks, "OpenGRC risks", ""],
    [ogc.assets, "OpenGRC assets", ""],
    [ogc.implementations, "OpenGRC impl", ""],
    [proboSource, "Probo source", proboSource === "product-lab/drop" ? "sample" : ""],
    [pc.addFinding, "Probo addFinding", ""],
    [pc.addRisk, "Probo addRisk", ""],
  ];
  el.innerHTML = items
    .map(
      ([n, label, cls]) =>
        `<div class="kpi ${cls}"><b>${fmt(n)}</b><span>${label}</span></div>`
    )
    .join("");
  const labelEl = $("sink-kpis-label");
  if (labelEl) {
    labelEl.textContent =
      `OpenGRC / Probo leave-behind · posted=false · file-true, not live import · ${sinkSourceHonesty(ogSource, proboSource)}`;
  }
}

function renderCoverageKpis(coverage) {
  const el = $("coverage-kpis");
  if (!el) return;
  const families = coverage.families || {};
  const nist = (families.nist_csf && families.nist_csf.rows) || 0;
  const cpg = (families.cisa_cpg && families.cisa_cpg.rows) || 0;
  const cis = (families.cis && families.cis.rows) || 0;
  const iso = (families.iso && families.iso.rows) || 0;
  const items = [
    [coverage.controls, "Controls", ""],
    [coverage.scenarios, "Scenarios", ""],
    [nist, "NIST CSF", ""],
    [cpg, "CISA CPG", ""],
    [cis, "CIS", ""],
    [iso, "ISO", ""],
  ];
  el.innerHTML = items
    .map(
      ([n, label, cls]) =>
        `<div class="kpi ${cls}"><b>${fmt(n)}</b><span>${label}</span></div>`
    )
    .join("");
}

function heatClass(n, max) {
  const val = Number(n) || 0;
  if (!val) return "heat-0";
  const ratio = val / Math.max(1, Number(max) || 1);
  if (ratio > 0.75) return "heat-4";
  if (ratio > 0.5) return "heat-3";
  if (ratio > 0.25) return "heat-2";
  return "heat-1";
}

function renderCoverageHeat(tokens) {
  const el = $("coverage-heat");
  if (!el) return;
  if (state.tab !== "coverage") {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  const rows = Array.isArray(tokens) ? tokens : [];
  if (!rows.length) {
    el.innerHTML = "<p>No framework_refs tokens on this out/.</p>";
    return;
  }
  const max = Math.max(1, ...rows.map((row) => Number(row.total) || 0));
  el.innerHTML = rows
    .map((row) => {
      const token = escapeHtml(String(row.token || ""));
      const family = escapeHtml(FAMILY_LABELS[row.family] || String(row.family || ""));
      const total = Number(row.total) || 0;
      return `<div class="heat-cell ${heatClass(total, max)}"><b>${token}</b><span>${family} · ${total}</span></div>`;
    })
    .join("");
}

function sortPoamRows(rows) {
  return rows.slice().sort((a, b) => {
    const sa = POAM_SEV_RANK[String(a.severity || "").toLowerCase()];
    const sb = POAM_SEV_RANK[String(b.severity || "").toLowerCase()];
    const ra = sa == null ? 9 : sa;
    const rb = sb == null ? 9 : sb;
    if (ra !== rb) return ra - rb;
    return String(a.weakness || "").localeCompare(String(b.weakness || ""));
  });
}

function isBlankPoamField(row, key) {
  if (key === "owner" && row.blank_owner === true) return true;
  if (key === "due" && row.blank_due === true) return true;
  return !String(row[key] ?? "").trim();
}

function poamRowClass(row) {
  const classes = [];
  if (isBlankPoamField(row, "owner")) classes.push("blank-owner");
  if (isBlankPoamField(row, "due")) classes.push("blank-due");
  if (classes.length) classes.push("needs-human");
  return classes.join(" ");
}

function matches(row, q, sev) {
  if (sev) {
    const val = String(row.severity || row.Severity || row.current_risk || "").toLowerCase();
    if (val !== sev) return false;
  }
  if (!q) return true;
  return Object.values(row).some((v) => String(v ?? "").toLowerCase().includes(q));
}

function cell(key, row) {
  const raw = row[key];
  const text = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
  if (key === "severity" || key === "current_risk") {
    const cls = text.toLowerCase().replace(/\s+/g, "-");
    return `<td><span class="sev ${cls}">${escapeHtml(text)}</span></td>`;
  }
  if ((key === "owner" || key === "due") && isBlankPoamField(row, key)) {
    return `<td class="missing-cell"><span class="missing">blank — human</span></td>`;
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
  const source = state.tab === "poam" ? sortPoamRows(state.rows) : state.rows;
  const rows = source.filter((r) => matches(r, q, sev));
  $("proposed-note").classList.toggle("hidden", state.tab !== "proposed");
  const poamNote = $("poam-note");
  if (poamNote) poamNote.classList.toggle("hidden", state.tab !== "poam");
  const coverageNote = $("coverage-note");
  if (coverageNote) {
    coverageNote.classList.toggle(
      "hidden",
      state.tab !== "coverage" && state.tab !== "controls" && state.tab !== "scenarios"
    );
  }
  renderCoverageHeat(state.tab === "coverage" ? state.rows : []);
  if (!rows.length) {
    $("table-wrap").innerHTML = "<p>No rows match.</p>";
    return;
  }
  const head = cols.map(([, label]) => `<th>${label}</th>`).join("");
  const body = rows
    .map((row) => {
      const cls = state.tab === "poam" ? poamRowClass(row) : "";
      const attr = cls ? ` class="${cls}"` : "";
      return `<tr${attr}>${cols.map(([key]) => cell(key, row)).join("")}</tr>`;
    })
    .join("");
  $("table-wrap").innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

async function loadTab() {
  const payload = await getJson(ENDPOINTS[state.tab]);
  if (state.tab === "coverage") {
    state.coverage = payload;
    state.rows = Array.isArray(payload.tokens) ? payload.tokens : [];
    renderTable();
    return;
  }
  const rows = Array.isArray(payload) ? payload : [];
  state.rows = state.tab === "poam" ? sortPoamRows(rows) : rows;
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
      const ogc = (estate.opengrc && estate.opengrc.counts) || {};
      const pbc = (estate.probo && estate.probo.counts) || {};
      const ogSource = sinkSource((estate.opengrc && estate.opengrc.source) || "");
      const pbSource = sinkSource((estate.probo && estate.probo.source) || "");
      $("status-bar").textContent = `${label} · ${mode} · ${canonical} canonical · OpenGRC risks ${fmt(ogc.risks)} · ${sinkSourceKpiLabel(ogSource)} · Probo addFinding ${fmt(pbc.addFinding)} · ${sinkSourceKpiLabel(pbSource)} · posted=false · generated ${when}`;
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
