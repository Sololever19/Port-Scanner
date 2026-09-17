(() => {
  const hostInput = document.getElementById("host");
  const portMode = document.getElementById("portMode");
  const customPortsField = document.getElementById("customPortsField");
  const portSpecInput = document.getElementById("portSpec");
  const modeToggle = document.getElementById("modeToggle");
  const scanBtn = document.getElementById("scanBtn");
  const errorMsg = document.getElementById("errorMsg");

  const stageIdle = document.getElementById("stageIdle");
  const stageScanning = document.getElementById("stageScanning");
  const stageResults = document.getElementById("stageResults");
  const scanningLabel = document.getElementById("scanningLabel");

  const resHost = document.getElementById("resHost");
  const resIp = document.getElementById("resIp");
  const resDuration = document.getElementById("resDuration");
  const resOpenCount = document.getElementById("resOpenCount");
  const resMode = document.getElementById("resMode");
  const portGrid = document.getElementById("portGrid");
  const resultsBody = document.getElementById("resultsBody");

  let currentMode = "simulate";

  portMode.addEventListener("change", () => {
    customPortsField.hidden = portMode.value !== "custom";
  });

  modeToggle.addEventListener("click", (e) => {
    const btn = e.target.closest(".toggle-opt");
    if (!btn) return;
    currentMode = btn.dataset.mode;
    [...modeToggle.querySelectorAll(".toggle-opt")].forEach((b) => {
      const active = b === btn;
      b.classList.toggle("active", active);
      b.setAttribute("aria-checked", String(active));
    });
    scanBtn.classList.toggle("mode-real", currentMode === "real");
    scanBtn.querySelector(".scan-btn-label").textContent =
      currentMode === "real" ? "RUN REAL SCAN" : "RUN SCAN";
  });

  function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.hidden = false;
  }

  function clearError() {
    errorMsg.hidden = true;
    errorMsg.textContent = "";
  }

  function setStage(stage) {
    stageIdle.hidden = stage !== "idle";
    stageScanning.hidden = stage !== "scanning";
    stageResults.hidden = stage !== "results";
    stageResults.classList.toggle("show", stage === "results");
  }

  async function runScan() {
    clearError();

    const host = hostInput.value.trim();
    if (!host) {
      showError("Enter a target host or IP first.");
      hostInput.focus();
      return;
    }

    const ports = portMode.value === "custom" ? portSpecInput.value.trim() : "common";
    if (portMode.value === "custom" && !ports) {
      showError("Enter a port spec, e.g. 1-1024 or 22,80,443.");
      portSpecInput.focus();
      return;
    }

    scanBtn.disabled = true;
    scanningLabel.firstChild.textContent =
      currentMode === "real" ? "Scanning (real)" : "Simulating scan";
    setStage("scanning");

    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host,
          mode: currentMode,
          ports,
          timeout: 0.6,
          workers: 150,
        }),
      });

      const data = await resp.json();

      if (!resp.ok) {
        setStage("idle");
        showError(data.error || "Scan failed.");
        return;
      }

      renderResults(data);
      setStage("results");
    } catch (err) {
      setStage("idle");
      showError("Could not reach the scan server. Is app.py still running?");
    } finally {
      scanBtn.disabled = false;
    }
  }

  function renderResults(data) {
    resHost.textContent = data.host;
    resIp.textContent = data.resolved_ip;
    resDuration.textContent = `${data.duration}s`;
    resMode.textContent = data.mode === "real" ? "REAL" : "SIMULATED";

    const openPorts = data.results.filter((r) => r.state === "open");
    resOpenCount.textContent = openPorts.length;

    // Port grid — every scanned port as a small cell
    portGrid.innerHTML = "";
    data.results.forEach((r, i) => {
      const cell = document.createElement("div");
      cell.className = "port-cell";
      cell.dataset.state = r.state;
      cell.textContent = r.port;
      cell.title = `${r.port} — ${r.state}${r.service ? " (" + r.service + ")" : ""}`;
      cell.style.animationDelay = `${Math.min(i * 4, 600)}ms`;
      portGrid.appendChild(cell);
    });

    // Table — only open + filtered ports, most relevant first
    resultsBody.innerHTML = "";
    const notable = data.results
      .filter((r) => r.state !== "closed")
      .sort((a, b) => a.port - b.port);

    if (notable.length === 0) {
      const tr = document.createElement("tr");
      tr.className = "no-open-row";
      tr.innerHTML = `<td colspan="5">No open or filtered ports found.</td>`;
      resultsBody.appendChild(tr);
      return;
    }

    for (const r of notable) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${r.port}</td>
        <td><span class="state-pill ${r.state}">${r.state.toUpperCase()}</span></td>
        <td>${r.service || "—"}</td>
        <td>${r.latency_ms}ms</td>
        <td class="banner-cell">${escapeHtml(r.banner) || "—"}</td>
      `;
      resultsBody.appendChild(tr);
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  scanBtn.addEventListener("click", runScan);
  hostInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") runScan();
  });
})();
