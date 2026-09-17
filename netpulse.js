(() => {
  // ---------------- elements ----------------
  const targetInput = document.getElementById("targetInput");
  const runScanBtn = document.getElementById("runScanBtn");
  const captureBtn = document.getElementById("captureBtn");
  const statusDot = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");
  const errorMsg = document.getElementById("errorMsg");

  const openPortsBody = document.getElementById("openPortsBody");
  const openPortsCount = document.getElementById("openPortsCount");

  const radar = document.getElementById("radar");
  const radarPct = document.getElementById("radarPct");
  const radarDots = document.getElementById("radarDots");
  const exposureLevel = document.getElementById("exposureLevel");
  const exposureFill = document.getElementById("exposureFill");

  const streamBody = document.getElementById("streamBody");
  const packetCount = document.getElementById("packetCount");
  const streamFilters = document.getElementById("streamFilters");

  const statPortsProbed = document.getElementById("statPortsProbed");
  const statOpenServices = document.getElementById("statOpenServices");
  const statPacketsCaptured = document.getElementById("statPacketsCaptured");
  const statFlagged = document.getElementById("statFlagged");

  // Ports considered risky if exposed — used for the "flagged" concept
  const RISKY_PORTS = new Set([21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]);

  // ---------------- radar dots (static ring decoration) ----------------
  const DOT_COUNT = 16;
  for (let i = 0; i < DOT_COUNT; i++) {
    const angle = (i / DOT_COUNT) * Math.PI * 2;
    const radius = 108;
    const dot = document.createElement("div");
    dot.className = "radar-dot";
    dot.style.transform = `translate(${Math.cos(angle) * radius}px, ${Math.sin(angle) * radius}px)`;
    radarDots.appendChild(dot);
  }

  // ---------------- scan ----------------
  let scanning = false;
  let progressTimer = null;

  function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.hidden = false;
  }
  function clearError() {
    errorMsg.hidden = true;
  }

  function setRadarPct(pct) {
    radarPct.textContent = `${Math.round(pct)}%`;
  }

  function startRadarAnimation() {
    radar.classList.add("scanning");
    let pct = 0;
    setRadarPct(0);
    progressTimer = setInterval(() => {
      // ease toward 90%, final jump to 100 happens when results land
      pct += (90 - pct) * 0.12 + 0.4;
      if (pct > 90) pct = 90;
      setRadarPct(pct);
    }, 120);
  }

  function finishRadarAnimation() {
    clearInterval(progressTimer);
    radar.classList.remove("scanning");
    setRadarPct(100);
  }

  async function runScan() {
    if (scanning) return;
    clearError();

    const host = targetInput.value.trim();
    if (!host) {
      showError("Enter a target IP or hostname first.");
      targetInput.focus();
      return;
    }

    scanning = true;
    runScanBtn.disabled = true;
    runScanBtn.textContent = "Scanning…";
    startRadarAnimation();

    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host,
          mode: "real",
          ports: "common",
          timeout: 0.6,
          workers: 150,
        }),
      });
      const data = await resp.json();

      if (!resp.ok) {
        showError(data.error || "Scan failed.");
        finishRadarAnimation();
        return;
      }

      renderScanResults(data);
      finishRadarAnimation();
    } catch (err) {
      showError("Could not reach the scan backend. Is app.py still running?");
      finishRadarAnimation();
    } finally {
      scanning = false;
      runScanBtn.disabled = false;
      runScanBtn.textContent = "Run Scan";
    }
  }

  function renderScanResults(data) {
    const openPorts = data.results.filter((r) => r.state === "open");
    const flagged = openPorts.filter((r) => RISKY_PORTS.has(r.port));

    openPortsCount.textContent = openPorts.length;
    statOpenServices.textContent = openPorts.length;
    statPortsProbed.textContent = `${data.results.length}/${data.results.length}`;
    statFlagged.textContent = flagged.length;

    openPortsBody.innerHTML = "";
    if (openPorts.length === 0) {
      openPortsBody.innerHTML = `<p class="empty-note">No open ports found.</p>`;
    } else {
      for (const p of openPorts) {
        const row = document.createElement("div");
        const isFlagged = RISKY_PORTS.has(p.port);
        row.className = "port-row" + (isFlagged ? " flagged" : "");
        row.innerHTML = `
          <span class="port-num">${p.port}</span>
          <span class="port-service">${p.service || "unknown"}</span>
          ${isFlagged ? '<span class="risk-tag">EXPOSED</span>' : ""}
        `;
        openPortsBody.appendChild(row);
      }
    }

    // exposure risk: based on open + flagged counts
    let level = "low";
    let fillPct = Math.min(10 + openPorts.length * 6, 100);
    if (flagged.length >= 2 || openPorts.length >= 6) level = "high";
    else if (flagged.length === 1 || openPorts.length >= 3) level = "medium";

    exposureLevel.textContent = level[0].toUpperCase() + level.slice(1);
    exposureLevel.className = `exposure-level level-${level}`;
    exposureFill.style.width = `${fillPct}%`;
    exposureFill.style.background =
      level === "high" ? "var(--red)" : level === "medium" ? "var(--orange)" : "var(--green)";
  }

  runScanBtn.addEventListener("click", runScan);
  targetInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") runScan();
  });

  // ---------------- simulated packet stream ----------------
  let capturing = false;
  let captureTimer = null;
  let totalPackets = 0;
  let activeFilter = "ALL";

  const PROTOS = ["TCP", "UDP", "DNS", "TLS", "HTTP", "ICMP"];
  const INFO_BY_PROTO = {
    TCP: ["SYN", "ACK", "PSH,ACK", "FIN,ACK", "keepalive"],
    UDP: ["datagram", "keepalive"],
    DNS: ["query A", "query AAAA", "response"],
    TLS: ["Client Hello", "Server Hello", "Application Data"],
    HTTP: ["GET /", "200 OK", "POST /api"],
    ICMP: ["echo request", "echo reply"],
  };

  function randInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  function fakeIp(local) {
    return local
      ? `10.0.${randInt(0, 9)}.${randInt(1, 254)}`
      : `192.168.${randInt(0, 255)}.${randInt(1, 254)}`;
  }
  function nowTime() {
    const d = new Date();
    return d.toTimeString().slice(0, 8);
  }

  function spawnPacket() {
    const proto = PROTOS[randInt(0, PROTOS.length - 1)];
    const info = INFO_BY_PROTO[proto][randInt(0, INFO_BY_PROTO[proto].length - 1)];
    const packet = {
      time: nowTime(),
      src: fakeIp(true),
      dst: fakeIp(false),
      proto,
      len: randInt(60, 1500),
      info,
    };
    totalPackets++;
    packetCount.textContent = totalPackets;
    statPacketsCaptured.textContent = totalPackets;

    if (activeFilter === "ALL" || activeFilter === proto) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${packet.time}</td>
        <td>${packet.src}</td>
        <td>${packet.dst}</td>
        <td class="proto-${proto}">${proto}</td>
        <td>${packet.len}</td>
        <td>${packet.info}</td>
      `;
      streamBody.insertBefore(tr, streamBody.firstChild);
      while (streamBody.children.length > 60) {
        streamBody.removeChild(streamBody.lastChild);
      }
    }
  }

  function startCapture() {
    capturing = true;
    captureBtn.textContent = "Stop Capture";
    captureBtn.classList.add("capturing");
    statusDot.classList.add("live");
    statusText.textContent = "Capturing (simulated)";
    captureTimer = setInterval(spawnPacket, 350);
  }

  function stopCapture() {
    capturing = false;
    captureBtn.textContent = "Start Capture";
    captureBtn.classList.remove("capturing");
    statusDot.classList.remove("live");
    statusText.textContent = "Capture stopped";
    clearInterval(captureTimer);
  }

  captureBtn.addEventListener("click", () => {
    capturing ? stopCapture() : startCapture();
  });

  streamFilters.addEventListener("click", (e) => {
    const chip = e.target.closest(".filter-chip");
    if (!chip) return;
    activeFilter = chip.dataset.proto;
    [...streamFilters.querySelectorAll(".filter-chip")].forEach((c) =>
      c.classList.toggle("active", c === chip)
    );
  });
})();
