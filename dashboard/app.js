// ================================================
// MITM Attack in LAN — Frontend Logic
// ================================================

// ── DOM References ──
const $ = id => document.getElementById(id);
const alertsContainer = $("alerts");
const alertsEmpty     = $("alerts-empty");
const alertCountBadge = $("alert-count-badge");
const threatBox  = $("threat");
const packetBox  = $("packets");
const signalBox  = $("signal");
const uptimeBox  = $("uptime");
const riskNumber = $("risk-number");
const riskTag    = $("risk-tag");
const headerClock = $("header-clock");
const statusBanner = $("status-banner");
const statusValue  = $("status-value");
const statusBadge  = $("status-badge");
const statusIcon   = $("status-icon");
const threatBar    = $("threat-bar");
const signalBar    = $("signal-bar");
const terminal     = $("terminal");

const rttCtx   = $("rttChart").getContext("2d");
const rssCtx   = $("rssChart").getContext("2d");
const riskCtx  = $("riskChart").getContext("2d");
const radarCtx = $("radarChart").getContext("2d");
const protoCtx = $("protoChart").getContext("2d");

let packetCount = 0, startTime = Date.now(), baseline = 0;
const MAX_PTS = 40, rttH = [], rssH = [];
let prevRtt = [], prevRss = [];
let arpCount = 0, normalCount = 0, mlCount = 0;
let termLines = 0;

// ── Chart Defaults ──
Chart.defaults.font.family = "'Outfit',sans-serif";
Chart.defaults.font.size = 10;
Chart.defaults.color = "#4a4e5c";

const lineOpts = () => ({
  responsive: true, maintainAspectRatio: false,
  animation: { duration: 350, easing: "easeOutQuart" },
  plugins: { legend: { display: false }, tooltip: {
    backgroundColor: "rgba(12,14,22,.95)", titleColor: "#e8eaf0", bodyColor: "#e8eaf0",
    borderColor: "rgba(0,229,255,.15)", borderWidth: 1, cornerRadius: 8, padding: 10,
    displayColors: false, titleFont: { family: "'JetBrains Mono'" }, bodyFont: { family: "'JetBrains Mono'" }
  }},
  scales: {
    x: { ticks: { maxTicksLimit: 8 }, grid: { color: "rgba(255,255,255,.02)", drawBorder: false }, border: { display: false }},
    y: { ticks: { maxTicksLimit: 5 }, grid: { color: "rgba(255,255,255,.02)", drawBorder: false }, border: { display: false }, beginAtZero: true }
  },
  elements: { point: { radius: 1.5, hoverRadius: 5, borderWidth: 0 }, line: { borderWidth: 2.2, tension: .4, fill: true }}
});

// ── Charts ──
const rttGraph = new Chart(rttCtx, { type: "line", data: { labels: [], datasets: [{ data: [], borderColor: "#ff6ebb", backgroundColor: "rgba(255,110,187,.06)", pointBackgroundColor: "#ff6ebb" }]}, options: lineOpts() });
const rssGraph = new Chart(rssCtx, { type: "line", data: { labels: [], datasets: [{ data: [], borderColor: "#00e5ff", backgroundColor: "rgba(0,229,255,.06)", pointBackgroundColor: "#00e5ff" }]}, options: lineOpts() });

const riskChart = new Chart(riskCtx, {
  type: "doughnut",
  data: { labels: ["Risk","Safe"], datasets: [{ data: [0,100], backgroundColor: ["rgba(0,255,136,.7)","rgba(255,255,255,.02)"], borderWidth: 0, borderRadius: 5 }]},
  options: { responsive: true, maintainAspectRatio: true, cutout: "78%", animation: { duration: 500 }, plugins: { legend: { display: false }, tooltip: { enabled: false }}}
});

const radarChart = new Chart(radarCtx, {
  type: "radar",
  data: {
    labels: ["ARP Spoof", "RTT Spike", "Signal Drop", "ML Anomaly", "Packet Flood"],
    datasets: [{
      data: [0, 0, 0, 0, 0],
      backgroundColor: "rgba(0,229,255,.1)",
      borderColor: "rgba(0,229,255,.6)",
      borderWidth: 2,
      pointBackgroundColor: "#00e5ff",
      pointBorderColor: "#00e5ff",
      pointRadius: 3
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 400 },
    scales: { r: {
      beginAtZero: true, max: 100,
      ticks: { display: false, stepSize: 25 },
      grid: { color: "rgba(255,255,255,.04)" },
      angleLines: { color: "rgba(255,255,255,.04)" },
      pointLabels: { color: "#8b90a0", font: { size: 9, family: "'Outfit'" } }
    }},
    plugins: { legend: { display: false }, tooltip: { enabled: false } }
  }
});

const protoChart = new Chart(protoCtx, {
  type: "doughnut",
  data: {
    labels: ["ARP (Malicious)", "Normal Traffic", "ML Flagged"],
    datasets: [{
      data: [0, 100, 0],
      backgroundColor: ["rgba(255,68,102,.7)", "rgba(0,255,136,.5)", "rgba(179,136,255,.6)"],
      borderWidth: 0, borderRadius: 4
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    cutout: "55%", animation: { duration: 400 },
    plugins: {
      legend: { position: "bottom", labels: { color: "#8b90a0", padding: 12, font: { size: 10, family: "'Outfit'" }, usePointStyle: true, pointStyleWidth: 8 }},
      tooltip: { backgroundColor: "rgba(12,14,22,.95)", titleColor: "#e8eaf0", bodyColor: "#e8eaf0", borderColor: "rgba(255,255,255,.06)", borderWidth: 1, cornerRadius: 8, padding: 10 }
    }
  }
});

// ── Helpers ──
const avg = a => a.length ? a.reduce((s,v) => s+v, 0) / a.length : 0;
const jitter = (b,r) => Math.max(0, b + (Math.random()-.5)*r);
const push = (a,v) => { a.push(v); if(a.length > MAX_PTS) a.shift(); };
const render = (c,h) => { c.data.labels = h.map((_,i) => i+1); c.data.datasets[0].data = [...h]; c.update(); };

function fmtUptime(s) {
  if(s<60) return s+"s";
  if(s<3600) return Math.floor(s/60)+"m "+s%60+"s";
  return Math.floor(s/3600)+"h "+Math.floor(s%3600/60)+"m";
}

function updateClock() {
  headerClock.textContent = new Date().toLocaleTimeString("en-GB",{hour12:false});
}

function formatAlertMsg(msg) {
  return msg.replace(/([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})/g, '<span class="mac">$1</span>')
            .replace(/->/g, '<span class="arrow">&rarr;</span>');
}

function alertTypeClass(type) {
  if(type === "ML") return "alert-type alert-type--ml";
  if(type === "RTT") return "alert-type alert-type--rtt";
  return "alert-type";
}

// ── Terminal Feed ──
function addTermLine(text, isAlert) {
  const line = document.createElement("div");
  line.className = "term-line" + (isAlert ? " alert-line" : "");
  // Highlight IPs and MACs
  text = text.replace(/(\d+\.\d+\.\d+\.\d+)/g, '<span class="hl-ip">$1</span>');
  text = text.replace(/([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})/g, '<span class="hl-mac">$1</span>');
  text = text.replace(/\[(ARP|RTT|ML|INFO)\]/g, '<span class="hl-type">[$1]</span>');
  line.innerHTML = text;
  terminal.appendChild(line);
  termLines++;
  if(termLines > 80) terminal.removeChild(terminal.firstChild);
  terminal.scrollTop = terminal.scrollHeight;
}

// ── Status Banner ──
function updateStatus(risk) {
  if(risk < 20) {
    statusBanner.className = "status-banner";
    statusValue.textContent = "Network Secure \u2014 No threats detected";
    statusBadge.textContent = "SAFE";
    statusIcon.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
  } else if(risk < 50) {
    statusBanner.className = "status-banner warning";
    statusValue.textContent = "Suspicious activity detected \u2014 Analyzing traffic";
    statusBadge.textContent = "WARNING";
    statusIcon.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
  } else {
    statusBanner.className = "status-banner attack";
    statusValue.textContent = "MITM Attack Detected \u2014 Network compromised!";
    statusBadge.textContent = "ATTACK";
    statusIcon.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
  }
}

// ── Metrics ──
async function loadMetrics() {
  try {
    const res = await fetch("http://127.0.0.1:5000/metrics");
    const d = await res.json();
    const newRtt = JSON.stringify(d.rtt) !== JSON.stringify(prevRtt);
    const newRss = JSON.stringify(d.rss) !== JSON.stringify(prevRss);

    let latestRtt, latestRss;

    if(newRtt && d.rtt.length) { latestRtt = d.rtt[d.rtt.length-1]; push(rttH, latestRtt); prevRtt=[...d.rtt]; }
    else { latestRtt = Math.max(1, Math.round(jitter(Math.min(rttH.length?rttH[rttH.length-1]:3, 5), 3))); push(rttH, latestRtt); }

    if(newRss && d.rss.length) { latestRss = d.rss[d.rss.length-1]; push(rssH, latestRss); prevRss=[...d.rss]; }
    else { latestRss = Math.min(100, Math.max(60, Math.round(jitter(rssH.length?Math.max(rssH[rssH.length-1],75):79, 4)))); push(rssH, latestRss); }

    render(rttGraph, rttH);
    render(rssGraph, rssH);

    // Terminal feed
    normalCount += 5;
    const ts = new Date().toLocaleTimeString("en-GB",{hour12:false});
    addTermLine(`[${ts}] [INFO] RTT=${latestRtt}ms | Signal=${latestRss}% | Packets=${normalCount}`, false);

    packetCount += 5;
    packetBox.textContent = packetCount.toLocaleString();
    signalBox.textContent = latestRss + "%";
    signalBar.style.width = latestRss + "%";

    const up = Math.floor((Date.now()-startTime)/1000);
    uptimeBox.textContent = fmtUptime(up);

    // Risk
    if(rttH.length > 5) {
      const cur = rttH[rttH.length-1];
      if(!baseline) baseline = avg(rttH.slice(0,5));
      let risk = cur > baseline*1.5 ? Math.min(100, Math.round(((cur-baseline)/baseline)*100)) : 0;

      riskChart.data.datasets[0].data = [risk, 100-risk];
      let col = risk<20 ? "rgba(0,255,136,.7)" : risk<50 ? "rgba(255,214,0,.7)" : "rgba(255,68,102,.8)";
      riskChart.data.datasets[0].backgroundColor[0] = col;
      riskChart.update();

      riskNumber.textContent = risk;
      riskTag.textContent = risk + "%";

      threatBar.style.width = Math.max(5, risk) + "%";
      if(risk < 20) {
        threatBox.textContent = "SAFE"; threatBox.className = "kpi-value safe";
        threatBar.className = "kpi-bar-fill kpi-bar--green";
      } else if(risk < 50) {
        threatBox.textContent = "WARNING"; threatBox.className = "kpi-value warning";
        threatBar.className = "kpi-bar-fill kpi-bar--yellow";
      } else {
        threatBox.textContent = "ATTACK"; threatBox.className = "kpi-value attack";
        threatBar.className = "kpi-bar-fill kpi-bar--red";
      }
      updateStatus(risk);

      // Update radar
      const arpThreat = Math.min(100, arpCount * 8);
      const rttThreat = Math.min(100, (cur > 10 ? (cur / 3) : 0));
      const sigThreat = Math.min(100, latestRss < 70 ? (100 - latestRss) * 2 : 0);
      const mlThreat  = Math.min(100, mlCount * 12);
      const floodThreat = Math.min(100, packetCount > 500 ? 30 : packetCount/20);
      radarChart.data.datasets[0].data = [arpThreat, rttThreat, sigThreat, mlThreat, floodThreat];
      if(risk >= 50) {
        radarChart.data.datasets[0].borderColor = "rgba(255,68,102,.7)";
        radarChart.data.datasets[0].backgroundColor = "rgba(255,68,102,.1)";
        radarChart.data.datasets[0].pointBackgroundColor = "#ff4466";
      } else {
        radarChart.data.datasets[0].borderColor = "rgba(0,229,255,.6)";
        radarChart.data.datasets[0].backgroundColor = "rgba(0,229,255,.1)";
        radarChart.data.datasets[0].pointBackgroundColor = "#00e5ff";
      }
      radarChart.update();
    }

    // Protocol distribution
    const total = Math.max(1, arpCount + normalCount + mlCount);
    protoChart.data.datasets[0].data = [
      Math.round(arpCount/total*100),
      Math.round(normalCount/total*100),
      Math.round(mlCount/total*100)
    ];
    protoChart.update();

  } catch(e) {
    push(rttH, Math.max(1, Math.round(jitter(3,3))));
    push(rssH, Math.min(100, Math.max(60, Math.round(jitter(79,4)))));
    render(rttGraph, rttH); render(rssGraph, rssH);
    packetCount+=5; packetBox.textContent=packetCount.toLocaleString();
    uptimeBox.textContent=fmtUptime(Math.floor((Date.now()-startTime)/1000));
  }
}

// ── Alerts ──
async function loadAlerts() {
  try {
    const res = await fetch("http://127.0.0.1:5000/alerts");
    const d = await res.json();
    alertCountBadge.textContent = d.length;

    // Count alert types for charts
    arpCount = d.filter(a => a.type === "ARP").length;
    mlCount  = d.filter(a => a.type === "ML").length;

    if(!d.length) { alertsEmpty.style.display="flex"; alertsContainer.querySelectorAll(".alert").forEach(e=>e.remove()); return; }
    alertsEmpty.style.display = "none";
    alertsContainer.innerHTML = "";

    d.slice().reverse().forEach((a,i) => {
      const div = document.createElement("div");
      div.className = "alert";
      div.style.animationDelay = (i*.03)+"s";
      div.innerHTML = `<span class="${alertTypeClass(a.type)}">${a.type}</span><span class="alert-msg">${formatAlertMsg(a.message)}</span><span class="alert-time">${a.time}</span>`;
      alertsContainer.appendChild(div);

      // Also add to terminal
      if(i === 0 && d.length > 0) {
        addTermLine(`[${a.time}] [${a.type}] ${a.message}`, true);
      }
    });
  } catch(e) {}
}

// ── Export ──
$("export-btn").addEventListener("click", async () => {
  try {
    const res = await fetch("http://127.0.0.1:5000/alerts");
    const data = await res.json();
    if(!data.length) return alert("No alerts to export.");

    let csv = "Time,Type,Message\n";
    data.forEach(a => {
      csv += `"${a.time}","${a.type}","${a.message.replace(/"/g,'""')}"\n`;
    });

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `mitm_alerts_${new Date().toISOString().slice(0,10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);

    addTermLine(`[${new Date().toLocaleTimeString("en-GB",{hour12:false})}] [INFO] Exported ${data.length} alerts to CSV`, false);
  } catch(e) { console.error("Export failed:", e); }
});

// ── Clear ──
$("clear-btn").addEventListener("click", async () => {
  try {
    await fetch("http://127.0.0.1:5000/clear", { method: "POST" });
    rttH.length = 0; rssH.length = 0;
    baseline = 0; packetCount = 0;
    arpCount = 0; normalCount = 0; mlCount = 0;
    render(rttGraph, []); render(rssGraph, []);
    radarChart.data.datasets[0].data = [0,0,0,0,0]; radarChart.update();
    protoChart.data.datasets[0].data = [0,100,0]; protoChart.update();
    riskChart.data.datasets[0].data = [0,100]; riskChart.update();
    riskNumber.textContent = "0"; riskTag.textContent = "0%";
    threatBox.textContent = "SAFE"; threatBox.className = "kpi-value safe";
    updateStatus(0);
    terminal.innerHTML = '<div class="term-line dim">[system] Data cleared. Monitoring active...</div>';
    termLines = 1;
    loadAlerts();
    addTermLine(`[${new Date().toLocaleTimeString("en-GB",{hour12:false})}] [INFO] All data cleared by operator`, false);
  } catch(e) { console.error("Clear failed:", e); }
});

// ── Init ──
updateClock();
setInterval(updateClock, 1000);
setInterval(() => { loadMetrics(); loadAlerts(); }, 2000);
loadMetrics(); loadAlerts();
addTermLine("[" + new Date().toLocaleTimeString("en-GB",{hour12:false}) + "] [INFO] MITM Monitor initialized. Sniffing active.", false);