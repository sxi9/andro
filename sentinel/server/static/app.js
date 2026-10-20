/* Android Sentinel dashboard — live wiring to /ws + REST. Vanilla JS, no deps. */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  /* ---------- selected device ---------- */
  var DEV = null;  // adb serial of the device currently shown; null = server default
  try { DEV = localStorage.getItem("sentinel-device") || null; } catch (e) {}
  function dq(url) {
    if (!DEV) return url;
    return url + (url.indexOf("?") >= 0 ? "&" : "?") + "device=" + encodeURIComponent(DEV);
  }
  function setDevice(serial) {
    DEV = serial || null;
    try { if (DEV) localStorage.setItem("sentinel-device", DEV); else localStorage.removeItem("sentinel-device"); } catch (e) {}
    // device-scoped views must be reloaded and feeds cleared
    ["#feed-mon", "#feed-net", "#feed-priv"].forEach(function (s) {
      var el = $(s); if (el) el.innerHTML = '<div class="empty">switching device…</div>';
    });
    sysLogs = []; radioLogs = []; destStats = {}; alertedIPs = {};
    seenIds = {};
    pollStatus();
    refreshCurrentTab();
    fetch(dq("/api/events?limit=60")).then(function (r) { return r.json(); })
      .then(function (evs) { (evs || []).reverse().forEach(routeEvent); }).catch(function () {});
  }
  function refreshCurrentTab() {
    if (currentTab === "apps") loadApps();
    else if (currentTab === "alerts") { loadAlerts(); loadRules(); }
    else if (currentTab === "storage") loadStorage();
    else if (currentTab === "perf") loadPerf();
    else if (currentTab === "devices") { loadDevices(); loadRootCard(); }
    else if (currentTab === "logs") renderLogs();
    else if (currentTab === "radio") renderRadioLog();
    else if (currentTab === "network") { renderFlow(); renderDestTable(); }
    else if (currentTab === "appmgr") loadAppManager();
    else if (currentTab === "intercept") loadIntercept();
    else if (currentTab === "requests") loadRequests();
  }

  /* ---------- theme ---------- */
  try {
    var savedTheme = localStorage.getItem("sentinel-theme");
    if (savedTheme) document.documentElement.setAttribute("data-theme", savedTheme);
  } catch (e) { /* storage may be unavailable */ }
  $("#theme").addEventListener("click", function () {
    var cur = document.documentElement.getAttribute("data-theme") || "dark";
    var next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("sentinel-theme", next); } catch (e) {}
  });

  /* ---------- tabs ---------- */
  var titles = {
    monitor: ["Live Activity", "Unified timeline of everything the device is doing"],
    network: ["Network & Data", "Every connection, where it lands, how much leaves the device"],
    privacy: ["Mic · Cam · Location", "Sensor access with foreground / background attribution"],
    apps: ["Apps & Permissions", "Inventory, god-mode access and dangerous grants"],
    appmgr: ["App Manager", "Every app, with full details and owner controls"],
    logs: ["Logcat", "System log attributed to the owning app"],
    radio: ["Cellular & Radio", "Telephony state, serving cell and the radio log"],
    storage: ["Files & Storage", "Per-app storage, the file browser, and app extraction"],
    perf: ["Performance", "Memory, swap and CPU — what's eating RAM, free it, and tune the kernel"],
    alerts: ["Alerts & Rules", "What tripped, and the detections watching your device"],
    intercept: ["SSL Intercept", "Trust a proxy CA and point the device at it — authorized own-device testing"],
    requests: ["Requests", "Per-app HTTP requests through the proxy, filtered, with watches"],
    devices: ["Devices & ADB", "Every device ADB sees, their state, and connection controls"],
  };
  var currentTab = "monitor";
  function go(tab) {
    currentTab = tab;
    if (tab !== "perf" && typeof perfStopTimers === "function") perfStopTimers();
    $$(".panel").forEach(function (p) { p.classList.toggle("on", p.dataset.panel === tab); });
    $$("[data-nav] button").forEach(function (b) { b.classList.toggle("on", b.dataset.tab === tab); });
    $("#ttl").textContent = titles[tab][0];
    $("#sub").textContent = titles[tab][1];
    $(".scroll").scrollTop = 0;
    if (tab === "apps") loadApps();
    if (tab === "alerts") { loadAlerts(); loadRules(); }
    if (tab === "logs") renderLogs();
    if (tab === "radio") renderRadioLog();
    if (tab === "storage") loadStorage();
    if (tab === "perf") loadPerf();
    if (tab === "devices") { loadDevices(); loadRootCard(); }
    if (tab === "appmgr") loadAppManager();
    if (tab === "intercept") loadIntercept();
    if (tab === "requests") loadRequests();
    if (tab === "console") loadConsole();
    if (tab === "network") { renderFlow(); renderDestTable(); }
    var gs = $("#gsearch");
    if (gs) {
      gs.placeholder = "Search " + (titles[tab] ? titles[tab][0].toLowerCase() : "this tab");
      if (typeof applyGlobalSearch === "function") applyGlobalSearch();
    }
  }
  $$("[data-nav] button").forEach(function (b) {
    b.addEventListener("click", function () { go(b.dataset.tab); });
  });

  /* ---------- helpers ---------- */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fmtTime(ts) {
    var d = new Date(ts * 1000);
    return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2) +
           ":" + ("0" + d.getSeconds()).slice(-2);
  }
  function fmtBytes(n) {
    n = n || 0;
    if (n > 1e9) return (n / 1e9).toFixed(2) + " GB";
    if (n > 1e6) return (n / 1e6).toFixed(1) + " MB";
    if (n > 1e3) return (n / 1e3).toFixed(0) + " KB";
    return n + " B";
  }
  function shortApp(pkg) {
    if (!pkg) return "system";
    var p = pkg.split(".");
    return p.length > 2 ? p[p.length - 1] : pkg;
  }
  var ICONS = {
    net: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
    sensor: '<path d="M12 2a3 3 0 0 0-3 3v6a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3"/>',
    app: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    log: '<path d="M4 4h16v16H4z"/><path d="M8 9h4M8 13h8M8 17h6"/>',
    radio: '<path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 15.8a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/>',
    threat: '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>',
    alert: '<path d="M12 3a6 6 0 0 0-6 6c0 5-2 6-2 6h16s-2-1-2-6a6 6 0 0 0-6-6Z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
  };
  function icon(group) {
    var g = ICONS[group] ? group : "log";
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7">' + ICONS[g] + "</svg>";
  }
  function pillFor(ev) {
    var d = ev.data || {};
    if (ev.kind === "alert") return ["crit", (d.rule || "alert")];
    if (d.background) return ["crit", "background"];
    if (d.tracker) return ["info", "tracker"];
    if (ev.severity === "warn" || ev.severity === "crit") return ["warn", ev.severity];
    if (d.transport) return ["", d.transport];
    return null;
  }
  function evHTML(ev, flash) {
    var group = ev.kind.split(".")[0];
    var icls = group === "sensor" && ev.kind === "sensor.loc" ? "loc" : group;
    var pill = pillFor(ev);
    return '<div class="ev' + (flash ? " flash" : "") + '" data-transport="' +
      esc((ev.data || {}).transport || "") + '" data-sev="' + esc(ev.severity) + '"' +
      (ev.app ? ' data-app="' + esc(ev.app) + '" title="Click to open ' + esc(shortApp(ev.app)) + ' in Apps"' : "") + ">" +
      '<div class="ic ' + icls + '">' + icon(group) + "</div>" +
      '<div class="body"><div class="t1"><b>' + esc(ev.title) + "</b></div>" +
      (ev.detail ? '<div class="t2">' + esc(ev.detail) + "</div>" : "") + "</div>" +
      '<div class="meta"><span class="ts">' + fmtTime(ev.ts) + "</span>" +
      (pill ? '<span class="pill ' + pill[0] + '">' + esc(pill[1]) + "</span>" : "") +
      "</div></div>";
  }
  function pushFeed(el, ev, max) {
    var empty = el.querySelector(".empty");
    if (empty) empty.remove();
    el.insertAdjacentHTML("afterbegin", evHTML(ev, true));
    while (el.children.length > (max || 60)) el.removeChild(el.lastChild);
    applyRowFilters(el.firstChild, el.id);
  }

  /* severity filter (monitor feed) + global search, applied per row */
  var sevFilter = "all";
  var SEV_RANK = { info: 0, notice: 1, warn: 2, crit: 3 };
  function rowMatchesFilters(row, containerId) {
    if (!row || row.nodeType !== 1) return true;
    if (containerId === "feed-mon" && sevFilter !== "all") {
      var min = sevFilter === "warn" ? 2 : 1;
      if ((SEV_RANK[row.dataset.sev] || 0) < min) return false;
    }
    if (containerId === "feed-net" && curTransport !== "all" &&
        row.dataset.transport !== curTransport) return false;
    var q = gQuery();
    if (q && row.textContent.toLowerCase().indexOf(q) < 0) return false;
    return true;
  }
  function applyRowFilters(row, containerId) {
    if (row && row.nodeType === 1 && row.style)
      row.style.display = rowMatchesFilters(row, containerId) ? "" : "none";
  }

  /* ---------- log views ---------- */
  var sysLogs = [], radioLogs = [];
  var curLvl = "all", curSearch = "";
  function logLineHTML(ev) {
    var d = ev.data || {};
    return '<div class="logln"><span class="lt">' + fmtTime(ev.ts) + "</span>" +
      '<span class="lv ' + esc(d.level || "I") + '">' + esc(d.level || "I") + "</span>" +
      '<span class="lp">' + esc(d.tag || ev.title) + "</span>" +
      '<span class="lm">' + esc((ev.app ? "[" + shortApp(ev.app) + "] " : "") + ev.detail) + "</span></div>";
  }
  function renderRadioLog() {
    $("#radiolog").innerHTML = radioLogs.map(logLineHTML).join("") ||
      '<div class="empty">no radio log lines yet</div>';
  }
  function renderLogs() {
    var out = sysLogs.filter(function (ev) {
      var d = ev.data || {};
      if (curLvl !== "all" && d.level !== curLvl) return false;
      if (curSearch) {
        var hay = ((d.tag || "") + " " + (ev.app || "") + " " + ev.detail).toLowerCase();
        if (hay.indexOf(curSearch) < 0) return false;
      }
      return true;
    });
    $("#logview").innerHTML = out.map(logLineHTML).join("") ||
      '<div class="empty">no matching lines</div>';
    applyGlobalSearch();
  }
  $("#logsearch").addEventListener("input", function () {
    curSearch = this.value.toLowerCase(); renderLogs();
  });
  $$("#lvlseg button").forEach(function (b) {
    b.addEventListener("click", function () {
      $$("#lvlseg button").forEach(function (x) { x.classList.remove("on"); });
      b.classList.add("on"); curLvl = b.dataset.lvl; renderLogs();
    });
  });

  /* ---------- transport filter (network tab) ---------- */
  var curTransport = "all";
  $$("#transportseg button").forEach(function (b) {
    b.addEventListener("click", function () {
      $$("#transportseg button").forEach(function (x) { x.classList.remove("on"); });
      b.classList.add("on"); curTransport = b.dataset.tr;
      $$("#feed-net .ev").forEach(function (row) { applyRowFilters(row, "feed-net"); });
    });
  });

  /* ---------- flow map ---------- */
  var destStats = {};   // key -> {label, count, tracker, alerted, last}
  var alertedIPs = {};
  function noteDest(ev) {
    var d = ev.data || {};
    var key = d.host || d.ip;
    if (!key) return;
    var s = destStats[key] = destStats[key] ||
      { label: key, count: 0, tracker: d.tracker, alerted: false, last: 0 };
    s.count += 1; s.last = ev.ts;
    if (d.tracker) s.tracker = d.tracker;
    if (alertedIPs[d.ip]) s.alerted = true;
  }
  function renderFlow() {
    var svg = $("#flowsvg");
    if (!svg) return;
    var tops = Object.keys(destStats).map(function (k) { return destStats[k]; })
      .sort(function (a, b) { return b.count - a.count; }).slice(0, 6);
    var cx = 140, cy = 150;
    var slots = [[520, 44], [700, 100], [740, 190], [600, 258], [450, 240], [470, 120]];
    var h = "";
    tops.forEach(function (t, i) {
      var p = slots[i]; if (!p) return;
      var col = t.alerted ? "var(--crit)" : t.tracker ? "var(--info)" : "var(--accent)";
      h += '<path d="M' + cx + " " + cy + " C " + (cx + 150) + " " + cy + "," +
        (p[0] - 110) + " " + p[1] + "," + p[0] + " " + p[1] +
        '" fill="none" stroke="' + col + '" stroke-width="1.6" opacity="0.55" stroke-dasharray="5 7">' +
        '<animate attributeName="stroke-dashoffset" from="24" to="0" dur="' +
        (1 + i * 0.25) + 's" repeatCount="indefinite"/></path>';
    });
    tops.forEach(function (t, i) {
      var p = slots[i]; if (!p) return;
      var col = t.alerted ? "var(--crit)" : t.tracker ? "var(--info)" : "var(--accent)";
      h += '<g class="node"><circle cx="' + p[0] + '" cy="' + p[1] + '" r="7" fill="' + col + '"/>' +
        '<text class="nm" x="' + (p[0] + 12) + '" y="' + (p[1] - 2) + '">' + esc(t.label.slice(0, 34)) + "</text>" +
        '<text x="' + (p[0] + 12) + '" y="' + (p[1] + 12) + '">' +
        t.count + " conns" + (t.tracker ? " · " + esc(t.tracker) : "") + "</text></g>";
    });
    h += '<g class="node"><circle cx="' + cx + '" cy="' + cy + '" r="30" fill="var(--panel-2)" stroke="var(--accent)" stroke-width="2"/>' +
      '<path transform="translate(' + (cx - 11) + "," + (cy - 11) + ') scale(0.92)" d="M7 2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Z M11 18h2" fill="none" stroke="var(--accent)" stroke-width="1.6"/>' +
      '<text class="nm" x="' + cx + '" y="' + (cy + 52) + '" text-anchor="middle">this device</text></g>';
    svg.innerHTML = h;
  }
  setInterval(function () {
    if (currentTab === "network") { renderFlow(); renderDestTable(); }
  }, 5000);

  /* ---------- sensor cards (privacy tab) ---------- */
  var sensorLast = {};  // kind -> ev
  var SENSOR_META = {
    "sensor.mic": ["Microphone"], "sensor.cam": ["Camera"],
    "sensor.loc": ["Location"], "sensor.clip": ["Clipboard"],
  };
  function renderSensorCards(cameraActive) {
    var h = "";
    Object.keys(SENSOR_META).forEach(function (kind) {
      var label = SENSOR_META[kind][0];
      var last = sensorLast[kind];
      var liveNow = kind === "sensor.cam" && cameraActive && cameraActive.length;
      var bg = last && last.data && last.data.background;
      h += '<div class="card"><div style="display:flex;align-items:center;gap:11px">' +
        '<div class="ic ' + (kind === "sensor.loc" ? "loc" : "sensor") + '" style="width:34px;height:34px">' + icon("sensor") + "</div>" +
        '<div><div style="font-weight:600;font-size:14px">' + label + "</div>" +
        '<div style="font-size:11px;color:var(--fg-mut)">' +
        (liveNow ? '<span style="color:var(--crit)">● in use: ' + esc(cameraActive.join(", ")) + "</span>" : "○ idle") +
        "</div></div>" +
        (bg ? '<span class="pill crit" style="margin-left:auto">bg access</span>' : "") + "</div>" +
        '<div style="margin-top:11px;font-size:12px;color:var(--fg-dim);font-family:var(--ff-mono)">' +
        (last ? "last: " + esc(last.app || "?") + " · " + fmtTime(last.ts) +
          (bg ? " · BACKGROUND" : "") : "no access seen this session") +
        "</div></div>";
    });
    $("#sensorcards").innerHTML = h;
  }

  /* ---------- status ---------- */
  var lastStatus = {};
  function applyStatus(s) {
    lastStatus = s;
    $("#demobadge").classList.toggle("on", !!s.demo);
    var dev = s.device || {};
    $("#devname").textContent = dev.connected
      ? (dev.model || "device") : "waiting for device…";
    var rootPill = $("#devroot");
    rootPill.textContent = dev.connected ? (dev.root ? "rooted" : "no root") : "offline";
    rootPill.className = "pill " + (dev.connected ? (dev.root ? "good" : "warn") : "crit");
    $("#devmeta").innerHTML = dev.connected
      ? "Android " + esc(dev.android || "?") + " · sdk " + esc(dev.sdk || "?") +
        (dev.wireless ? " · wireless adb" : " · usb") +
        (s.adb_wifi ? ' · <span style="color:var(--warn)">adb-wifi ON</span>' : "")
      : "enable USB debugging and plug in,<br>or adb connect for wireless";
    $("#t-alerts").textContent = s.open_alerts || 0;
    $("#abadge").textContent = s.open_alerts ? s.open_alerts : "";
    $("#t-conns").textContent = s.connections || 0;
    $("#t-transport").textContent = s.transport ? "via " + s.transport : "—";
    $("#t-hosts").textContent = s.hostnames_cached || 0;
    $("#t-capture").textContent = s.capture ? "SNI capture live" : "capture off";
    var cam = s.camera_active || [];
    $("#t-sensors").textContent = cam.length ? cam.length : "—";
    $("#t-sensors-d").textContent = cam.length ? "camera: " + cam.map(shortApp).join(", ") : "idle";
    var god = s.godmode || {};
    var godApps = {};
    Object.keys(god).forEach(function (k) { (god[k] || []).forEach(function (p) { godApps[p] = 1; }); });
    $("#t-god").textContent = Object.keys(godApps).length;
    // now panel
    var nowItems = [];
    cam.forEach(function (p) {
      nowItems.push('<div class="ev"><div class="ic sensor">' + icon("sensor") +
        '</div><div class="body"><div class="t1"><b>' + esc(p) +
        '</b></div><div class="t2">camera open now</div></div><span class="pill crit">live</span></div>');
    });
    Object.keys(god).forEach(function (k) {
      (god[k] || []).forEach(function (p) {
        nowItems.push('<div class="ev"><div class="ic threat">' + icon("threat") +
          '</div><div class="body"><div class="t1"><b>' + esc(p) +
          '</b></div><div class="t2">' + esc(k) + "</div></div>" +
          '<span class="pill warn">god-mode</span></div>');
      });
    });
    $("#nowlist").innerHTML = nowItems.join("") || '<div class="empty">nothing active</div>';
    // telephony (radio tab + privacy context)
    var t = s.telephony || {};
    $("#r-nt").textContent = t.network_type || "—";
    $("#r-op").textContent = t.operator || "—";
    $("#r-call").textContent = t.call_state || "—";
    $("#r-tr").textContent = s.transport || "—";
    var cell = t.cell || {};
    $("#r-ci").textContent = cell.ci != null ? cell.ci : "—";
    $("#r-tac").textContent = cell.tac != null ? cell.tac : "—";
    renderSensorCards(cam);
    applyGlobalSearch();  // #nowlist was rebuilt; re-apply the active filter
  }
  function pollStatus() {
    fetch(dq("/api/status")).then(function (r) { return r.json(); })
      .then(applyStatus).catch(function () {});
  }
  setInterval(pollStatus, 8000);
  pollStatus();

  /* ---------- netstats panels ---------- */
  function renderEgress(stats) {
    var rows = Object.keys(stats).map(function (u) { return stats[u]; })
      .sort(function (a, b) { return (b.tx || 0) - (a.tx || 0); }).slice(0, 10);
    if (!rows.length) return;
    var max = rows[0].tx || 1;
    $("#egress").innerHTML = rows.map(function (r) {
      var wifiW = Math.round(((r.wtx || 0) / max) * 100);
      var cellW = Math.round(((r.mtx || 0) / max) * 100);
      return '<div style="display:flex;align-items:center;gap:12px;padding:8px 15px">' +
        '<div style="width:130px;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' +
        esc(r.app) + '">' + esc(shortApp(r.app)) + "</div>" +
        '<div style="flex:1;display:flex;flex-direction:column;gap:3px">' +
        '<div class="bar"><i style="width:' + wifiW + '%"></i></div>' +
        '<div class="bar"><i class="cell" style="width:' + cellW + '%"></i></div></div>' +
        '<div class="mono tnum" style="width:84px;text-align:right;font-size:11.5px;color:var(--fg-dim)">' +
        fmtBytes(r.wtx) + "<br>" + fmtBytes(r.mtx) + "</div></div>";
    }).join("");
    $("#egresshint").textContent = "top bar wifi · bottom bar cellular (tx)";
    var mob = rows.filter(function (r) { return r.mtx > 0; })
      .sort(function (a, b) { return b.mtx - a.mtx; }).slice(0, 8);
    $("#mobiledata").innerHTML = mob.map(function (r) {
      var w = Math.round((r.mtx / (mob[0].mtx || 1)) * 100);
      return '<div style="display:flex;align-items:center;gap:10px;padding:6px 0">' +
        '<div style="width:110px;font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
        esc(shortApp(r.app)) + "</div>" +
        '<div class="bar" style="flex:1"><i class="cell" style="width:' + w + '%"></i></div>' +
        '<div class="mono tnum" style="width:66px;text-align:right;font-size:11.5px;color:var(--fg-dim)">' +
        fmtBytes(r.mtx) + "</div></div>";
    }).join("") || '<div class="empty">no cellular traffic recorded</div>';
  }

  /* ---------- apps ---------- */
  var DANGEROUS = ["READ_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "READ_CONTACTS", "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES"];
  var lastApps = [];
  function loadApps() {
    fetch(dq("/api/apps")).then(function (r) { return r.json(); }).then(function (apps) {
      lastApps = apps || [];
      $("#t-apps").textContent = lastApps.length;
      var god = 0, side = 0;
      lastApps.forEach(function (a) {
        if (a.godmode && a.godmode.length) god++;
        if (!a.installer || a.installer.indexOf("vending") < 0) side++;
      });
      $("#t-god2").textContent = god;
      $("#t-side").textContent = side;
      renderApps();
    }).catch(function () {});
  }

  function renderApps() {
    var q = ($("#appsearch").value || "").toLowerCase();
    var sort = $("#appsort").value;
    var rows = lastApps.filter(function (a) {
      if (!q) return true;
      var hay = (a.package + " " + (a.version_name || "") + " " +
        (a.installer || "") + " " + (a.granted || []).join(" ") + " " +
        (a.godmode || []).join(" ")).toLowerCase();
      return hay.indexOf(q) >= 0;
    });
    var cmp = {
      risk: function (a, b) { return (b.risk || 0) - (a.risk || 0); },
      name: function (a, b) { return shortApp(a.package).localeCompare(shortApp(b.package)); },
      data: function (a, b) { return (b.data_size || 0) - (a.data_size || 0); },
      cell: function (a, b) { return (b.mtx || 0) - (a.mtx || 0); },
      tx: function (a, b) { return (b.tx || 0) - (a.tx || 0); },
    }[sort] || function () { return 0; };
    rows.sort(cmp);
    var h = rows.map(function (a) {
      var sideloaded = !a.installer || a.installer.indexOf("vending") < 0;
      var granted = (a.granted || []).map(function (p) { return p.split(".").pop(); });
      var hot = granted.filter(function (p) { return DANGEROUS.indexOf(p) >= 0; });
      var risk = a.risk || 0;
      var rcls = risk >= 70 ? "r" : risk >= 40 ? "y" : "g";
      return '<div class="approw clickable" data-app="' + esc(a.package) +
        '" title="Click to inspect storage, logs and backup options">' +
        '<div class="score ' + rcls + '" data-tip="Risk ' + risk + "/100: " +
        esc((a.risk_factors || []).join("; ") || "no risk factors") + '">' + risk + "</div>" +
        '<div class="appmeta"><div class="nm">' + esc(shortApp(a.package)) +
        (a.godmode || []).map(function (g) { return ' <span class="pill crit">' + esc(g) + "</span>"; }).join("") +
        "</div>" +
        '<div class="pk">' + esc(a.package) + " · " +
        (sideloaded ? "sideloaded" : esc(a.installer)) +
        (a.version_name ? " · v" + esc(a.version_name) : "") + "</div>" +
        '<div class="chips">' +
        (a.data_size ? '<span class="pill">' + fmtBytes(a.data_size) + " data</span>" : "") +
        (a.mtx ? '<span class="pill">' + fmtBytes(a.mtx) + " cellular</span>" : "") +
        (sideloaded ? '<span class="pill warn">not Play</span>' : "") + "</div>" +
        (hot.length ? '<div class="perms">' + hot.map(function (p) {
          return '<span class="perm hot">' + esc(p) + "</span>";
        }).join("") + "</div>" : "") +
        "</div></div>";
    }).join("");
    $("#applist").innerHTML = h ||
      '<div class="empty">' + (q ? "nothing matches “" + esc(q) + "”" :
        "no third-party apps found yet") + "</div>";
    $$("#applist .approw").forEach(function (row) {
      row.addEventListener("click", function () {
        go("storage");
        inspectApp(row.dataset.app);
      });
    });
    applyGlobalSearch();
  }
  $("#appsearch").addEventListener("input", renderApps);
  $("#appsort").addEventListener("change", renderApps);

  /* ---------- alerts + rules ---------- */
  var lastAlerts = [], alertSev = "all";
  function loadAlerts() {
    fetch(dq("/api/alerts?state=open")).then(function (r) { return r.json(); }).then(function (alerts) {
      lastAlerts = alerts || [];
      lastAlerts.forEach(function (a) {
        if (a.data && a.data.ip) alertedIPs[a.data.ip] = 1;
      });
      renderAlerts();
    }).catch(function () {});
  }
  function renderAlerts() {
    var alerts = lastAlerts.filter(function (a) {
      return alertSev === "all" || a.severity === alertSev;
    });
    var h = alerts.map(function (a) {
      return '<div class="alertrow"><div class="ic alert" style="width:30px;height:30px;flex:0 0 30px">' +
        icon("alert") + "</div>" +
        '<div class="ab"><div class="at">' + esc(a.title) +
        ' <span class="pill ' + (a.severity === "crit" ? "crit" : "warn") + '">' + esc(a.severity) + "</span>" +
        (a.device ? ' <span class="pill mut">' + esc(shortApp(a.device)) + "</span>" : "") + "</div>" +
        (a.detail ? '<div class="ad">' + esc(a.detail) + "</div>" : "") +
        '<div class="aa"><button class="btn p" data-ack="' + a.id +
        '" title="Mark as reviewed and remove from the open list">Acknowledge</button>' +
        '<button class="btn" data-mute="' + a.id + '" title="Silence this alert">Mute</button>' +
        '<span style="margin-left:auto;font-size:11px;color:var(--fg-mut);font-family:var(--ff-mono)">' +
        fmtTime(a.ts) + "</span></div></div></div>";
    }).join("");
    $("#alertlist").innerHTML = h || '<div class="empty">' +
      (alertSev === "all" ? "no open alerts — all clear" :
        "no open " + esc(alertSev) + " alerts") + "</div>";
    $("#monalerts").innerHTML = lastAlerts.slice(0, 5).map(function (a) {
      return '<div class="ev"><div class="ic alert">' + icon("alert") +
        '</div><div class="body"><div class="t1"><b>' + esc(a.title) +
        '</b></div><div class="t2">' + esc(a.detail || a.rule) + "</div></div>" +
        '<span class="pill ' + (a.severity === "crit" ? "crit" : "warn") + '">' +
        esc(a.severity) + "</span></div>";
    }).join("") || '<div class="empty">no open alerts</div>';
    $$("#alertlist [data-ack], #alertlist [data-mute]").forEach(function (b) {
      b.addEventListener("click", function (e) {
        e.stopPropagation();
        var id = b.dataset.ack || b.dataset.mute;
        var state = b.dataset.ack ? "acked" : "muted";
        fetch("/api/alerts/" + id + "/state", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ state: state }),
        }).then(function () {
          toast(state === "acked" ? "Alert acknowledged" : "Alert muted", "good");
          loadAlerts(); pollStatus();
        });
      });
    });
    applyGlobalSearch();
  }
  $$("#alertsev button").forEach(function (b) {
    b.addEventListener("click", function () {
      $$("#alertsev button").forEach(function (x) { x.classList.remove("on"); });
      b.classList.add("on");
      alertSev = b.dataset.asev;
      renderAlerts();
    });
  });
  function loadRules() {
    fetch(dq("/api/rules")).then(function (r) { return r.json(); }).then(function (rules) {
      $("#rulelist").innerHTML = (rules || []).map(function (r) {
        return '<div class="approw" style="padding:11px 15px"><div class="appmeta">' +
          '<div class="nm" style="font-weight:500;font-size:13px">' + esc(r.name) +
          ' <span class="pill ' + (r.severity === "crit" ? "crit" : r.severity === "warn" ? "warn" : "info") + '">' +
          esc(r.severity) + "</span></div>" +
          '<div class="pk" style="white-space:normal">' + esc(r.description) + "</div></div>" +
          '<button class="toggle' + (r.enabled ? " on" : "") + '" data-rule="' + esc(r.id) +
          '" aria-label="toggle ' + esc(r.name) + '"><i></i></button></div>';
      }).join("");
      $$("#rulelist .toggle").forEach(function (t) {
        t.addEventListener("click", function () {
          var on = !t.classList.contains("on");
          t.classList.toggle("on", on);
          fetch("/api/rules/" + t.dataset.rule, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: on }),
          }).then(function () {
            toast("Rule " + (on ? "enabled" : "disabled"), on ? "good" : "warn");
          });
        });
      });
    }).catch(function () {});
  }
  loadAlerts(); loadRules();

  /* ---------- files & storage ---------- */
  var FOLDER = '<svg class="fico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/></svg>';
  var FILE = '<svg class="fico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4"/></svg>';
  var LINKI = '<svg class="fico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/></svg>';

  var lastStorApps = [];
  var storSort = { col: "data", dir: -1 };
  function loadStorage() {
    fetch(dq("/api/apps")).then(function (r) { return r.json(); }).then(function (apps) {
      lastStorApps = apps || [];
      renderStorageTable();
    }).catch(function () {});

    fetch(dq("/api/storage")).then(function (r) { return r.json(); }).then(function (s) {
      var apps = s.apps || {}, total = 0;
      Object.keys(apps).forEach(function (k) { total += (apps[k].data || 0) + (apps[k].app || 0); });
      $("#t-appdata").textContent = total ? fmtBytes(total) : "—";
      var t = s.totals || {};
      $("#t-datafree").textContent = t.data_free ? fmtBytes(t.data_free) : "—";
      $("#t-cachefree").textContent = t.cache_free ? fmtBytes(t.cache_free) + " cache free" : "";
    }).catch(function () {});

    loadBackups();
  }

  /* ---------- performance / device health ---------- */
  var perfWired = false, perfTimer = null, klogTimer = null;
  function perfRefresh() {
    fetch(dq("/api/perf")).then(function (r) { return r.json(); }).then(renderPerf).catch(function () {});
  }
  function klogRefresh() {
    fetch(dq("/api/perf/kernel?lines=500")).then(function (r) { return r.json(); }).then(renderKernelLog).catch(function () {});
  }
  function perfStopTimers() {
    if (perfTimer) { clearInterval(perfTimer); perfTimer = null; }
    if (klogTimer) { clearInterval(klogTimer); klogTimer = null; }
  }
  function perfPost(url, body) {
    return fetch(dq(url), {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body || {}),
    }).then(function (r) { return r.json(); });
  }
  function fmtMHz(khz) {
    if (!khz) return "—";
    return khz >= 1000000 ? (khz / 1e6).toFixed(2) + " GHz" : Math.round(khz / 1000) + " MHz";
  }
  function tempColor(c) { return c >= 70 ? "#e5484d" : c >= 50 ? "#f5a623" : "#3ecf8e"; }
  function renderCores(cores) {
    var box = $("#p-cores"); if (!box) return;
    if (!cores.length) { box.innerHTML = '<div class="empty">no per-core data</div>'; return; }
    box.innerHTML = cores.map(function (c) {
      var pct = (c.cur && c.max) ? Math.round(c.cur / c.max * 100) : 0, off = !c.online;
      return '<div style="display:flex;align-items:center;gap:8px;margin:5px 0">' +
        '<span style="min-width:52px">Core ' + c.id + "</span>" +
        '<div style="flex:1;min-width:60px;background:rgba(128,128,128,.2);border-radius:4px;height:8px;overflow:hidden"><div style="height:100%;width:' + (off ? 0 : pct) + "%;background:" + (off ? "#666" : "#3b82f6") + '"></div></div>' +
        '<span class="tnum" style="min-width:76px;text-align:right">' + (off ? "offline" : fmtMHz(c.cur)) + "</span>" +
        '<span class="hint" style="min-width:86px">' + esc(c.governor || "") + "</span>" +
        (c.id === 0 ? '<span class="hint" style="min-width:52px">on</span>'
          : '<label class="chk" style="min-width:52px"><input type="checkbox" data-core="' + c.id + '"' + (c.online ? " checked" : "") + "> on</label>") +
        "</div>";
    }).join("");
    $$("#p-cores input[data-core]").forEach(function (cb) {
      cb.addEventListener("change", function () {
        perfPost("/api/perf/core", { core: parseInt(cb.getAttribute("data-core"), 10), online: cb.checked })
          .then(function (r) { if (r && !r.ok) alert(r.output || "failed"); });
      });
    });
  }
  function renderTemps(thermal, batt) {
    var box = $("#p-temps"); if (!box) return;
    var html = "";
    if (batt && batt.level != null) {
      html += '<div style="margin-bottom:10px">Battery <b>' + batt.level + "%</b>" +
        (batt.temp_c != null ? ' · <span style="color:' + tempColor(batt.temp_c) + '">' + batt.temp_c + "°C</span>" : "") +
        (batt.status ? " · " + esc(batt.status) : "") + (batt.charging ? " ⚡" : "") + "</div>";
    }
    if (!thermal.length) { box.innerHTML = html + '<div class="empty">no thermal sensors exposed</div>'; return; }
    thermal.slice().sort(function (a, b) { return b.temp_c - a.temp_c; }).forEach(function (t) {
      html += '<div style="display:flex;justify-content:space-between;gap:10px;margin:3px 0">' +
        '<span class="hint" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(t.type) + "</span>" +
        '<span class="tnum" style="color:' + tempColor(t.temp_c) + '">' + t.temp_c + "°C</span></div>";
    });
    box.innerHTML = html;
  }
  function renderPerf(d) {
    d = d || {};
    var m = d.mem || {}, cpu = d.cpu || {};
    $("#p-memused").textContent = (m.mem_used_pct != null ? m.mem_used_pct + "%" : "—");
    $("#p-memavail").textContent = m.mem_available ? fmtBytes(m.mem_available) + " free of " + fmtBytes(m.mem_total) : "";
    $("#p-swap").textContent = (m.swap_used_pct != null ? m.swap_used_pct + "%" : "—");
    $("#p-swapd").textContent = m.swap_total ? fmtBytes(m.swap_used) + " / " + fmtBytes(m.swap_total) : "no swap";
    var iow = cpu.iow != null ? cpu.iow : null;
    $("#p-iow").textContent = iow != null ? Math.round(iow) + "%" : "—";
    $("#p-iow").style.color = (iow != null && iow > 100) ? "var(--bad,#e5484d)" : "";
    $("#p-load").textContent = (d.loadavg && d.loadavg.length) ? "load " + d.loadavg.join(" ") : "load —";
    renderCores(d.cores || []);
    renderTemps(d.thermal || [], d.battery || {});
    var tb = $("#p-proctbl").querySelector("tbody");
    var procs = d.procs || [];
    if (!procs.length) { tb.innerHTML = '<tr><td colspan="4" class="empty">no process data yet…</td></tr>'; return; }
    tb.innerHTML = procs.map(function (p) {
      return "<tr><td title='pid " + p.pid + "'>" + esc(p.name) + "</td>" +
        "<td class='tnum'>" + fmtBytes(p.res) + "</td>" +
        "<td class='tnum'>" + (p.cpu || 0) + "</td>" +
        "<td><button class='btn sm' data-killpid='" + p.pid + "' data-killname='" + esc(p.name) + "' title='Stop this process'>✕</button></td></tr>";
    }).join("");
    $$("#p-proctbl button[data-killpid]").forEach(function (b) {
      b.addEventListener("click", function () {
        var name = b.getAttribute("data-killname"), pid = b.getAttribute("data-killpid");
        if (!confirm("Stop " + name + " (pid " + pid + ")? Background apps restart automatically.")) return;
        var body = /^[a-z0-9_.]+$/i.test(name) && name.indexOf(".") > 0
          ? { package: name } : { pid: parseInt(pid, 10) };
        perfPost("/api/perf/kill", body).then(function () { setTimeout(loadPerf, 600); });
      });
    });
  }
  function renderKernelLog(res) {
    var box = $("#p-klog");
    if (!res || res.ok === false) { box.innerHTML = '<div class="empty">' + esc((res && res.output) || "could not read kernel log (root needed)") + "</div>"; return; }
    var lines = res.lines || [];
    if (!lines.length) { box.innerHTML = '<div class="empty">kernel log empty</div>'; return; }
    var f = ($("#p-klog-filter").value || "").toLowerCase();
    box.innerHTML = lines.filter(function (l) { return !f || l.text.toLowerCase().indexOf(f) >= 0; })
      .map(function (l) {
        return "<div style='white-space:pre-wrap;" + (l.warn ? "color:var(--bad,#e5484d)" : "") + "'>" + esc(l.text) + "</div>";
      }).join("") || '<div class="empty">no lines match the filter</div>';
    box.scrollTop = box.scrollHeight;
  }
  var RISKY_TK = { cpu_max_freq: 1, cpu_min_freq: 1, gpu_max_freq: 1, gpu_min_freq: 1,
    uv_table: 1, vdd_levels: 1, gpu_uv: 1, display_size: 1, display_density: 1 };
  function renderKnob(k) {
    var id = "tk-" + k.key, ctrl, opts = k.options || [];
    if ((k.kind === "enum" || k.kind === "freq") && opts.length) {
      ctrl = '<select id="' + id + '">' + opts.map(function (o) {
        return "<option" + (String(o) === String(k.value) ? " selected" : "") + ">" + esc(o) + "</option>";
      }).join("") + "</select>";
    } else if (k.kind === "int") {
      ctrl = '<input type="number" id="' + id + '" value="' + esc(k.value) + '"' +
        (k.min != null ? ' min="' + k.min + '"' : "") + (k.max != null ? ' max="' + k.max + '"' : "") + ' style="width:130px">';
    } else {
      ctrl = '<input id="' + id + '" value="' + esc(k.value) + '" style="width:240px">';
    }
    return '<div style="display:flex;align-items:center;gap:8px;margin:5px 0;flex-wrap:wrap">' +
      '<span style="min-width:210px">' + esc(k.label) + (k.unit ? ' <span class="hint">(' + esc(k.unit) + ")</span>" : "") + "</span>" +
      ctrl + '<button class="btn sm" data-tkset="' + esc(k.key) + '">Set</button></div>';
  }
  function renderTunables(data) {
    var box = $("#p-tunables"), groups = (data && data.groups) || [];
    if (!groups.length) { box.innerHTML = '<div class="empty">no writable tunables found on this kernel</div>'; return; }
    box.innerHTML = groups.map(function (g) {
      return '<div style="margin-bottom:12px"><div class="hint" style="font-weight:600;margin:8px 0 2px;text-transform:uppercase;letter-spacing:.04em">' +
        esc(g.name) + "</div>" + (g.knobs || []).map(renderKnob).join("") + "</div>";
    }).join("");
  }
  function loadTunables() {
    fetch(dq("/api/perf/tunables")).then(function (r) { return r.json(); }).then(renderTunables).catch(function () {});
  }
  function loadPerf() {
    perfRefresh();
    loadTunables();
    // live tiles + process list while the tab is open
    if (perfTimer) clearInterval(perfTimer);
    perfTimer = setInterval(perfRefresh, 5000);
    if (perfWired) return;
    perfWired = true;
    $("#p-free").addEventListener("click", function () {
      var btn = $("#p-free"); btn.disabled = true; btn.textContent = "Freeing…";
      perfPost("/api/perf/free", {}).then(function (res) {
        btn.disabled = false; btn.textContent = "Free memory";
        if (res && res.ok) $("#p-freed").textContent = "freed " + fmtBytes(Math.max(res.freed || 0, 0));
        setTimeout(loadPerf, 800);
      }).catch(function () { btn.disabled = false; btn.textContent = "Free memory"; });
    });
    $("#p-klog-load").addEventListener("click", function () {
      $("#p-klog").innerHTML = '<div class="empty">reading…</div>';
      klogRefresh();
    });
    $("#p-klog-live").addEventListener("change", function () {
      if (klogTimer) { clearInterval(klogTimer); klogTimer = null; }
      if (this.checked) { klogRefresh(); klogTimer = setInterval(klogRefresh, 3000); }
    });
    $("#p-klog-filter").addEventListener("input", function () {
      if (lastKlog) renderKernelLog(lastKlog);
    });
    $("#p-tunables").addEventListener("click", function (e) {
      var b = e.target && e.target.closest ? e.target.closest("[data-tkset]") : null;
      if (!b) return;
      var key = b.getAttribute("data-tkset"), inp = $("#tk-" + key);
      var val = inp ? inp.value : "";
      if (RISKY_TK[key] && !confirm("Apply " + key + " = " + val + " ?\nFrequency / voltage / resolution changes can make the device unstable until reboot.")) return;
      b.disabled = true;
      perfPost("/api/perf/tunable", { key: key, value: val }).then(function (r) {
        b.disabled = false;
        if (r && !r.ok) alert(r.output || "failed");
        loadTunables();
      }).catch(function () { b.disabled = false; });
    });
    ["extreme", "gaming", "performance", "balanced", "powersave", "reset"].forEach(function (p) {
      var btn = $("#p-prof-" + p);
      if (!btn) return;
      btn.addEventListener("click", function () {
        if (typeof confirm === "function") {
          if (p === "extreme" && !confirm("EXTREME / NO LIMITS\n\nThis pins CPU & GPU to maximum AND DISABLES THERMAL THROTTLING. The device can overheat and may shut down or be damaged. Only run it briefly and watch the temperatures. Use Reset to undo.\n\nContinue?")) return;
          if (p !== "balanced" && p !== "reset" && p !== "extreme" &&
              !confirm("Apply the " + p + " profile? It sets CPU/GPU clocks, governor, I/O and memory at once. Resets on reboot.")) return;
        }
        var out = $("#p-prof-out"); if (out) out.textContent = (p === "reset" ? "resetting…" : "applying " + p + "…");
        perfPost("/api/perf/profile", { profile: p }).then(function (r) {
          if (out) out.textContent = (r && r.output) || "";
          loadTunables();
        }).catch(function () { if (out) out.textContent = "failed"; });
      });
    });
  }
  var lastKlog = null;
  var _origRenderKernelLog = renderKernelLog;
  renderKernelLog = function (res) { lastKlog = res; _origRenderKernelLog(res); };

  function inspectApp(pkg) {
    var card = $("#appstorage-card");
    card.style.display = "";
    if (card.classList.contains("collapsed")) {
      card.classList.remove("collapsed");
      collapsed["c:storage:" + card.id] = false;
      saveJSON("sentinel-collapsed", collapsed);
    }
    $("#as-title").textContent = "App storage: " + shortApp(pkg);
    $("#appstorage").innerHTML = '<div class="empty">reading ' + esc(pkg) + " …</div>";
    card.scrollIntoView({ behavior: "smooth", block: "nearest" });
    fetch(dq("/api/storage/app/" + encodeURIComponent(pkg))).then(function (r) { return r.json(); })
      .then(function (d) {
        var sizes = d.sizes || {};
        var sub = d.subdirs || {};
        var kv = Object.keys(sub).map(function (k) {
          var p = sub[k];
          return "<dt>" + esc(k) + "</dt><dd>" + esc(p) +
            (sizes[p] ? '  <span style="color:var(--accent)">' + fmtBytes(sizes[p]) + "</span>" : "") + "</dd>";
        }).join("");
        var logs = (d.log_files || []).length
          ? '<div class="sectitle" style="padding:0 15px">log files found (' + d.log_files.length + ")</div>" +
            (d.log_files || []).slice(0, 40).map(function (f) {
              return '<div class="fentry file">' + FILE + '<span class="fn">' + esc(f) + "</span></div>";
            }).join("")
          : '<div class="empty">no log-like files found</div>';
        $("#appstorage").innerHTML =
          '<dl class="kv2"><dt>data dir</dt><dd>' + esc(d.data_dir) +
          (sizes[d.data_dir] ? '  <span style="color:var(--accent)">' + fmtBytes(sizes[d.data_dir]) + "</span>" : "") + "</dd>" + kv + "</dl>" +
          '<div style="padding:0 15px 12px;display:flex;gap:7px;flex-wrap:wrap"><button class="btn p" data-backup2="' + esc(pkg) + '">extract this app (APK + data)</button>' +
          '<button class="btn" data-openam="' + esc(pkg) + '" title="Full details, permissions, app ops, storage and actions">Open in App Manager</button></div>' +
          logs;
        var bb = $("#appstorage [data-backup2]");
        if (bb) bb.addEventListener("click", function () { startBackup(pkg); });
        var ob = $("#appstorage [data-openam]");
        if (ob) ob.addEventListener("click", function () { amOpen(pkg); });
      }).catch(function () {
        $("#appstorage").innerHTML = '<div class="empty">could not read storage (needs root)</div>';
      });
  }

  function startBackup(pkg) {
    fetch(dq("/api/backup/" + encodeURIComponent(pkg)), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apk: true, data: true, external: false }),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.error) { toast(res.error, "warn"); return; }
      toast("Extracting " + shortApp(pkg), "good",
            "APK + data are being pulled; it appears under Backups when done");
      setTimeout(loadBackups, 3000);
    }).catch(function () { toast("extract request failed", "crit"); });
  }

  function loadBackups() {
    fetch(dq("/api/backups")).then(function (r) { return r.json(); }).then(function (b) {
      $("#t-backups").textContent = (b || []).length;
      $("#backuplist").innerHTML = (b || []).map(function (x) {
        return '<div class="fentry"><span class="fn">' + esc(x.package || x.name) +
          '  <span style="color:var(--fg-mut)">' + (x.components || []).join("+") + "</span></span>" +
          '<span class="fsz">' + fmtBytes(x.bytes) + "</span></div>" +
          '<div class="mono" style="font-size:10.5px;color:var(--fg-mut);padding:0 15px 8px;word-break:break-all">' + esc(x.path) + "</div>";
      }).join("") || '<div class="empty">no backups yet</div>';
    }).catch(function () {});
  }

  function browseFiles(path) {
    $("#fb-path").value = path;
    $("#filebrowser").innerHTML = '<div class="empty">listing ' + esc(path) + " …</div>";
    fetch(dq("/api/files?path=" + encodeURIComponent(path))).then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { $("#filebrowser").innerHTML = '<div class="empty">' + esc(d.error) + "</div>"; return; }
        var ents = d.entries || [];
        $("#filebrowser").innerHTML = ents.map(function (e) {
          var ico = e.kind === "dir" ? FOLDER : e.kind === "link" ? LINKI : FILE;
          return '<div class="fentry ' + e.kind + '"' +
            (e.kind === "dir" ? ' data-cd="' + esc(joinPath(path, e.name)) + '"' : "") + ">" +
            ico + '<span class="fn">' + esc(e.name) +
            (e.target ? ' -> ' + esc(e.target) : "") + "</span>" +
            '<span class="fsz">' + (e.kind === "file" ? fmtBytes(e.size) : "") + "</span></div>";
        }).join("") || '<div class="empty">empty directory</div>';
        $$("#filebrowser [data-cd]").forEach(function (row) {
          row.addEventListener("click", function () { browseFiles(row.dataset.cd); });
        });
      }).catch(function () {
        $("#filebrowser").innerHTML = '<div class="empty">could not list (needs root for app dirs)</div>';
      });
  }
  function joinPath(base, name) {
    return (base.replace(/\/+$/, "") || "") + "/" + name;
  }
  function parentPath(p) {
    p = p.replace(/\/+$/, "");
    var i = p.lastIndexOf("/");
    return i <= 0 ? "/" : p.slice(0, i);
  }
  $("#fb-go").addEventListener("click", function () { browseFiles($("#fb-path").value || "/sdcard"); });
  $("#fb-up").addEventListener("click", function () { browseFiles(parentPath($("#fb-path").value || "/sdcard")); });
  $("#fb-path").addEventListener("keydown", function (e) {
    if (e.key === "Enter") browseFiles(this.value || "/sdcard");
  });
  $("#ev-go").addEventListener("click", function () {
    var hours = $("#ev-hours").value;
    $("#ev-result").textContent = "exporting…";
    fetch("/api/export/evidence", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hours: Number(hours), device: DEV }),
    }).then(function (r) { return r.json(); })
      .then(function (d) {
        $("#ev-result").innerHTML = "Saved " + d.alerts + " alerts, " + d.events +
          " events.<br>" + esc(d.path) + "<br>sha256 " + esc((d.sha256 || "").slice(0, 16)) + "…";
      }).catch(function () { $("#ev-result").textContent = "export failed"; });
  });

  setInterval(function () { if (currentTab === "alerts" || currentTab === "monitor") loadAlerts(); }, 20000);
  setInterval(function () {
    fetch(dq("/api/netstats")).then(function (r) { return r.json(); })
      .then(renderEgress).catch(function () {});
  }, 12000);
  fetch(dq("/api/netstats")).then(function (r) { return r.json(); }).then(renderEgress).catch(function () {});

  /* ---------- devices & ADB ---------- */
  function populatePicker(data) {
    var sel = $("#devpick");
    var mon = (data.devices || []).filter(function (d) { return d.monitored; });
    var want = (DEV && mon.some(function (d) { return d.serial === DEV; })) ? DEV
      : (data.default || "");
    sel.innerHTML = '<option value="">auto (' + (mon.length) + " device" +
      (mon.length === 1 ? "" : "s") + ")</option>" +
      mon.map(function (d) {
        var s = d.summary || {};
        return '<option value="' + esc(d.serial) + '">' +
          esc(s.model || d.serial) + " · " + esc(s.transport || d.transport || "") + "</option>";
      }).join("");
    sel.value = DEV && mon.some(function (d) { return d.serial === DEV; }) ? DEV : "";
    sel.style.display = mon.length > 1 ? "" : (mon.length ? "" : "none");
  }

  function renderDeviceList(data) {
    var devs = data.devices || [];
    $("#t-mon").textContent = data.count || 0;
    $("#t-seen").textContent = devs.length;
    $("#t-adbver").textContent = (data.adb_version || "").replace("Android Debug Bridge version", "").trim() || "—";
    var notReady = devs.filter(function (d) { return !d.ready; }).length;
    $("#t-notready").textContent = notReady ? (notReady + " need attention") : "all ready";
    $("#dbadge").textContent = notReady ? notReady : "";
    if (currentTab !== "devices") return;
    $("#devlist").innerHTML = devs.map(function (d) {
      var s = d.summary || {};
      var cls = d.ready ? "ready" : "bad";
      var acts = [];
      if (d.ready && d.monitored) acts.push('<button class="btn p" data-view="' + esc(d.serial) + '">view</button>');
      if (!d.ready) acts.push('<button class="btn" data-reconnect="' + esc(d.serial) + '">reconnect</button>');
      if (d.transport === "wireless") acts.push('<button class="btn" data-disconnect="' + esc(d.serial) + '">disconnect</button>');
      return '<div class="devrow ' + cls + '"><div class="dled"></div><div class="dbody">' +
        '<div class="dnm">' + esc(s.model || d.model || d.serial) +
        ' <span class="pill ' + (d.ready ? "good" : "crit") + '">' + esc(d.state || "?") + "</span>" +
        ' <span class="pill mut">' + esc(d.transport || "") + "</span>" +
        (s.android ? ' <span class="pill mut">Android ' + esc(s.android) + "</span>" : "") +
        (s.root === false ? ' <span class="pill warn">no root</span>' : "") +
        (d.monitored ? ' <span class="pill good">monitored</span>' : "") + "</div>" +
        '<div class="dser">' + esc(d.serial) + "</div>" +
        (d.ready ? "" : '<div class="drsn">' + esc(d.reason || "") + "</div>") +
        (acts.length ? '<div class="dact">' + acts.join("") + "</div>" : "") +
        "</div></div>";
    }).join("") || '<div class="empty">no devices. Plug in over USB with debugging on, or connect wireless below.</div>';
    $$("#devlist [data-view]").forEach(function (b) {
      b.addEventListener("click", function () { setDevice(b.dataset.view); go("monitor"); });
    });
    $$("#devlist [data-reconnect]").forEach(function (b) {
      b.addEventListener("click", function () { adbPost("/api/adb/reconnect", { serial: b.dataset.reconnect }, "#adb-out"); });
    });
    $$("#devlist [data-disconnect]").forEach(function (b) {
      b.addEventListener("click", function () { adbPost("/api/adb/disconnect", { host_port: b.dataset.disconnect }, "#adb-out2"); });
    });
    applyGlobalSearch();
  }

  var lastDevices = null;  // last /api/devices answer; the root card reads the monitored set from it
  function loadDevices() {
    fetch("/api/devices").then(function (r) { return r.json(); })
      .then(function (data) { lastDevices = data; populatePicker(data); renderDeviceList(data); })
      .catch(function () {});
  }
  function pollDevices() { loadDevices(); }
  setInterval(pollDevices, 5000);
  loadDevices();

  $("#devpick").addEventListener("change", function () { setDevice(this.value); });

  function adbPost(path, body, outSel) {
    var out = outSel ? $(outSel) : null;
    if (out) out.textContent = "working…";
    return fetch(path, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    }).then(function (r) {
      return r.json().then(function (j) { return { ok: r.ok, j: j }; });
    }).then(function (res) {
      var j = res.j || {};
      var msg = j.ok === false ? ("error: " + (j.error || "failed")) : (j.output || "done");
      if (out) out.textContent = msg;
      toast(j.ok === false ? msg : "ADB: " + msg.split("\n")[0], j.ok === false ? "warn" : "good");
      setTimeout(pollDevices, 900);
      return res;
    }).catch(function () {
      if (out) out.textContent = "request failed";
      toast("ADB request failed", "crit");
    });
  }

  (function wireAdb() {
    var map = [
      ["#adb-restart", "/api/adb/restart", function () { return {}; }, "#adb-out"],
      ["#adb-kill", "/api/adb/kill", function () { return {}; }, "#adb-out"],
      ["#adb-start", "/api/adb/start", function () { return {}; }, "#adb-out"],
      ["#adb-reconnect", "/api/adb/reconnect", function () { return { offline: true }; }, "#adb-out"],
    ];
    map.forEach(function (m) {
      var b = $(m[0]); if (b) b.addEventListener("click", function () { adbPost(m[1], m[2](), m[3]); });
    });
    var pair = $("#adb-pair");
    if (pair) pair.addEventListener("click", function () {
      adbPost("/api/adb/pair", { host_port: $("#pair-hp").value.trim(), code: $("#pair-code").value.trim() }, "#adb-out2");
    });
    var conn = $("#adb-connect");
    if (conn) conn.addEventListener("click", function () {
      adbPost("/api/adb/connect", { host_port: $("#conn-hp").value.trim() }, "#adb-out2");
    });
  })();

  /* ---------- root / su card: one row per monitored device, from GET /api/root ---------- */
  function loadRootCard() {
    var box = $("#root-body");
    if (!box) return;
    var devs = lastDevices ? Promise.resolve(lastDevices)
      : fetch("/api/devices").then(function (r) { return r.json(); });
    devs.then(function (data) {
      var mon = (data.devices || []).filter(function (d) { return d.monitored && d.ready; });
      if (!mon.length) {
        box.innerHTML = '<div class="empty">no monitored device - root status appears once one is attached</div>';
        return;
      }
      return Promise.all(mon.map(function (d) {
        return getJSON("/api/root?device=" + encodeURIComponent(d.serial))
          .catch(function (err) { return { error: err.message || "root status unavailable" }; });
      })).then(function (rs) {
        box.innerHTML = mon.map(function (d, i) { return rootRowHTML(d, rs[i] || {}); }).join("");
        if (DEV === null || mon.some(function (d) { return d.serial === DEV; })) amRoot = null;  // chip re-reads
      });
    }).catch(function () { box.innerHTML = '<div class="empty">could not read the device list</div>'; });
  }
  function rootRowHTML(d, r) {
    var s = d.summary || {}, mgr = r.manager || {};
    var chips = r.error
      ? '<span class="pill crit" title="' + esc(r.error) + '">root status unavailable: ' + esc(String(r.error).slice(0, 80)) + "</span>"
      : '<span class="pill ' + (r.root ? "good" : "crit") + '" title="' + esc(r.su_path || "no su binary found") + '">su: ' + (r.root ? "works" : "no") + "</span>" +
        '<span class="pill ' + (mgr.name && mgr.name !== "unknown" ? "info" : "mut") + '">manager: ' +
        esc(mgr.name || "none") + (mgr.version ? " " + esc(mgr.version) : "") + "</span>" +
        '<span class="pill ' + (r.adbd_root ? "good" : "mut") + '">adbd: ' + (r.adbd_root ? "root" : "shell") + "</span>" +
        '<span class="pill ' + (r.selinux === "Permissive" ? "warn" : r.selinux ? "good" : "mut") + '">SELinux: ' + esc(r.selinux || "?") + "</span>" +
        '<span class="pill ' + (r.use_su ? "good" : "warn") + '">using root for actions: ' + (r.use_su ? "on" : "off") + "</span>";
    return '<div class="rootrow" data-serial="' + esc(d.serial) + '"><div class="rn">' + esc(s.model || d.model || d.serial) +
      ' <span class="pill mut">' + esc(d.serial) + "</span>" + (s.demo ? ' <span class="pill warn">demo</span>' : "") + "</div>" +
      '<div class="rchips">' + chips + "</div>" +
      '<div class="racts">' +
      '<button class="btn p" data-rootact="request" title="su -c id with a 45 s timeout: approve the prompt on the phone">Request su</button>' +
      '<label class="am-cklabel" title="Wrap App Manager commands in su -c (persisted per device)">' +
      '<button class="toggle' + (r.use_su ? " on" : "") + '" data-rootact="use" data-enabled="' + (r.use_su ? "false" : "true") +
      '" aria-label="use root for actions"><i></i></button> Use root for actions</label>' +
      '<button class="btn" data-rootact="adbroot" title="adb root: restart adbd with root (userdebug / custom ROMs only)">adb root</button>' +
      '<button class="btn" data-rootact="adbunroot" title="adb unroot: back to the shell user">adb unroot</button>' +
      "</div>" +
      '<div class="rexp"><b>Request su</b> runs <code>su -c id</code> so the root manager (Magisk, KernelSU, APatch…) shows its grant prompt on the phone; you have 45 s to tap Grant. ' +
      "<b>Use root for actions</b> wraps App Manager commands in su; off = plain adb shell, so root-only actions (firewall, IFW, DenyList, prefs) fail cleanly. " +
      "<b>adb root</b> / <b>adb unroot</b> restart adbd itself as root, which only userdebug and custom ROMs allow; production builds answer “adbd cannot run as root”.</div></div>";
  }
  $("#root-body").addEventListener("click", function (e) {
    var b = e.target.closest("[data-rootact]");
    if (!b) return;
    var serial = b.closest(".rootrow").dataset.serial, act = b.dataset.rootact;
    var path = { request: "/api/root/request", use: "/api/root/use", adbroot: "/api/adb/root", adbunroot: "/api/adb/unroot" }[act];
    var body = { device: serial };
    if (act === "use") body.enabled = b.dataset.enabled === "true";
    if (act === "request") toast("Tap Grant on the phone within 45 s", "", "waiting for su on " + serial);
    b.disabled = true;
    postJSON(path, body).then(function (res) {
      var j = res.j || {}, bad = !res.ok || j.ok === false;
      var msg = act === "request" ? (j.root ? "su granted" : "su not granted")
        : act === "use" ? ("root for actions " + (j.use_su ? "on" : "off"))
        : ((j.output || "done").split("\n")[0]);
      toast((bad ? "Failed: " : "") + msg, bad ? "warn" : "good", j.output && act !== "adbroot" && act !== "adbunroot" ? j.output.split("\n")[0] : "");
    }).catch(function () { toast("request failed", "crit"); })
      .then(function () { amRoot = null; setTimeout(function () { loadRootCard(); loadDevices(); }, 700); });
  });

  /* ================= app manager ================= */
  var amApps = [], amWhich = "all", amLocal = null, amSel = null, amMeta = {}, amUser = null, amRows = {};
  var amDev = DEV, amPending = null;  // device the list belongs to; package to open after a reload
  var amListPending = false, amReopen = null;
  var amHandlers = null, amHandlersKey = "";  // "Defaults on this device", cached per device + user
  var amAutoDone = {}, amResolveIv = null;
  var amChecked = {};                  // package -> 1: ticked rows for the bulk bar
  var amRunning = {}, amRunningErr = false;  // package -> {pids, rss_kb} from /running, per list load
  var amRoot = null, amRootKey = "";   // /api/root of the list's device, for the header chip
  var amProcs = {};                    // pid -> process row from the last /running read (Overview names)
  var amTab = "overview", amHistAll = false;
  try { amTab = sessionStorage.getItem("am-tab") || "overview"; } catch (e) {}  // the detail tab is remembered per session
  var amTabCache = {};                 // "<device>|<pkg>|<url>" -> fetched data (lazy per-tab loads)

  // GET/POST helpers: the GET error shape is {"error"}, actions answer {"ok","output"}; a non-JSON
  // body (proxy page, 404 before the backend route exists) must still produce a readable message
  function getJSON(url) {
    return fetch(url).then(function (r) {
      return r.text().then(function (t) {
        var j = null;
        try { j = JSON.parse(t); } catch (e) { j = null; }
        if (!r.ok) throw new Error((j && (j.error || j.output)) || ("HTTP " + r.status + (j && j.detail ? " " + j.detail : "")));
        return j == null ? {} : j;
      });
    });
  }
  function amGet(url) { return getJSON(dq(url)); }
  function postJSON(path, body) {
    return fetch(path, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    }).then(function (r) {
      return r.text().then(function (t) {
        var j = null;
        try { j = JSON.parse(t); } catch (e) { j = null; }
        if (!j) j = { ok: false, output: "HTTP " + r.status };
        return { ok: r.ok, status: r.status, j: j };
      });
    });
  }
  function amUserLabel() {
    if (amUser === "all") return "all users";
    var id = amUser == null ? 0 : amUser, name = "";
    (amMeta.users || []).forEach(function (u) { if (u.id === id) name = u.name; });
    return "user " + id + (name ? " (" + name + ")" : "");
  }
  function amActUser(pkg) {  // all-users mode: act where the app lives
    if (typeof amUser === "number") return amUser;
    var row = pkg ? (amRows[pkg] || {}) : {};
    return (row.users_installed && row.users_installed[0]) || 0;
  }
  function loadAppManager(quiet) {
    if (amDev !== DEV) {  // device switched: user ids, the selection and the ticks belong to the old one
      amDev = DEV; amUser = null; amSel = null; amHandlers = null; amChecked = {}; amTabCache = {};
      amRunning = {}; amRoot = null;
      $("#am-dtitle").textContent = "App details";
      $("#am-dsub").textContent = "select an app";
      $("#am-tabs").style.display = "none";
      // never leave the previous device's action buttons under the new header
      $("#am-dbody").innerHTML = '<div class="empty">Pick an app on the left.</div>';
      renderAmBulk();
    }
    if (quiet && amListPending) return;  // the resolve poll must not pile up listings on a slow device
    if (!quiet) { $("#am-applist").innerHTML = '<div class="empty">loading apps…</div>'; amHandlers = null; }
    var url = "/api/appmanager/list?which=" + amWhich + (amUser != null ? "&user=" + amUser : "");
    amListPending = true;
    fetch(dq(url)).then(function (r) { return r.json(); })
      .then(function (d) {
        amListPending = false;
        amApps = d.apps || []; amMeta = d;
        amRows = {};
        amApps.forEach(function (a) { amRows[a.package] = a; });
        // user / profile picker (only shown when the device has more than one)
        var us = $("#am-user");
        if (us && d.users) {
          var multi = d.users.length > 1;
          us.innerHTML = (multi ? '<option value="all">All users</option>' : "") +
            d.users.map(function (u) {
              return '<option value="' + u.id + '">' + esc(u.name) + " (user " + u.id + ")" +
                (u.running ? "" : " · stopped") + "</option>";
            }).join("");
          us.style.display = multi ? "" : "none";
          if (amUser == null && d.users.length) amUser = d.users[0].id;
          us.value = String(amUser);
        }
        var all = amUser === "all";
        var c = $("#am-count");
        if (c) c.textContent = d.error ? ("⚠ " + d.error) :
          (d.count + " apps" + (all ? " across " + (d.users || []).length + " users" : "") +
           (d.uninstalled ? " · " + d.uninstalled +
             (all ? " not installed for any user" : " uninstalled for this user") : "") +
           (d.labels_resolved ? " · " + d.labels_resolved + " real names from APKs" : "") +
           (d.flags && d.flags !== "demo" ? " · pm " + d.flags : ""));
        // ticks for packages that left the list (other filter / user) are dropped
        Object.keys(amChecked).forEach(function (p) { if (!amRows[p]) delete amChecked[p]; });
        renderAmBulk();
        renderAmList();
        if (amPending) {  // a "find anywhere" hit asked for this package once the list is in
          var p = amPending; amPending = null;
          if (amRows[p]) amSelect(p);
          else toast(shortApp(p) + " is not in this list", "warn", "try the uninstalled filter or All users");
        }
        if (amReopen) {  // user/profile switch: re-open the shown app for that user, or quietly clear the pane
          var rp = amReopen; amReopen = null;
          if (amRows[rp]) amSelect(rp);
          else {
            amSel = null; $("#am-tabs").style.display = "none";
            $("#am-dtitle").textContent = "App details"; $("#am-dsub").textContent = "select an app";
            $("#am-dbody").innerHTML = '<div class="empty">Pick an app on the left.</div>';
          }
        }
        if (!amSel) loadAmDefaults();
        maybeAutoResolve(d);
      })
      .catch(function () { amListPending = false; $("#am-applist").innerHTML = '<div class="empty">could not load apps</div>'; });
    loadAmRunning();
    loadAmRootChip();
    if (!quiet) loadAmOneclick();
  }
  $("#am-user").addEventListener("change", function () {
    amUser = this.value === "all" ? "all" : parseInt(this.value, 10);
    amReopen = amSel;  // the pane is per user: re-open the shown app once the new list is in
    loadAppManager();
  });
  // the list endpoint does not know which apps have a process: one /running read per list load
  function loadAmRunning(done) {
    amGet("/api/appmanager/running").then(function (d) {
      amRunning = {}; amProcs = {}; amRunningErr = false;
      (d.processes || []).forEach(function (p) {
        amProcs[p.pid] = p;
        if (!p.package) return;
        var r = amRunning[p.package] = amRunning[p.package] || { pids: [], rss_kb: 0 };
        r.pids.push(p.pid); r.rss_kb += p.rss_kb || 0;
      });
      if (amApps.length) renderAmList();
      if (done) done();
    }).catch(function () { amRunning = {}; amRunningErr = true; });
  }
  function amSortRows(rows) {
    var sort = $("#am-sort").value;
    var byName = function (a, b) {
      return (a.label || shortApp(a.package)).toLowerCase().localeCompare((b.label || shortApp(b.package)).toLowerCase());
    };
    var srcRank = { apk: 0, known: 1, meta: 2, guess: 3 };
    var cmp = {
      name: byName,
      package: function (a, b) { return a.package.localeCompare(b.package); },
      data: function (a, b) { return ((b.data_size || 0) - (a.data_size || 0)) || byName(a, b); },
      apk: function (a, b) { return ((b.apk_size || 0) - (a.apk_size || 0)) || byName(a, b); },
      source: function (a, b) {
        var x = srcRank[a.label_source], y = srcRank[b.label_source];
        return ((x == null ? 9 : x) - (y == null ? 9 : y)) || byName(a, b);
      },
    }[sort] || byName;
    return rows.slice().sort(cmp);
  }
  function renderAmList() {
    var q = ($("#am-search").value || "").trim().toLowerCase();
    var multi = (amMeta.users || []).length > 1;
    var rows = amApps.filter(function (a) {
      if (amLocal === "running" && !amRunning[a.package]) return false;
      if (amLocal === "frozen" && a.enabled && !a.maybe_hidden) return false;
      if (!q) return true;
      return a.package.toLowerCase().indexOf(q) >= 0 ||
        (a.label || "").toLowerCase().indexOf(q) >= 0;
    });
    rows = amSortRows(rows);
    $("#am-applist").innerHTML = rows.map(function (a) {
      var name = a.label || shortApp(a.package);
      var init = name.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?";
      var nm = a.label_source === "guess"
        ? ' class="am-nm guess" title="name guessed from the package id - press Resolve names for the real one"'
        : a.label_source === "apk" ? ' class="am-nm" title="name read from the APK"' : ' class="am-nm"';
      var ui = a.users_installed || [], run = amRunning[a.package], ck = !!amChecked[a.package];
      return '<div class="am-row' + (ck ? " checked" : "") + '" data-pkg="' + esc(a.package) + '">' +
        '<input type="checkbox" class="am-ck" aria-label="select ' + esc(name) + '"' + (ck ? " checked" : "") + ">" +
        '<div class="ai"' + (a.system ? ' style="background:var(--fg-mut)"' : "") + ">" + esc(init) + "</div>" +
        '<div class="am-meta"><div' + nm + ">" + esc(name) +
        (a.system ? ' <span class="pill mut">system</span>' : "") +
        (amUser === "all" && multi && ui.length
          ? ' <span class="pill mut" title="Android users this package is installed for">' +
            (ui.length > 1 ? "users " : "user ") + esc(ui.join(", ")) + "</span>" : "") +
        (a.maybe_hidden ? ' <span class="pill warn" title="Gone from the package list but its data directory is still there: most likely frozen with pm hide (the detail pane reads the real flag)">hidden (frozen)</span>' :
          a.installed === false ? ' <span class="pill crit" title="Removed for this user (debloated); still on the device">not installed</span>' : "") +
        (!a.enabled && a.installed !== false ? ' <span class="pill warn">disabled</span>' : "") +
        (run ? ' <span class="pill good" title="pids ' + esc(run.pids.join(", ")) + " · " + fmtBytes(run.rss_kb * 1024) + ' resident">running</span>' : "") +
        (a.godmode ? ' <span class="pill crit">god-mode</span>' : "") + "</div>" +
        '<div class="am-pk">' + esc(a.package) + "</div></div>" +
        (a.data_size ? '<span class="fsz">' + fmtBytes(a.data_size) + "</span>" : "") + "</div>";
    }).join("") || (amLocal
      ? '<div class="empty">no ' + esc(amLocal) + " apps" + (q ? " matching “" + esc(q) + "”" : "") +
        (amLocal === "running" && amRunningErr ? " (process list unavailable)" : "") + "</div>"
      : q ? amFindPrompt(q) : '<div class="empty">no apps</div>');
    if (amSel) {
      var s = $('#am-applist .am-row[data-pkg="' + CSS.escape(amSel) + '"]');
      if (s) s.classList.add("sel");
    }
    applyGlobalSearch();
  }
  $("#am-sort").addEventListener("change", renderAmList);
  // one delegated handler for the list: tick boxes, app rows, and the "find anywhere" block
  $("#am-applist").addEventListener("click", function (e) {
    var ck = e.target.closest(".am-ck");
    if (ck) { amToggleCheck(ck.closest(".am-row").dataset.pkg, ck.checked); return; }
    var row = e.target.closest(".am-row");
    if (row) { amSelect(row.dataset.pkg); return; }
    if (e.target.closest("#am-find-btn")) { amFind(); return; }
    var hit = e.target.closest(".am-find-row");
    if (hit) { amOpenFound(hit.dataset.pkg, hit.dataset.user); return; }
    var link = e.target.closest(".am-link");
    if (link) amJump(link.dataset.pkg);
  });
  function amSelect(pkg) {
    $$("#am-applist .am-row").forEach(function (x) { x.classList.toggle("sel", x.dataset.pkg === pkg); });
    loadAmDetail(pkg);
  }
  // open a package named by a link (defaults block, browser chips); it must be in the loaded list
  function amJump(pkg) {
    if (!amRows[pkg]) {
      toast(shortApp(pkg) + ": not in the current list - try the uninstalled filter or All users", "warn");
      return;
    }
    var sb = $("#am-search");
    if (sb.value) { sb.value = ""; renderAmList(); }  // the search filter could be hiding the row
    amSelect(pkg);
    var s = $('#am-applist .am-row[data-pkg="' + CSS.escape(pkg) + '"]');
    if (s && s.scrollIntoView) s.scrollIntoView({ block: "nearest" });
  }
  function amResetFilter() {  // back to "all" so a package opened from elsewhere is in the list
    amWhich = "all"; amLocal = null;
    $$("#am-filter button").forEach(function (x) { x.classList.toggle("on", x.dataset.which === "all"); });
  }
  // open a package from another tab (Files): clear what could hide it, then load the list and select it
  function amOpen(pkg) {
    amResetFilter();
    $("#am-search").value = "";
    amPending = pkg;
    go("appmgr");
  }
  $("#am-search").addEventListener("input", renderAmList);
  $("#am-search").addEventListener("keydown", function (e) {  // Enter with no match = search everywhere; Esc clears
    if (e.key === "Enter" && $("#am-find-btn")) amFind();
    if (e.key === "Escape") { this.value = ""; renderAmList(); this.blur(); }
  });
  function startResolve(auto) {
    if (auto) toast("Reading real app names from the APKs in the background", "",
                    "once per session - press Resolve names to run it again");
    else toast("Resolving app names from APK resources…", "", "this reads only the manifest and resources of each APK");
    fetch("/api/appmanager/resolve-labels", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device: DEV }),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok === false) { toast(res.error || "could not start", "warn"); return; }
      if (!auto) toast(res.running ? "A name resolve is already running for this device"
                                   : "Resolving " + res.packages + " app names", "good");
      var ticks = 0;
      if (amResolveIv) clearInterval(amResolveIv);
      amResolveIv = setInterval(function () {
        // refresh names in place, but never over a "search everywhere" result the user is reading
        if (currentTab === "appmgr" && !$("#am-find")) loadAppManager(true);
        if (++ticks > 45) { clearInterval(amResolveIv); amResolveIv = null; }
      }, 4000);
    }).catch(function () { toast("request failed", "crit"); });
  }
  $("#am-resolve").addEventListener("click", function () { startResolve(false); });
  // a list that is mostly guessed names gets resolved once per browser session, per device
  function maybeAutoResolve(d) {
    if (!d.can_resolve || d.demo || !d.count || (d.labels_resolved || 0) >= Math.ceil(d.count / 2)) return;
    var key = "am-auto:" + (DEV || "default");
    if (amAutoDone[key]) return;
    amAutoDone[key] = 1;  // also stops repeats when sessionStorage is unavailable
    try {
      if (sessionStorage.getItem(key)) return;
      sessionStorage.setItem(key, "1");
      // a previous run that resolved nothing new (APKs without labels) is not retried
      // in every new tab: remember the count it ended with
      if (localStorage.getItem(key + ":done") === String(d.labels_resolved || 0)) return;
      localStorage.setItem(key + ":done", String(d.labels_resolved || 0));
    } catch (e) { /* storage may be blocked */ }
    startResolve(true);
  }
  $$("#am-filter button").forEach(function (b) {
    b.addEventListener("click", function () {
      $$("#am-filter button").forEach(function (x) { x.classList.remove("on"); });
      b.classList.add("on");
      if (b.dataset.local) {  // running / frozen are computed here over the full list
        amLocal = b.dataset.local;
        if (amWhich !== "all") { amWhich = "all"; loadAppManager(); } else renderAmList();
        return;
      }
      amLocal = null;
      amWhich = b.dataset.which;
      loadAppManager();
    });
  });
  // export the list as the backend sees it (filter + user) in a new tab
  $("#am-export").addEventListener("change", function () {
    var f = this.value; this.value = "";
    if (!f) return;
    window.open(dq("/api/appmanager/export?format=" + encodeURIComponent(f) + "&which=" + encodeURIComponent(amWhich) +
      (amUser != null ? "&user=" + encodeURIComponent(amUser) : "")), "_blank");
  });
  // root chip in the header: whether actions run through su on this device
  function loadAmRootChip() {
    var key = DEV || "default";
    if (amRoot && amRootKey === key) { renderAmRootChip(); return; }
    getJSON("/api/root" + (DEV ? "?device=" + encodeURIComponent(DEV) : ""))
      .then(function (r) { amRoot = r; amRootKey = key; renderAmRootChip(); })
      .catch(function (err) { amRoot = { error: err.message }; amRootKey = key; renderAmRootChip(); });
  }
  function renderAmRootChip() {
    var c = $("#am-rootchip"), r = amRoot || {};
    var on = !!(r.root && r.use_su);
    c.className = "pill am-rootchip " + (r.error ? "mut" : on ? "good" : "warn");
    c.textContent = r.error ? "root: unknown" : on ? "root: on" : "root: off - some actions need it";
    c.title = r.error ? ("root status unavailable: " + r.error) :
      ("su " + (r.root ? "works" : "not available") + (r.manager && r.manager.name ? " · " + r.manager.name +
        (r.manager.version ? " " + r.manager.version : "") : "") +
       " · use root for actions: " + (r.use_su ? "on" : "off") + " · click for the Devices tab");
  }
  $("#am-rootchip").addEventListener("click", function () { go("devices"); });

  /* ---- selection + bulk bar ---- */
  function amToggleCheck(pkg, on) {
    if (on) amChecked[pkg] = 1; else delete amChecked[pkg];
    var row = $('#am-applist .am-row[data-pkg="' + CSS.escape(pkg) + '"]');
    if (row) { row.classList.toggle("checked", on); var ck = row.querySelector(".am-ck"); if (ck) ck.checked = on; }
    renderAmBulk();
  }
  function renderAmBulk() {
    var n = Object.keys(amChecked).length;
    $("#am-bulk").style.display = n ? "" : "none";
    $("#am-bulk-n").textContent = n + " selected";
  }
  $("#am-selall").addEventListener("click", function () {
    $$("#am-applist .am-row").forEach(function (r) { amToggleCheck(r.dataset.pkg, true); });
  });
  $("#am-selnone").addEventListener("click", function () {
    Object.keys(amChecked).forEach(function (p) { amToggleCheck(p, false); });
    $("#am-bulk-results").innerHTML = "";
  });
  // data-* of a button -> action params: the contract's boolean fields become booleans, pid a
  // number; free strings stay strings (a pref key may literally be named "true")
  var AM_BOOL_PARAMS = { keep_data: 1, enabled: 1, whitelist: 1, restrict_background: 1, block: 1, allowed: 1, confirm: 1 };
  function amParamsFrom(el, skip) {
    var out = {}, ds = el.dataset;
    Object.keys(ds).forEach(function (k) {
      if (k === "act" || k === "pkg" || k === "batch" || k === "destructive" || (skip && skip.indexOf(k) >= 0)) return;
      var v = ds[k];
      out[k] = AM_BOOL_PARAMS[k] ? v === "true" : k === "pid" ? parseInt(v, 10) : v;
    });
    return out;
  }
  var BATCH_DESTRUCTIVE = { freeze: 1, "clear-data": 1, uninstall: 1, "appops-deny-dangerous": 1,
    "block-trackers": 1, "unblock-trackers": 1 };
  var AM_VERBS = { freeze: "freeze", unfreeze: "unfreeze", "clear-data": "wipe all data of", uninstall: "uninstall",
    "uninstall-updates": "remove the installed updates of", "appops-deny-dangerous": "deny the dangerous app ops of",
    "deny-dangerous-perms": "revoke every dangerous permission of", firewall: "change the firewall rule for",
    "block-trackers": "block the tracker components of", "unblock-trackers": "unblock the tracker components of",
    "ifw-block": "block a component of", "ifw-unblock": "unblock a component of", disable: "disable",
    "prefs-set": "rewrite a preference of", "prefs-delete": "delete a preference of", kill: "kill a process of" };
  function amVerb(action, params) {
    var v = AM_VERBS[action] || action.replace(/-/g, " ");
    if (action === "freeze" && params && params.method) v += " (" + params.method + ")";
    if (action === "uninstall" && params && params.keep_data) v += " (keeping data)";
    if (action === "firewall" && params) v = params.block ? "block all internet access of" : "unblock internet for";
    return v;
  }
  function amBatch(action, options, packages, into) {
    if (!packages.length) { toast("nothing selected", "warn"); return; }
    var destructive = !!BATCH_DESTRUCTIVE[action];
    if (destructive && typeof confirm === "function" &&
        !confirm("This will " + amVerb(action, options) + " " + packages.length + " app" +
          (packages.length === 1 ? "" : "s") + " on the device. Continue?")) return;
    var box = into || $("#am-bulk-results");
    box.innerHTML = '<div class="hint" style="padding:6px 0">running ' + esc(action) + " on " + packages.length + " app" +
      (packages.length === 1 ? "" : "s") + "…</div>";
    // the batch route takes one user: in All-users mode each app is acted on where it lives, so the
    // selection is grouped by user and sent one request per user, in order
    var byUser = {};
    packages.forEach(function (p) { var u = amActUser(p); (byUser[u] = byUser[u] || []).push(p); });
    var users = Object.keys(byUser), out = [];
    users.reduce(function (chain, u) {
      return chain.then(function () {
        return postJSON("/api/appmanager/batch", { device: DEV, action: action, packages: byUser[u], user: parseInt(u, 10),
          confirm: destructive, options: options || {} })
          .catch(function (err) {  // one failed group becomes FAIL lines; the others still render
            return { ok: false, status: 0, j: { output: "request failed" + (err && err.message ? ": " + err.message : "") } };
          })
          .then(function (res) { out.push(res); });
      });
    }, Promise.resolve())
      .then(function () { renderAmResults(box, action, users.length === 1 ? out[0] : amMergeBatch(out, users, byUser)); amAfterBulk(); })
      .catch(function () { box.innerHTML = '<div class="hint">request failed</div>'; toast("batch request failed", "crit"); });
  }
  // per-user batch responses -> one response shaped like the route's; a refused request (no results)
  // becomes one FAIL line per package it covered so nothing is silently dropped
  function amMergeBatch(responses, users, byUser) {
    var j = { results: [], ok_count: 0, fail_count: 0, note: "" };
    responses.forEach(function (res, i) {
      var r = (res && res.j) || {};
      if (res && res.ok && r.results) {
        j.results = j.results.concat(r.results);
        j.ok_count += r.ok_count || 0; j.fail_count += r.fail_count || 0;
        if (r.note && j.note.indexOf(r.note) < 0) j.note += (j.note ? " · " : "") + r.note;
        return;
      }
      var why = r.output || r.error || ("HTTP " + (res ? res.status : "?") + (r.detail ? " " + r.detail : ""));
      byUser[users[i]].forEach(function (p) { j.results.push({ package: p, ok: false, output: why }); j.fail_count++; });
    });
    return { ok: true, status: 200, j: j };
  }
  // postJSON result whose body is {results:[{package, ok, output}], ok_count, fail_count, note?}
  // -> toast + collapsible per-package list; anything else (400 demo refusal, 404) is one hint line
  function renderAmResults(box, title, r) {
    var res = (r && r.j) || {};
    if (!r || !r.ok || res.ok === false || !res.results) {
      var why = res.output || res.error || ("HTTP " + (r ? r.status : "?") + (res.detail ? " " + res.detail : ""));
      box.innerHTML = '<div class="hint" style="padding:6px 0">' + esc(title) + ": " + esc(why) + "</div>";
      toast(title + ": " + why, "warn");
      return;
    }
    var rs = res.results || [], okn = res.ok_count || 0, bad = res.fail_count || 0;
    toast(title + ": " + okn + " ok · " + bad + " failed", bad ? "warn" : "good", res.note || "");
    box.innerHTML = '<details class="am-results"' + (bad ? " open" : "") + "><summary>" + esc(title) + ": " + okn + " ok · " + bad +
      " failed" + (res.note ? " · " + esc(res.note) : "") + " (" + rs.length + " results)</summary>" +
      rs.map(function (r) {
        return '<div class="rr' + (r.ok ? "" : " bad") + '"><span class="pk">' + (r.ok ? "ok  " : "FAIL") + " " + esc(r.package) +
          '</span><span class="out">' + esc((r.output || "").slice(0, 300)) + "</span></div>";
      }).join("") + "</details>";
  }
  function amAfterBulk() {  // anything may have changed: drop the caches, re-read the list and the open app
    amTabCache = {};
    loadAppManager(true);
    if (amSel) loadAmDetail(amSel, true);
  }
  $("#am-bulk").addEventListener("click", function (e) {
    var b = e.target.closest("[data-batch]");
    if (!b) return;
    var action = b.dataset.batch, opts = amParamsFrom(b);
    if (action === "freeze") opts.method = $("#am-bulk-freeze").value;
    if (action === "uninstall") opts.keep_data = $("#am-bulk-keep").checked;
    amBatch(action, opts, Object.keys(amChecked));
  });

  /* ---- install APK (modal, multipart upload) ---- */
  function amInstallOpen() {
    $("#am-inst-user").innerHTML = '<option value="">current (' + esc(amUserLabel()) + ")</option>" +
      (amMeta.users || []).map(function (u) {
        return '<option value="' + u.id + '">' + esc(u.name) + " (user " + u.id + ")</option>";
      }).join("");
    $("#am-install-out").style.display = "none";
    $("#am-install-state").textContent = "";
    $("#am-install-modal").style.display = "";
  }
  function amInstallClose() { $("#am-install-modal").style.display = "none"; }
  $("#am-install-btn").addEventListener("click", amInstallOpen);
  $("#am-install-close").addEventListener("click", amInstallClose);
  $("#am-install-modal").addEventListener("click", function (e) { if (e.target === this) amInstallClose(); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && $("#am-install-modal").style.display !== "none") amInstallClose();
  });
  $("#am-install-go").addEventListener("click", function () {
    var f = $("#am-install-file").files[0], btn = this;
    if (!f) { toast("choose an APK first", "warn"); return; }
    if (f.size > 400 * 1024 * 1024) { toast("file is over 400 MB", "warn"); return; }
    var uv = $("#am-inst-user").value;
    var opts = { device: DEV, user: uv === "" ? (typeof amUser === "number" ? amUser : null) : parseInt(uv, 10),
      replace: $("#am-inst-replace").checked, downgrade: $("#am-inst-downgrade").checked,
      grant_all: $("#am-inst-grant").checked, allow_test: $("#am-inst-test").checked, installer: null };
    var fd = new FormData();
    fd.append("file", f, f.name);
    fd.append("options", JSON.stringify(opts));
    var out = $("#am-install-out"), st = $("#am-install-state");
    st.textContent = "uploading " + fmtBytes(f.size) + " and installing…";
    btn.disabled = true;
    fetch("/api/appmanager/install", { method: "POST", body: fd }).then(function (r) {
      return r.text().then(function (t) {
        var j = null;
        try { j = JSON.parse(t); } catch (e) { j = null; }
        j = j || {};
        if (j.ok == null) j.ok = r.ok;
        if (!j.output) j.output = j.error || ("HTTP " + r.status + (j.detail ? " " + j.detail : ""));
        return j;
      });
    }).then(function (j) {
      st.textContent = j.ok ? "installed" : "failed";
      out.style.display = "";
      out.textContent = (j.output || "") + ((j.files || []).length ? "\n\nfiles: " + j.files.join(", ") : "");
      toast(j.ok ? "Installed " + f.name : "Install failed: " + (j.output || "").split("\n")[0], j.ok ? "good" : "warn");
      if (j.ok) { amTabCache = {}; loadAppManager(true); }
    }).catch(function () { st.textContent = "request failed"; toast("install request failed", "crit"); })
      .then(function () { btn.disabled = false; });
  });

  /* ---- 1-click ops (card under the list) ---- */
  function loadAmOneclick() {
    var box = $("#am-oneclick");
    amGet("/api/appmanager/oneclick").then(function (d) {
      var ops = d.ops || [];
      box.innerHTML = (ops.map(function (o) {
        return '<div class="am-oc" data-op="' + esc(o.id) + '"><div><div class="t">' + esc(o.title) +
          (o.needs_root ? ' <span class="pill warn" title="needs su">root</span>' : "") +
          (o.destructive ? ' <span class="pill crit">destructive</span>' : "") + "</div>" +
          '<div class="d">' + esc(o.description) + "</div></div>" +
          '<div class="v"><select data-scope title="user = third-party apps only; all = everything but the core system">' +
          '<option value="user">user apps</option><option value="all">all apps</option></select>' +
          '<button class="btn ' + (o.destructive ? "danger" : "p") + '" data-run="' + esc(o.id) + '" data-destructive="' +
          (o.destructive ? "1" : "0") + '">Run</button></div></div>';
      }).join("") || '<div class="empty">no operations offered</div>') + '<div id="am-oneclick-results" style="padding:0 15px"></div>';
    }).catch(function (err) {
      box.innerHTML = '<div class="empty">1-click ops unavailable: ' + esc(err.message) + "</div>";
    });
  }
  $("#am-oneclick").addEventListener("click", function (e) {
    var b = e.target.closest("[data-run]");
    if (!b) return;
    var row = b.closest(".am-oc"), scope = row.querySelector("[data-scope]").value, op = b.dataset.run;
    var title = (row.querySelector(".t") || {}).textContent || op, destructive = b.dataset.destructive === "1";
    if (destructive && typeof confirm === "function" &&
        !confirm("Run “" + title.trim() + "” over " + (scope === "all" ? "every app" : "all user apps") +
          " on the device? This changes the device. Continue?")) return;
    var box = $("#am-oneclick-results");
    box.innerHTML = '<div class="hint" style="padding:8px 0">running ' + esc(op) + " over " + esc(scope) + " apps…</div>";
    postJSON("/api/appmanager/oneclick", { device: DEV, op: op, confirm: destructive, scope: scope })
      .then(function (res) { renderAmResults(box, op, res); amAfterBulk(); })
      .catch(function () { box.innerHTML = '<div class="hint">request failed</div>'; toast("request failed", "crit"); });
  });

  /* ---- actions (single app) ---- */
  var DESTRUCTIVE_AM = { disable: 1, "clear-data": 1, uninstall: 1, freeze: 1, "uninstall-updates": 1,
    "appops-deny-dangerous": 1, "deny-dangerous-perms": 1, firewall: 1, "ifw-block": 1, "ifw-unblock": 1,
    "block-trackers": 1, "unblock-trackers": 1, "prefs-set": 1, "prefs-delete": 1, kill: 1 };
  // actions after which the list row itself changes (enabled / installed state)
  var AM_LIST_CHANGING = { enable: 1, disable: 1, freeze: 1, unfreeze: 1, uninstall: 1, reinstall: 1, "uninstall-updates": 1 };
  function amAction(action, params, done) {
    var destructive = !!DESTRUCTIVE_AM[action];
    if (destructive && typeof confirm === "function" &&
        !confirm("This will " + amVerb(action, params) + " " + shortApp(params.package) + " on the device. Continue?")) return;
    var body = Object.assign({ device: DEV, confirm: destructive, user: amActUser(params.package) }, params, { action: action });
    postJSON("/api/appmanager/action", body).then(function (res) {
      var j = res.j || {};
      toast((j.ok ? "" : "Failed: ") + action + " — " + (j.output || "").split("\n")[0], j.ok ? "good" : "warn");
      amInvalidate(params.package);
      setTimeout(function () {
        if (amSel === params.package) loadAmDetail(amSel, true);
        if (AM_LIST_CHANGING[action]) loadAppManager(true);
      }, 600);
      if (done) done(j);
    }).catch(function () { toast("action failed", "crit"); });
  }
  // one delegated handler for the detail pane: package links, tab retry, backup / restore / browse
  // shortcuts, and every [data-act] button (its data-* become the action params)
  $("#am-dbody").addEventListener("click", function (e) {
    var l = e.target.closest(".am-link");
    if (l) { amJump(l.dataset.pkg); return; }
    if (e.target.closest("[data-retry]")) { amShowTab(amTab, true); return; }
    var bb = e.target.closest("[data-backup2]");
    if (bb) { startBackup(bb.dataset.backup2); return; }
    var br = e.target.closest("[data-browse]");
    if (br) { go("storage"); browseFiles(br.dataset.browse); return; }
    var rs = e.target.closest("[data-restore]");
    if (rs) { amRestore(rs); return; }
    var ha = e.target.closest("[data-histall]");
    if (ha) { amHistAll = ha.dataset.histall === "1"; amShowTab("history"); return; }
    // stage-2 tabs: scanner, manifest tools, signature copy / verify, prefs & db navigation and editing
    if (e.target.closest("[data-rescan]")) { amRescan(amSel); return; }
    if (e.target.closest("[data-mfcopy]")) { amCopy(amMfXml(), "the manifest XML"); return; }
    if (e.target.closest("[data-mfdl]")) { amDownload(amMfXml(), (amSel || "app") + "-AndroidManifest.xml", "application/xml"); return; }
    var cp = e.target.closest("[data-copy]");
    if (cp) { amCopy(cp.dataset.copy, "digest"); return; }
    if (e.target.closest("[data-sigverify]")) { amSigVerify(); return; }
    if (e.target.closest("[data-sigpaste]")) { amSigPaste(); return; }
    var pf = e.target.closest("[data-pfile]");
    if (pf) { amLoadPrefFile(amSel, pf.dataset.pfile); return; }
    var df = e.target.closest("[data-dbfile]");
    if (df) { amLoadDb(amSel, df.dataset.dbfile, null); return; }
    var dt = e.target.closest("[data-dbtable]");
    if (dt) { var ds = amDbSel[amSel] || {}; amLoadDb(amSel, ds.file, dt.dataset.dbtable, ds.limit); return; }
    var pe = e.target.closest("[data-pedit]");
    if (pe) { amPrefEdit(pe.closest(".am-pref")); return; }
    var psv = e.target.closest("[data-psave]");
    if (psv) { amPrefSave(psv.closest(".am-pref"), amSel); return; }
    if (e.target.closest("[data-pcancel]")) { amLoadPrefFile(amSel, amPrefSel[amSel]); return; }
    if (e.target.closest("[data-padd]")) { amPrefAdd(amSel); return; }
    var b = e.target.closest("[data-act]");
    if (!b) return;
    var act = b.dataset.act, params = amParamsFrom(b);
    params.package = b.dataset.pkg || amSel;
    if (act === "freeze") { var ms = $("#am-freeze-method"); if (ms) params.method = ms.value; }
    if (act === "uninstall") { var kd = $("#am-keepdata"); if (kd) params.keep_data = kd.checked; }
    amAction(act, params);
  });
  $("#am-dbody").addEventListener("change", function (e) {  // per-op mode selects (App ops tab) + tab controls
    var s = e.target.closest("select[data-opsel]");
    if (s) { amAction("appop", { package: s.dataset.pkg, op: s.dataset.op, mode: s.value }); return; }
    if (e.target.id === "am-comp-trk") { amCompTrk = e.target.checked; amShowTab("components"); return; }
    if (e.target.id === "am-db-limit") {
      var ds = amDbSel[amSel] || {};
      if (ds.file) amLoadDb(amSel, ds.file, ds.table, parseInt(e.target.value, 10) || 200);
    }
  });
  $("#am-dbody").addEventListener("input", function (e) {  // live filters and the hash box
    if (e.target.id === "am-comp-q") amCompFilter();
    else if (e.target.id === "am-mf-q") amMfDebounce();
    else if (e.target.id === "am-sig-in") amSigVerify();
  });
  $("#am-dbody").addEventListener("keydown", function (e) {
    var t = e.target;
    if (e.key === "Escape" && (t.id === "am-comp-q" || t.id === "am-mf-q" || t.id === "am-sig-in")) {
      t.value = "";
      if (t.id === "am-comp-q") amCompFilter(); else if (t.id === "am-mf-q") amManifestSearch(); else amSigVerify();
      t.blur();
      return;
    }
    if (e.key === "Enter" && t.id === "am-sig-in") { amSigVerify(); return; }
    if (e.key === "Enter" && t.id === "am-padd-val") { amPrefAdd(amSel); return; }
    var ed = t.classList && t.classList.contains("am-pedit") ? t.closest(".am-pref") : null;
    if (!ed) return;
    if (e.key === "Enter" && t.tagName !== "TEXTAREA") { e.preventDefault(); amPrefSave(ed, amSel); }
    else if (e.key === "Escape") amLoadPrefFile(amSel, amPrefSel[amSel]);
  });
  function amRestore(btn) {
    var row = btn.closest(".am-bk"), name = btn.dataset.restore, pkg = btn.dataset.pkg;
    var apk = !!(row.querySelector('[data-ropt="apk"]') || {}).checked;
    var data = !!(row.querySelector('[data-ropt="data"]') || {}).checked;
    if (!apk && !data) { toast("tick APK and/or data to restore", "warn"); return; }
    if (typeof confirm === "function" &&
        !confirm("Restore " + name + " (" + (apk ? "APK" : "") + (apk && data ? " + " : "") + (data ? "data over the current data" : "") +
          ") to the device? Continue?")) return;
    postJSON("/api/restore", { device: DEV, name: name, apk: apk, data: data, confirm: true }).then(function (res) {
      var j = res.j || {};
      if (!res.ok || j.ok === false || j.error) { toast("Restore failed: " + (j.output || j.error || "HTTP " + res.status), "warn"); return; }
      toast("Restoring " + shortApp(pkg), "good", "job " + j.job + " · " + (j.state || "running") + " · progress in the Live feed");
      amInvalidate(pkg);
    }).catch(function () { toast("restore request failed", "crit"); });
  }

  /* ---- detail pane: tab frame ----
     AM_TABS entries: {id, label, url, render, after}
       url:    null -> the tab renders from the detail payload (GET /api/appmanager/app/{pkg});
               function(pkg) -> the GET the tab needs; its result is cached per device+pkg+url
       render: function(data, pkg) -> html for #am-dbody
       after:  optional function(data, pkg, force), runs once the html is in place (follow-up
               loads; force is the refresh button's, so they re-read too)
     Loads are lazy (on first show) and cached in amTabCache; amInvalidate(pkg) drops a package's
     entries after an action; the refresh button re-reads the current tab. Stage 2 fills the
     stub renders (components, scanner, manifest, signatures, prefs) and gives them a url. */
  function amAppUrl(pkg, suffix) { return "/api/appmanager/app/" + encodeURIComponent(pkg) + (suffix || ""); }
  // the detail and controls reads are per Android user on the backend: they carry the user the
  // pane's buttons act on, which also keeps one cache entry per user
  function amUserUrl(pkg, suffix) { return amAppUrl(pkg, suffix) + "?user=" + amActUser(pkg); }
  var AM_TABS = [
    { id: "overview", label: "Overview", url: null, render: renderAmTabOverview, after: afterAmTabOverview },
    { id: "permissions", label: "Permissions", url: null, render: renderAmTabPermissions },
    { id: "appops", label: "App ops", url: null, render: renderAmTabAppops },
    { id: "components", label: "Components", url: amManifestUrl, render: renderAmTabComponents, after: afterAmTabComponents },
    { id: "scanner", label: "Scanner", url: amScanUrl, render: renderAmTabScanner },
    { id: "manifest", label: "Manifest", url: amManifestUrl, render: renderAmTabManifest, after: afterAmTabManifest },
    { id: "signatures", label: "Signatures", url: amManifestUrl, render: renderAmTabSignatures, after: afterAmTabSignatures },
    { id: "storage", label: "Storage", url: function (pkg) { return amAppUrl(pkg, "/storage"); }, render: renderAmTabStorage },
    { id: "prefs", label: "Prefs & DBs", url: function (pkg) { return amUserUrl(pkg, "/prefs"); }, render: renderAmTabPrefs, after: afterAmTabPrefs },
    { id: "backups", label: "Backups", url: function () { return "/api/backups"; }, render: renderAmTabBackups },
    { id: "history", label: "History", url: function () { return "/api/appmanager/history?limit=200"; }, render: renderAmTabHistory },
  ];
  function amCacheKey(pkg, url) { return (DEV || "default") + "|" + pkg + "|" + url; }
  function amInvalidate(pkg) {  // after an action every cached load of this package is stale
    var pre = (DEV || "default") + "|" + pkg + "|";
    Object.keys(amTabCache).forEach(function (k) { if (k.indexOf(pre) === 0) delete amTabCache[k]; });
  }
  function amTabLoad(pkg, url, force) {  // a tab's data through the cache; force re-reads it
    var key = amCacheKey(pkg, url);
    if (!force && amTabCache[key]) return Promise.resolve(amTabCache[key]);
    return amGet(url).then(function (d) { amTabCache[key] = d; return d; });
  }
  function amDetailOf(pkg) { return amTabCache[amCacheKey(pkg, amUserUrl(pkg))] || null; }
  function loadAmDetail(pkg, keepTab, force) {
    amSel = pkg;
    void keepTab;  // the tab is remembered per session now: a newly picked app opens on the same tab
    $("#am-dtitle").textContent = (amRows[pkg] || {}).label || shortApp(pkg);
    $("#am-dsub").textContent = pkg;
    renderAmTabBar();
    amShowTab(amTab, force);
  }
  function renderAmTabBar() {
    var bar = $("#am-tabs");
    bar.style.display = "";
    bar.innerHTML = AM_TABS.map(function (t) {
      return '<button data-tab="' + t.id + '"' + (t.id === amTab ? ' class="on"' : "") + ">" + esc(t.label) + "</button>";
    }).join("") + '<button class="am-tab-refresh" data-refresh="1" title="Re-read this tab from the device">refresh</button>';
  }
  $("#am-tabs").addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b || !amSel) return;
    if (b.dataset.refresh) { amShowTab(amTab, true); return; }
    amShowTab(b.dataset.tab);
  });
  function amShowTab(id, force) {
    var spec = AM_TABS[0];
    AM_TABS.forEach(function (t) { if (t.id === id) spec = t; });
    amTab = spec.id;
    try { sessionStorage.setItem("am-tab", amTab); } catch (e) {}
    $$("#am-tabs button[data-tab]").forEach(function (b) { b.classList.toggle("on", b.dataset.tab === amTab); });
    var pkg = amSel, body = $("#am-dbody");
    body.innerHTML = '<div class="empty">reading ' + esc(pkg) + " …</div>";
    amTabLoad(pkg, spec.url ? spec.url(pkg) : amUserUrl(pkg), force).then(function (d) {
      if (amSel !== pkg || amTab !== spec.id) return;  // the user moved on while this loaded
      body.innerHTML = spec.render(d, pkg);
      if (spec.after) spec.after(d, pkg, force);
      applyGlobalSearch();
    }).catch(function (err) {
      if (amSel !== pkg || amTab !== spec.id) return;
      body.innerHTML = '<div class="empty">could not load ' + esc(spec.label.toLowerCase()) + ": " +
        esc((err && err.message) || "request failed") +
        '<br><button class="btn" data-retry="1" style="margin-top:8px">retry</button></div>';
    });
  }
  function amSec(title, inner, extra) {
    return '<div class="am-sec"' + (extra || "") + "><h4>" + title + "</h4>" + inner + "</div>";
  }
  function amBtn(act, pkg, label, cls, params, title) {
    var ds = "";
    Object.keys(params || {}).forEach(function (k) { ds += " data-" + k + '="' + esc(String(params[k])) + '"'; });
    return '<button class="btn' + (cls ? " " + cls : "") + '" data-act="' + act + '" data-pkg="' + esc(pkg) + '"' + ds +
      (title ? ' title="' + esc(title) + '"' : "") + ">" + label + "</button>";
  }
  function fmtDateTime(ts) {
    if (!ts) return "";
    var d = new Date(ts * 1000);
    return d.getFullYear() + "-" + ("0" + (d.getMonth() + 1)).slice(-2) + "-" + ("0" + d.getDate()).slice(-2) + " " + fmtTime(ts);
  }

  /* ---- tab: Overview ---- */
  function renderAmTabOverview(d, pkg) {
    var det = d.detail || {}, st = d.state || {}, run = d.running || {}, meta = d.meta || {}, ui = d.users_installed || [];
    var row = amRows[pkg] || {}, links = d.links || {};
    var mf = amManifestOf(pkg);  // only when another tab already read it: no APK read for the overview
    if (mf && mf.error) mf = null;
    var gy = function (k, v) { return v == null || v === "" ? "" : "<dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd>"; };
    var host = meta.host_browser;  // meta: WebAPK manifest (host browser, start URL)
    var installed = st.installed != null ? st.installed : row.installed !== false;
    var enabled = det.enabled !== false;
    var frozen = st.frozen || (enabled ? null : "disabled");
    var pids = run.pids || [];
    var state = '<div class="am-state">' +
      '<span class="pill mut">' + (det.system ? "system" : "user app") + "</span>" +
      (installed === false ? '<span class="pill crit">not installed for ' + esc(amUserLabel()) + "</span>" : "") +
      (frozen ? '<span class="pill warn">' + esc(frozen) + "</span>" : '<span class="pill good">enabled</span>') +
      (st.hidden && frozen !== "hidden" ? '<span class="pill warn">hidden</span>' : "") +
      (st.suspended && frozen !== "suspended" ? '<span class="pill warn">suspended</span>' : "") +
      (st.stopped ? '<span class="pill mut" title="force-stopped state: no process until the user opens it">stopped</span>' : "") +
      (pids.length ? '<span class="pill good" title="pids ' + esc(pids.join(", ")) + '">running · ' + pids.length + " pid" +
        (pids.length === 1 ? "" : "s") + " · " + fmtBytes((run.rss_kb || 0) * 1024) + "</span>" :
        (d.running ? '<span class="pill mut">not running</span>' : "")) +
      (d.godmode || []).map(function (g) { return '<span class="pill crit">' + esc(g) + "</span>"; }).join("") +
      (mf && mf.debuggable ? '<span class="pill crit" title="android:debuggable=true in the manifest">debuggable</span>' : "") +
      (mf && mf.uses_cleartext_traffic ? '<span class="pill warn" title="usesCleartextTraffic=true in the manifest">cleartext</span>' : "") +
      (d.error ? '<span class="pill crit" title="' + esc(d.error) + '">partial</span>' : "") + "</div>";
    var ap = pkg;
    var actions = '<div class="am-actions">' +
      amBtn("launch", ap, "Launch", "p", null, "monkey -p <pkg> ... LAUNCHER") +
      amBtn("open-settings", ap, "Open settings on device", "", null, "App info screen on the phone") +
      amBtn("force-stop", ap, "Force stop") +
      '<span class="am-group">' + amBtn("freeze", ap, "Freeze", "danger", null, "disable-user / suspend / hide for this user") +
      '<select id="am-freeze-method" title="disable: pm disable-user · suspend: pm suspend · hide: pm hide">' +
      '<option value="disable">disable</option><option value="suspend">suspend</option><option value="hide">hide</option></select></span>' +
      amBtn("unfreeze", ap, "Unfreeze", "", null, "pm enable + unsuspend + unhide") +
      amBtn("clear-cache", ap, "Clear cache") +
      amBtn("clear-data", ap, "Clear data", "danger") +
      (installed === false
        ? amBtn("reinstall", ap, "Reinstall", "p", null, "Reinstall for this user from the copy still on the device")
        : '<span class="am-group">' + amBtn("uninstall", ap, "Uninstall", "danger") +
          '<label class="am-cklabel" title="pm uninstall -k: keep the data and cache directories"><input type="checkbox" id="am-keepdata"> keep data</label></span>') +
      (det.system ? amBtn("uninstall-updates", ap, "Uninstall updates", "danger", null, "pm uninstall without --user: back to the factory copy") : "") +
      amBtn("save-apk", ap, "Save APK", "", null, "Pull every APK (base + splits) to this computer") +
      '<button class="btn" data-backup2="' + esc(pkg) + '" title="APK + private data to this computer (data needs root)">Extract APK+data</button>' +
      '<span class="am-group">' + amBtn("compile", ap, "Compile: speed", "", { mode: "speed" }, "pm compile -m speed -f") +
      amBtn("compile", ap, "reset", "", { mode: "reset" }, "pm compile --reset") + "</span>" +
      "</div>";
    var linkrow = '<div class="am-sec"><div class="am-links">' +
      '<a href="' + esc(links.play || ("https://play.google.com/store/apps/details?id=" + encodeURIComponent(pkg))) + '" target="_blank" rel="noopener">Play Store</a>' +
      '<a href="' + esc(links.fdroid || ("https://f-droid.org/packages/" + encodeURIComponent(pkg) + "/")) + '" target="_blank" rel="noopener">F-Droid</a>' +
      '<a href="' + esc(links.exodus || ("https://reports.exodus-privacy.eu.org/en/reports/" + encodeURIComponent(pkg) + "/latest/")) + '" target="_blank" rel="noopener">Exodus trackers</a>' +
      "</div></div>";
    var du = d.data_usage;
    var ident = amSec("Identity", '<dl class="kv2" style="padding:0">' +
      gy("package", pkg) + gy("version", (det.version_name || "?") + " (" + (det.version || "?") + ")") +
      gy("type", det.system ? "system" : "user app") +
      gy("enabled", enabled ? "yes" : "no — " + (frozen || "disabled")) +
      gy("installed for", ui.length ? ui.map(function (u) { return "user " + u; }).join(", ") : null) +
      gy("uid", d.uid) + gy("shared user", d.shared_user) + gy("process", d.process) +
      gy("installer", det.installer || "unknown") +
      gy("web app URL", meta.start_url) + gy("scope", meta.scope) +
      gy("opened by", host ? ((amRows[host] || {}).label || shortApp(host)) + " (" + host + ")" : null) +
      gy("target SDK", det.target_sdk) + gy("min SDK", det.min_sdk) + gy("ABI", det.abi) +
      gy("installed", det.first_install) + gy("updated", det.last_update) +
      gy("data dir", det.data_dir) + gy("signature", det.sig) +
      (du ? gy("data usage", "wifi ↓" + fmtBytes(du.wifi_rx) + " ↑" + fmtBytes(du.wifi_tx) +
        " · mobile ↓" + fmtBytes(du.mobile_rx) + " ↑" + fmtBytes(du.mobile_tx)) : "") +
      "</dl>");
    var controls = amSec("Controls", '<div id="am-controls"><div class="empty" style="padding:8px 0">loading controls…</div></div>');
    var procs = d.running ? amSec("Processes", '<div id="am-procs">' + renderAmProcs(run, pkg) + "</div>") : "";
    return state + actions + linkrow + ident + procs + controls;
  }
  function afterAmTabOverview(d, pkg, force) {
    loadAmControls(pkg, force);
    var pids = (d.running || {}).pids || [];
    if (pids.some(function (p) { return !amProcs[p]; })) {  // names come from /running, not the detail
      loadAmRunning(function () {
        var box = $("#am-procs");
        if (box && amSel === pkg && amTab === "overview") box.innerHTML = renderAmProcs(d.running, pkg);
      });
    }
  }
  function loadAmControls(pkg, force) {
    amTabLoad(pkg, amUserUrl(pkg, "/controls"), force).then(function (c) {
      var box = $("#am-controls");
      if (box && amSel === pkg) box.innerHTML = renderAmControls(c, pkg);
    }).catch(function (err) {
      var box = $("#am-controls");
      if (box && amSel === pkg) box.innerHTML = '<div class="hint">controls unavailable: ' + esc(err.message) + "</div>";
    });
  }
  function renderAmControls(c, pkg) {
    var yn = function (v, yes, no, cls) {
      return v == null ? '<span class="pill mut">unknown</span>' :
        '<span class="pill ' + (cls ? cls(v) : (v ? "warn" : "mut")) + '">' + (v ? yes : no) + "</span>";
    };
    var ctl = function (k, sub, v) {
      return '<div class="am-ctl"><div class="k">' + k + (sub ? "<small>" + esc(sub) + "</small>" : "") + '</div><div class="v">' + v + "</div></div>";
    };
    var h = "";
    h += ctl("Battery optimisation exempt", "dumpsys deviceidle whitelist",
      yn(c.battery_whitelisted, "exempt", "optimised", function (v) { return v ? "good" : "mut"; }) +
      (c.battery_whitelisted ? amBtn("battery", pkg, "optimise", "", { whitelist: false }) : amBtn("battery", pkg, "exempt", "", { whitelist: true })));
    h += ctl("Restrict background data", "cmd netpolicy restrict-background-blacklist",
      yn(c.net_restricted_background, "restricted", "allowed") +
      (c.net_restricted_background ? amBtn("netpolicy", pkg, "allow", "", { restrict_background: false }) : amBtn("netpolicy", pkg, "restrict", "", { restrict_background: true })));
    if (c.data_saver != null) h += ctl("Data saver", "device-wide setting", yn(c.data_saver, "on", "off"));
    h += ctl("Sensors", "cmd sensorservice set-uid-state",
      yn(c.sensors === "active" ? true : c.sensors === "idle" ? false : null, "active", "idle", function (v) { return v ? "good" : "warn"; }) +
      amBtn("sensors", pkg, "active", "", { state: "active" }) + amBtn("sensors", pkg, "idle", "", { state: "idle" }) +
      amBtn("sensors", pkg, "reset", "", { state: "reset" }));
    if (c.denylist_available) h += ctl("Magisk DenyList", "root is hidden from the app while listed",
      yn(c.denylist, "listed", "not listed", function (v) { return v ? "good" : "mut"; }) +
      (c.denylist ? amBtn("denylist", pkg, "remove", "", { enabled: false }) : amBtn("denylist", pkg, "add", "", { enabled: true })));
    var al = c.app_links || [];
    h += ctl("Open links allowed", al.length ? al.map(function (l) { return l.domain + " (" + l.state + ")"; }).join(", ").slice(0, 300) : "pm set-app-links-allowed",
      yn(c.app_links_allowed, "allowed", "not allowed", function (v) { return v ? "good" : "mut"; }) +
      (c.app_links_allowed ? amBtn("app-links", pkg, "disallow", "", { allowed: false }) : amBtn("app-links", pkg, "allow", "", { allowed: true })));
    h += ctl("Firewall", "iptables owner match on the uid; does not survive a reboot",
      yn(c.firewall_blocked, "internet blocked", "internet allowed", function (v) { return v ? "crit" : "good"; }) +
      (c.firewall_blocked ? amBtn("firewall", pkg, "unblock", "", { block: false }) : amBtn("firewall", pkg, "block internet", "danger", { block: true })));
    var ov = c.overlays || [];
    if (ov.length) h += ctl("Overlays", "runtime resource overlays targeting this app (read-only)",
      ov.map(function (o) { return '<span class="pill ' + (o.enabled ? "good" : "mut") + '" title="' + esc(o.name) + '">' + esc(shortApp(o.name)) + "</span>"; }).join(""));
    h += ctl("SSAID", "per-app Android ID", '<span class="mono" style="font-size:11.5px">' + esc(c.ssaid || "—") + "</span>");
    h += ctl("KeyStore files", "/data/misc/keystore entries", '<span class="mono" style="font-size:11.5px">' + esc(c.keystore_files == null ? "—" : c.keystore_files) + "</span>");
    var errs = c.errors || {};
    var ek = Object.keys(errs);
    if (ek.length) h += '<div class="hint" style="margin-top:8px;font-size:11px;font-family:var(--ff-mono);color:var(--fg-mut)">' +
      ek.map(function (k) { return esc(k) + ": " + esc(errs[k]); }).join("<br>") + "</div>";
    return h;
  }

  /* ---- tab: Permissions ---- */
  // the standard Android runtime (dangerous) permission list; DANGEROUS above is the risk subset
  var DANGEROUS_PERMS = ["READ_CALENDAR", "WRITE_CALENDAR", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
    "ANSWER_PHONE_CALLS", "ADD_VOICEMAIL", "USE_SIP", "ACCEPT_HANDOVER", "BODY_SENSORS", "BODY_SENSORS_BACKGROUND",
    "ACTIVITY_RECOGNITION", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "ACCESS_MEDIA_LOCATION", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO", "READ_MEDIA_VISUAL_USER_SELECTED", "BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT",
    "NEARBY_WIFI_DEVICES", "POST_NOTIFICATIONS", "UWB_RANGING"];
  var SPECIAL_PERMS = ["SYSTEM_ALERT_WINDOW", "PACKAGE_USAGE_STATS", "WRITE_SETTINGS", "REQUEST_INSTALL_PACKAGES",
    "MANAGE_EXTERNAL_STORAGE", "BIND_ACCESSIBILITY_SERVICE", "BIND_NOTIFICATION_LISTENER_SERVICE", "BIND_DEVICE_ADMIN"];
  function isDangerousPerm(p) {
    var s = p.split(".").pop();
    return DANGEROUS.indexOf(s) >= 0 || DANGEROUS_PERMS.indexOf(s) >= 0;
  }
  function renderAmTabPermissions(d, pkg) {
    var det = d.detail || {}, flags = d.perm_flags || {};
    var granted = det.granted || [], requested = det.requested || [];
    var gset = {};
    granted.forEach(function (p) { gset[p] = 1; });
    var all = requested.slice();
    granted.forEach(function (p) { if (all.indexOf(p) < 0) all.push(p); });  // granted but not listed as requested
    var ndanger = all.filter(function (p) { return gset[p] && isDangerousPerm(p); }).length;
    var rows = all.map(function (p) {
      var on = gset[p], danger = isDangerousPerm(p), fl = flags[p] || [];
      return '<div class="permrow"><span class="pn' + (danger ? '" style="color:var(--crit)' : "") + '">' +
        esc(p.replace("android.permission.", "")) +
        (fl.length ? '<div class="am-flags">' + esc(fl.join(" ")) + "</div>" : "") + "</span>" +
        (danger ? '<span class="pill crit" title="runtime (dangerous) permission">dangerous</span>' : "") +
        '<span class="pill ' + (on ? "good" : "mut") + '">' + (on ? "granted" : "denied") + "</span>" +
        amBtn(on ? "revoke" : "grant", pkg, on ? "revoke" : "grant", "", { permission: p }) + "</div>";
    }).join("");
    var head = '<div class="am-actions">' +
      amBtn("deny-dangerous-perms", pkg, "Deny all dangerous (" + ndanger + ")", "danger", null, "pm revoke every granted runtime permission") +
      '<span class="hint">' + granted.length + " of " + all.length + " granted · runtime permissions in red</span></div>";
    var special = SPECIAL_PERMS.filter(function (s) {
      return all.some(function (p) { return p.split(".").pop() === s; });
    }).map(function (s) {
      var on = all.some(function (p) { return p.split(".").pop() === s && gset[p]; });
      return '<span class="pill ' + (on ? "crit" : "mut") + '">' + esc(s) + (on ? " · granted" : " · not granted") + "</span> ";
    }).join("");
    return head + amSec("Permissions", rows || '<div class="empty" style="padding:6px 0">no permissions declared</div>') +
      amSec("Special permissions", (special || '<span class="hint">none of the special (settings-page) permissions are requested</span>') +
        '<div class="hint" style="margin-top:8px;font-family:var(--ff-mono);font-size:11px;color:var(--fg-mut)">' +
        "These are granted on their own Settings page, not by pm grant: overlay, usage access, write settings, " +
        "install unknown apps, all-files access, accessibility, notification access, device admin. " +
        "Accessibility, notification and admin grants are the god-mode set.</div>");
  }

  /* ---- tab: App ops ---- */
  var AM_OP_MODES = ["allow", "ignore", "deny", "default", "foreground"];
  function renderAmTabAppops(d, pkg) {
    var ops = d.appops || [];
    var head = '<div class="am-actions">' +
      amBtn("appops-reset", pkg, "Reset to defaults", "", null, "appops reset <pkg>") +
      amBtn("appops-deny-dangerous", pkg, "Deny dangerous ops", "danger", null, "location, camera, mic, contacts, call log, SMS, phone state, clipboard, usage stats, overlay -> ignore") +
      '<span class="am-group">' + amBtn("prevent-background", pkg, "Prevent background", "", { enabled: true }, "RUN_IN_BACKGROUND + RUN_ANY_IN_BACKGROUND = ignore") +
      amBtn("prevent-background", pkg, "allow", "", { enabled: false }) + "</span></div>";
    var rows = ops.map(function (o) {
      var mode = o.mode || "";
      var sel = '<select data-opsel data-pkg="' + esc(pkg) + '" data-op="' + esc(o.op) + '" title="set this op">' +
        (mode && AM_OP_MODES.indexOf(mode) < 0 ? '<option value="' + esc(mode) + '" selected>' + esc(mode) + "</option>" : "") +
        (mode ? "" : '<option value="" selected>set…</option>') +
        AM_OP_MODES.map(function (m) { return '<option value="' + m + '"' + (m === mode ? " selected" : "") + ">" + m + "</option>"; }).join("") +
        "</select>";
      var meta = [];
      if (mode) meta.push("mode " + mode);
      if (o.background) meta.push("background");
      if (o.rejected) meta.push("rejected");
      if (o.ago != null) meta.push(o.ago < 60 ? o.ago + " s ago" : o.ago < 3600 ? Math.round(o.ago / 60) + " min ago" : Math.round(o.ago / 3600) + " h ago");
      return '<div class="am-op"><div><div class="on">' + esc(o.op) +
        (o.background ? ' <span class="pill crit">bg</span>' : "") + (o.rejected ? ' <span class="pill warn">rejected</span>' : "") + "</div>" +
        '<div class="om">' + esc(meta.join(" · ") || "no recent access") + "</div></div><div>" + sel + "</div></div>";
    }).join("");
    return head + amSec("App ops", rows || '<div class="empty" style="padding:6px 0">no app-op activity recorded for this app</div>') +
      '<div class="hint" style="padding:0 15px 12px;font-family:var(--ff-mono);font-size:11px;color:var(--fg-mut)">' +
      "allow / ignore (silently no data) / deny (app sees an error) / default / foreground. ignore is what Android's " +
      "permission toggles use; it keeps the app from crashing.</div>";
  }

  /* ---- manifest-backed tabs: Components, Manifest and Signatures share one GET .../manifest ---- */
  function amManifestUrl(pkg) { return amAppUrl(pkg, "/manifest"); }
  function amScanUrl(pkg) { return amAppUrl(pkg, "/scan?refresh=0"); }
  function amManifestOf(pkg) { return amTabCache[amCacheKey(pkg, amManifestUrl(pkg))] || null; }
  function amKv(k, v) { return v == null || v === "" ? "" : "<dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd>"; }
  // inspect_apk / scan_app answer 200 with {error} when the APK could not be read: say why and the fix
  function amManifestErr(d, what) {
    var e = String(d.error);
    return '<div class="empty">' + esc(what) + " unavailable: " + esc(e) +
      (/pyaxmlparser/i.test(e) ? '<br><span class="hint">pip install pyaxmlparser on this computer, then press refresh</span>' : "") +
      (/root|permission|unreadable|denied/i.test(e) ? '<br><span class="hint">reading the APK under /data/app needs root on most devices - see the Devices tab</span>' : "") +
      '<br><button class="btn" data-retry="1" style="margin-top:8px">retry</button></div>';
  }
  function amShortCls(name, pkg) {  // "com.x.app.ui.Main" -> ".ui.Main" inside its own package, else the full name
    return pkg && name.indexOf(pkg + ".") === 0 ? name.slice(pkg.length) : name;
  }
  // tabs that cross-check the detail payload re-render once it is in (a tab opened directly through the
  // remembered tab has no detail yet); amDetailOf is non-null afterwards, so this runs at most once
  function amWithDetail(pkg, tab) {
    if (amDetailOf(pkg)) return;
    amTabLoad(pkg, amUserUrl(pkg)).then(function () {
      if (amSel === pkg && amTab === tab) amShowTab(tab);
    }).catch(function () { /* the tab already shows what it has */ });
  }

  /* ---- tab: Components ---- */
  var AM_COMP_GROUPS = [["activities", "Activities", "activity"], ["services", "Services", "service"],
    ["receivers", "Receivers", "receiver"], ["providers", "Providers", "provider"]];
  var amCompQ = "", amCompTrk = true;  // the tab's filter box and "trackers first" sort survive re-renders
  function renderAmTabComponents(d, pkg) {
    if (d.error) return amManifestErr(d, "components");
    var det = (amDetailOf(pkg) || {}).detail || {}, offSet = {};
    (det.disabled_components || []).forEach(function (c) { offSet[c] = 1; });
    var total = 0, ntrk = 0;
    var groups = AM_COMP_GROUPS.map(function (g) {
      var list = (d[g[0]] || []).slice();
      total += list.length;
      list.forEach(function (c) { if (c.tracker) ntrk++; });
      if (amCompTrk) list.sort(function (a, b) { return (b.tracker ? 1 : 0) - (a.tracker ? 1 : 0); });
      var rows = list.map(function (c) { return renderAmComp(c, g[2], pkg, offSet); }).join("");
      return '<div class="am-sec am-cgroup" data-group="' + g[0] + '"><h4>' + g[1] + ' <span class="am-cnt">' + list.length + "</span></h4>" +
        (rows || '<div class="hint">none declared</div>') + "</div>";
    }).join("");
    var head = '<div class="am-actions">' +
      amBtn("block-trackers", pkg, "Block all trackers in this app", "danger", null,
        "IFW rule + pm disable on every component the Scanner marked as a tracker (scan first; root)") +
      amBtn("unblock-trackers", pkg, "Unblock", "", null, "remove those IFW rules and re-enable the tracker components (root)") +
      '<span class="hint">' + total + " components · " + ntrk + " tracker" + (ntrk === 1 ? "" : "s") +
      (d.cached ? " · cached" : "") + (d.demo ? " · demo data" : "") + "</span></div>" +
      '<div class="am-tabtools"><input type="search" id="am-comp-q" placeholder="filter: class, tracker, action, scheme…" value="' +
      esc(amCompQ) + '" autocomplete="off">' +
      '<label class="am-cklabel" title="tracker-matched components at the top of each group"><input type="checkbox" id="am-comp-trk"' +
      (amCompTrk ? " checked" : "") + "> trackers first</label></div>";
    return head + groups +
      '<div class="hint" style="padding:0 15px 12px;font-family:var(--ff-mono);font-size:11px;color:var(--fg-mut)">' +
      "Block writes an intent-firewall rule (/data/system/ifw/&lt;pkg&gt;.xml) and pm-disables the component; both need root. " +
      "Providers have no IFW rule type - use Disable. Launch / Start / Send run am start / start-service / broadcast with -n.</div>";
  }
  function afterAmTabComponents(d, pkg) {
    if (amCompQ) amCompFilter();
    amWithDetail(pkg, "components");  // the disabled pills cross-check dumpsys' disabled_components
  }
  function renderAmComp(c, kind, pkg, offSet) {
    var name = c.name || "", comp = pkg + "/" + name, ifs = c.intent_filters || [];
    var off = c.enabled === false || !!offSet[name];
    var q = (name + " " + (c.tracker || "") + " " + (c.authorities || []).join(" ") + " " + ifs.map(function (f) {
      return (f.actions || []).join(" ") + " " + (f.categories || []).join(" ") + " " +
        (f.data || []).map(function (x) { return [x.scheme, x.host, x.mime].join(" "); }).join(" ");
    }).join(" ")).toLowerCase();
    var pills = (c.exported ? '<span class="pill warn" title="other apps can start this component">exported</span>' : "") +
      (c.permission ? '<span class="pill mut" title="' + esc(c.permission) + '">permission</span>' : "") +
      (off ? '<span class="pill warn">disabled</span>' : "") +
      (c.tracker ? '<span class="pill crit" title="class prefix matches a tracker signature">tracker · ' + esc(c.tracker) + "</span>" : "");
    var meta = [];
    if (c.launch_mode && c.launch_mode !== "standard") meta.push("launch " + c.launch_mode);
    if (c.process) meta.push("process " + c.process);
    if (kind === "provider" && (c.authorities || []).length) meta.push("authorities " + c.authorities.join(", "));
    if (kind === "provider" && c.grant_uri_permissions) meta.push("grants URI permissions");
    var ifh = ifs.length ? '<details class="am-if"><summary>' + ifs.length + " intent filter" + (ifs.length === 1 ? "" : "s") +
      " · " + esc(amIfSummary(ifs)) + "</summary>" + ifs.map(function (f) {
        var data = (f.data || []).map(function (x) {
          return [x.scheme ? x.scheme + ":" : "", x.host ? "//" + x.host : "", x.path || "", x.mime ? " " + x.mime : ""].join("");
        }).filter(Boolean);
        return '<div class="am-ifr">' +
          (f.actions || []).map(function (a) { return '<span class="pill mut">' + esc(a.replace("android.intent.action.", "")) + "</span>"; }).join("") +
          (f.categories || []).map(function (a) { return '<span class="pill info">' + esc(a.replace("android.intent.category.", "")) + "</span>"; }).join("") +
          (data.length ? '<span class="mono">' + esc(data.join("  ")) + "</span>" : "") + "</div>";
      }).join("") + "</details>" : "";
    var acts = "";
    if (kind === "activity") acts += amBtn("launch-activity", pkg, "Launch", "p", { component: comp },
      "am start -n " + comp + " (through su when root is in use, so non-exported activities start too)");
    if (kind === "service") acts += amBtn("start-service", pkg, "Start", "p", { component: comp }, "am start-service -n " + comp);
    if (kind === "receiver") acts += amBtn("send-broadcast", pkg, "Send", "p", { component: comp }, "am broadcast -n " + comp);
    acts += off ? amBtn("enable-component", pkg, "Enable", "", { component: comp }, "pm enable " + comp)
                : amBtn("disable-component", pkg, "Disable", "", { component: comp }, "pm disable " + comp);
    if (kind !== "provider") acts +=
      amBtn("ifw-block", pkg, "Block", "danger", { component: comp }, "intent-firewall rule for " + comp + " + pm disable (root)") +
      amBtn("ifw-unblock", pkg, "Unblock", "", { component: comp }, "remove the IFW rule for " + comp + " and re-enable it (root)");
    return '<div class="am-comp' + (c.tracker ? " trk" : "") + '" data-q="' + esc(q) + '">' +
      '<div class="am-comp-h"><span class="cn" title="' + esc(name) + '">' + esc(amShortCls(name, pkg)) + "</span>" + pills + "</div>" +
      (meta.length ? '<div class="am-comp-m">' + esc(meta.join(" · ")) + "</div>" : "") + ifh +
      '<div class="am-comp-a">' + acts + "</div></div>";
  }
  function amIfSummary(ifs) {
    var acts = {}, schemes = {};
    ifs.forEach(function (f) {
      (f.actions || []).forEach(function (a) { acts[a.replace(/^android\.intent\.action\./, "")] = 1; });
      (f.data || []).forEach(function (x) { if (x.scheme) schemes[x.scheme] = 1; });
    });
    var a = Object.keys(acts), s = Object.keys(schemes);
    return a.slice(0, 3).join(", ") + (a.length > 3 ? " +" + (a.length - 3) : "") + (s.length ? " · " + s.join("/") : "");
  }
  function amCompFilter() {  // client-side over the rendered rows; empty groups say so through their count
    var q = amCompQ = (($("#am-comp-q") || {}).value || "").trim().toLowerCase();
    $$("#am-dbody .am-cgroup").forEach(function (g) {
      var all = $$(".am-comp", g), n = 0;
      all.forEach(function (r) {
        var show = !q || (r.dataset.q || "").indexOf(q) >= 0;
        r.style.display = show ? "" : "none";
        if (show) n++;
      });
      var cnt = g.querySelector(".am-cnt");
      if (cnt) cnt.textContent = q ? n + " of " + all.length : String(all.length);
    });
  }

  /* ---- tab: Scanner ---- */
  function renderAmTabScanner(d, pkg) {
    var rescan = '<button class="btn p" data-rescan="1" title="Re-read every classes*.dex of the APK over adb and match again (scan?refresh=1)">Rescan</button>';
    if (d.error) return '<div class="am-actions">' + rescan + "</div>" + amManifestErr(d, "scan");
    var trk = d.trackers || [], libs = d.libraries || [], nat = d.native_libs || [];
    var tile = function (k, v) { return '<div class="am-tile"><div class="k">' + k + '</div><div class="v">' + v + "</div></div>"; };
    var tiles = '<div class="am-tiles">' + tile("trackers found", trk.length) + tile("libraries", libs.length) +
      tile("dex files", d.dex_files == null ? "—" : esc(d.dex_files)) +
      tile("classes scanned", d.classes_scanned == null ? "—" : esc(Number(d.classes_scanned).toLocaleString())) +
      tile("apk size", d.apk_size != null ? fmtBytes(d.apk_size) : "—") + "</div>";
    var head = '<div class="am-actions">' + rescan +
      (trk.length ? amBtn("block-trackers", pkg, "Block all trackers", "danger", null, "IFW rule + pm disable on every tracker component below (root)") +
        amBtn("unblock-trackers", pkg, "Unblock", "", null, "remove those IFW rules and re-enable the tracker components (root)") : "") +
      '<span class="hint">' + (d.scanned_at ? "scanned " + esc(d.scanned_at) : "") + (d.cached ? " · cached" : " · fresh") +
      (d.demo ? " · demo data" : "") + "</span></div>";
    var cards = trk.map(function (t) {
      var comps = t.components || [], sigs = t.signatures_matched || [];
      return '<div class="am-trk"><div class="am-trk-h"><b>' + esc(t.name) + "</b>" +
        (t.category ? '<span class="pill crit">' + esc(t.category) + "</span>" : "") +
        '<span class="pill mut">' + esc(t.classes || 0) + " classes</span>" +
        (t.website ? '<a href="' + esc(t.website) + '" target="_blank" rel="noopener">' +
          esc(t.website.replace(/^https?:\/\//, "").replace(/\/$/, "")) + "</a>" : "") + "</div>" +
        (sigs.length ? '<div class="am-trk-s">' + sigs.map(function (s) { return '<span class="perm">' + esc(s) + "</span>"; }).join("") + "</div>" : "") +
        (comps.length ? '<div class="am-trk-c">' + comps.map(function (c) {
          var comp = pkg + "/" + c;
          return '<div class="am-trk-cr"><span class="cn" title="' + esc(c) + '">' + esc(amShortCls(c, pkg)) + "</span>" +
            amBtn("ifw-block", pkg, "Block", "danger", { component: comp }, "intent-firewall rule for " + comp + " + pm disable (root)") +
            amBtn("ifw-unblock", pkg, "Unblock", "", { component: comp }, "remove the IFW rule for " + comp + " and re-enable it (root)") + "</div>";
        }).join("") + "</div>" : '<div class="hint">code only - no manifest component carries this prefix</div>') + "</div>";
    }).join("");
    var libh = libs.map(function (l) {
      return '<div class="am-lib"><span>' + esc(l.name) + "</span>" +
        (l.website ? '<a href="' + esc(l.website) + '" target="_blank" rel="noopener">site</a>' : "") +
        '<span class="pill mut">' + esc(l.classes || 0) + " classes</span></div>";
    }).join("");
    var nath = nat.map(function (n) {
      return '<div class="am-lib"><span class="pill info">' + esc(n.abi) + '</span><span class="mono" style="font-size:11.5px;word-break:break-all">' +
        esc((n.files || []).join(", ")) + "</span></div>";
    }).join("");
    return head + tiles +
      amSec("Trackers", cards || '<div class="hint">no tracker signatures matched in the dex files</div>') +
      amSec("Libraries", libh || '<div class="hint">no known library prefixes matched</div>') +
      amSec("Native libraries", nath || '<div class="hint">no .so files in the APK</div>') +
      '<div class="hint" style="padding:0 15px 12px;font-family:var(--ff-mono);font-size:11px;color:var(--fg-mut)">' +
      "The scan reads only the classes*.dex entries, each by byte range over adb (never the whole APK), and matches the " +
      "class names against the built-in tracker and library prefixes. Nothing leaves this computer.</div>";
  }
  function amRescan(pkg) {
    var body = $("#am-dbody");
    body.innerHTML = '<div class="empty">scanning the dex files of ' + esc(pkg) + " over adb …</div>";
    amGet(amAppUrl(pkg, "/scan?refresh=1")).then(function (d) {
      amTabCache[amCacheKey(pkg, amScanUrl(pkg))] = d;  // the tab reads the refresh=0 key
      if (amSel === pkg && amTab === "scanner") amShowTab("scanner");
      toast(d.error ? "Scan failed: " + d.error : "Scanned " + shortApp(pkg) + ": " + (d.trackers || []).length + " trackers", d.error ? "warn" : "good");
    }).catch(function (err) {
      if (amSel === pkg && amTab === "scanner") body.innerHTML = '<div class="empty">scan failed: ' + esc(err.message) +
        '<br><button class="btn" data-retry="1" style="margin-top:8px">retry</button></div>';
    });
  }

  /* ---- tab: Manifest ---- */
  var amMfQ = "", amMfTimer = null;
  function renderAmTabManifest(d, pkg) {
    if (d.error) return amManifestErr(d, "manifest");
    var xml = d.manifest_xml || "", n = function (v) { return v == null ? "?" : esc(v); };
    var facts = '<div class="am-state">' +
      '<span class="pill mut">' + n(d.version_name) + " (" + n(d.version_code) + ")</span>" +
      '<span class="pill mut">sdk ' + n(d.min_sdk) + " → " + n(d.target_sdk) + (d.max_sdk != null ? " (max " + esc(d.max_sdk) + ")" : "") + "</span>" +
      (d.debuggable ? '<span class="pill crit" title="android:debuggable=true: run-as and a debugger work on this app">debuggable</span>' : "") +
      (d.allow_backup ? '<span class="pill warn" title="android:allowBackup=true">backup allowed</span>' : "") +
      (d.test_only ? '<span class="pill warn">test only</span>' : "") +
      (d.uses_cleartext_traffic ? '<span class="pill warn" title="usesCleartextTraffic=true: plain HTTP allowed">cleartext</span>' : "") +
      (d.large_heap ? '<span class="pill mut">large heap</span>' : "") + (d.multidex ? '<span class="pill mut">multidex</span>' : "") +
      (d.main_activity ? '<span class="pill mut" title="' + esc(d.main_activity) + '">main ' + esc(amShortCls(d.main_activity, pkg)) + "</span>" : "") +
      (d.cached ? '<span class="pill mut">cached</span>' : "") + (d.demo ? '<span class="pill warn">demo data</span>' : "") + "</div>";
    var tools = '<div class="am-tabtools"><input type="search" id="am-mf-q" placeholder="search the manifest…" value="' + esc(amMfQ) +
      '" autocomplete="off"><span class="hint" id="am-mf-n"></span>' +
      '<button class="btn" data-mfcopy="1" title="copy the decoded XML to the clipboard">Copy</button>' +
      '<button class="btn" data-mfdl="1" title="save the decoded XML as a file">Download</button></div>';
    var meta = d.meta_data || {}, mk = Object.keys(meta);
    var extra = '<dl class="kv2" style="padding:0">' +
      amKv("apk", d.apk_path ? d.apk_path + (d.apk_size != null ? " (" + fmtBytes(d.apk_size) + ")" : "") : null) +
      amKv("dex files", (d.dex_files || []).join(", ") || null) +
      amKv("splits", (d.splits || []).map(function (s) { return s.path.split("/").pop() + " " + fmtBytes(s.size); }).join(", ") || null) +
      amKv("features", (d.features || []).map(function (f) { return f.name + (f.required ? "" : " (optional)"); }).join(", ") || null) +
      amKv("libraries", (d.libraries || []).map(function (f) { return f.name + (f.required ? "" : " (optional)"); }).join(", ") || null) +
      amKv("declared permissions", (d.declared_permissions || []).map(function (p) { return p.name + (p.protection_level ? " [" + p.protection_level + "]" : ""); }).join(", ") || null) +
      amKv("uses-permission", (d.uses_permissions || []).length ? (d.uses_permissions || []).length + " (see the Permissions tab)" : null) +
      "</dl>" + (mk.length ? '<dl class="kv2" style="padding:8px 0 0">' + mk.slice(0, 60).map(function (k) { return amKv(k, String(meta[k])); }).join("") + "</dl>" : "");
    return facts + tools +
      (xml ? '<pre class="am-xml" id="am-xml">' + amHiXml(xml, amMfQ) + "</pre>" : '<div class="empty">no decoded manifest in the payload</div>') +
      amSec("From the manifest", extra);
  }
  function afterAmTabManifest() { if (amMfQ) amManifestSearch(); }
  // light XML colouring; every text piece still goes through esc(), q wraps matches in <mark>
  function amHiXml(xml, q) {
    var ql = (q || "").toLowerCase();
    var hi = function (s) {
      if (!ql) return esc(s);
      var out = "", lo = s.toLowerCase(), i = 0, j;
      while ((j = lo.indexOf(ql, i)) >= 0) { out += esc(s.slice(i, j)) + "<mark>" + esc(s.slice(j, j + ql.length)) + "</mark>"; i = j + ql.length; }
      return out + esc(s.slice(i));
    };
    var out = "", re = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<\/?[^>]*>|[^<]+/g, m;
    while ((m = re.exec(xml))) {
      var t = m[0];
      if (t.charAt(0) !== "<") { out += hi(t); continue; }
      if (t.indexOf("<!--") === 0 || t.indexOf("<?") === 0) { out += '<span class="xc">' + hi(t) + "</span>"; continue; }
      var tm = /^(<\/?)([^\s\/>]+)([\s\S]*?)(\/?>)$/.exec(t);
      if (!tm) { out += hi(t); continue; }
      out += esc(tm[1]) + '<span class="xt">' + hi(tm[2]) + "</span>";
      var ar = /([^\s=]+)(\s*=\s*)("[^"]*"|'[^']*')|\s+|\S+/g, am;
      while ((am = ar.exec(tm[3]))) {
        if (am[1]) out += '<span class="xa">' + hi(am[1]) + "</span>" + esc(am[2]) + '<span class="xv">' + hi(am[3]) + "</span>";
        else out += hi(am[0]);
      }
      out += esc(tm[4]);
    }
    return out;
  }
  function amMfXml() { var m = amSel ? amManifestOf(amSel) : null; return (m && m.manifest_xml) || ""; }
  function amManifestSearch() {
    var inp = $("#am-mf-q"), pre = $("#am-xml"), lbl = $("#am-mf-n");
    if (!inp || !pre) return;
    amMfQ = inp.value.trim();
    var xml = amMfXml(), cnt = 0;
    pre.innerHTML = amHiXml(xml, amMfQ);
    if (amMfQ) { var lo = xml.toLowerCase(), ql = amMfQ.toLowerCase(), i = 0, j; while ((j = lo.indexOf(ql, i)) >= 0) { cnt++; i = j + ql.length; } }
    if (lbl) lbl.textContent = amMfQ ? cnt + " match" + (cnt === 1 ? "" : "es") : "";
    var first = pre.querySelector("mark");
    if (first) pre.scrollTop = Math.max(0, first.offsetTop - 60);  // the pre is the offsetParent
  }
  function amMfDebounce() {  // a big manifest is re-coloured per keystroke; let typing settle first
    if (amMfTimer) clearTimeout(amMfTimer);
    amMfTimer = setTimeout(function () { amMfTimer = null; amManifestSearch(); }, 120);
  }
  function amCopy(text, what) {
    var done = function () { toast("Copied " + what, "good"); };
    var fallback = function () {
      try {
        var ta = document.createElement("textarea");
        ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta); ta.select();
        var ok = document.execCommand("copy");
        ta.remove();
        if (ok) done(); else toast("copy failed", "warn");
      } catch (e) { toast("copy failed", "warn"); }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  }
  function amDownload(text, name, mime) {
    var url = URL.createObjectURL(new Blob([text], { type: mime || "text/plain" }));
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  /* ---- tab: Signatures ---- */
  function amNormHash(s) { return String(s || "").toLowerCase().replace(/[^0-9a-f]/g, ""); }
  function renderAmTabSignatures(d, pkg) {
    if (d.error) return amManifestErr(d, "signatures");
    var sigs = d.signatures || [], detail = amDetailOf(pkg), det = (detail || {}).detail || {};
    // one card per certificate: the same cert signed under several schemes shows once, with scheme pills
    var cards = [], byKey = {};
    sigs.forEach(function (s) {
      var k = amNormHash(s.sha256) || amNormHash(s.sha1) || ("#" + cards.length);
      if (!byKey[k]) { byKey[k] = { schemes: [] }; cards.push(byKey[k]); }
      var c = byKey[k];
      if (s.scheme && c.schemes.indexOf(s.scheme) < 0) c.schemes.push(s.scheme);
      ["subject", "issuer", "serial", "not_before", "not_after", "sha256", "sha1", "md5", "algorithm"].forEach(function (f) { if (!c[f] && s[f]) c[f] = s[f]; });
    });
    var dsig = amNormHash(det.sig), now = new Date(), dumpHit = null;
    var covers = function (h) { var x = amNormHash(h); return !!(x && dsig && (x.indexOf(dsig) === 0 || dsig.indexOf(x) === 0)); };
    var hashRow = function (label, v) {
      return v ? "<dt>" + label + '</dt><dd><span class="am-hash" data-copy="' + esc(v) + '" title="click to copy">' + esc(v) + "</span></dd>" : "";
    };
    var html = cards.map(function (c, i) {
      var exp = c.not_after && !isNaN(Date.parse(c.not_after)) && new Date(c.not_after) < now;
      var dm = [c.sha256, c.sha1, c.md5].some(covers);
      if (dm && dumpHit == null) dumpHit = i + 1;
      return '<div class="am-sig"><div class="am-sig-h"><b>certificate ' + (i + 1) + "</b>" +
        c.schemes.map(function (s) { return '<span class="pill info">' + esc(s) + "</span>"; }).join("") +
        (c.algorithm ? '<span class="pill mut">' + esc(c.algorithm) + "</span>" : "") +
        (exp ? '<span class="pill warn">expired</span>' : "") +
        (dm ? '<span class="pill good" title="dumpsys package reports this digest">matches dumpsys</span>' : "") + "</div>" +
        '<dl class="kv2" style="padding:6px 0 0">' + amKv("subject", c.subject) + amKv("issuer", c.issuer) + amKv("serial", c.serial) +
        amKv("valid", (c.not_before || "?") + " → " + (c.not_after || "?")) +
        hashRow("sha256", c.sha256) + hashRow("sha1", c.sha1) + hashRow("md5", c.md5) + "</dl></div>";
    }).join("");
    var dump = !detail ? '<span class="hint">loading the dumpsys signature…</span>' :
      !det.sig ? '<span class="hint">dumpsys package reports no signature digest</span>' :
      '<span class="am-hash" data-copy="' + esc(det.sig) + '" title="click to copy">' + esc(det.sig) + "</span> " +
      (dumpHit ? '<span class="pill good">same as certificate ' + dumpHit + "</span>" :
        '<span class="pill warn" title="dumpsys prints a digest prefix; it should start one of the digests above">not among the APK certificates</span>');
    var verify = '<div class="am-tabtools"><input type="text" id="am-sig-in" placeholder="paste a SHA-256 / SHA-1 / MD5 to verify (colons, spaces and case ignored)" autocomplete="off" spellcheck="false">' +
      '<button class="btn" data-sigpaste="1" title="read the clipboard into the box">Paste</button>' +
      '<button class="btn p" data-sigverify="1" title="compare with every digest above and the dumpsys one">Verify</button></div>' +
      '<div id="am-sig-res" class="am-sig-res"></div>';
    return '<div class="am-actions"><span class="hint">' + sigs.length + " signature" + (sigs.length === 1 ? "" : "s") + " · " + cards.length +
      " certificate" + (cards.length === 1 ? "" : "s") + (d.cached ? " · cached" : "") + (d.demo ? " · demo data" : "") + "</span></div>" +
      amSec("APK signing certificates", html || '<div class="hint">no signature block read from the APK</div>') +
      amSec("dumpsys package signature", dump) +
      amSec("Verify a hash", verify + '<div class="hint">Compare a digest from the developer, a store listing or another device of yours.</div>');
  }
  function afterAmTabSignatures(d, pkg) { amWithDetail(pkg, "signatures"); }
  function amSigVerify() {
    var inp = $("#am-sig-in"), res = $("#am-sig-res");
    if (!inp || !res) return;
    var q = amNormHash(inp.value), hit = null, n = 0;
    if (!q) { res.innerHTML = ""; return; }
    var m = amSel ? amManifestOf(amSel) : null;
    ((m && m.signatures) || []).forEach(function (s) {
      ["sha256", "sha1", "md5"].forEach(function (k) {
        if (!s[k]) return;
        n++;
        if (!hit && amNormHash(s[k]) === q) hit = (s.scheme ? s.scheme + " " : "") + k;
      });
    });
    var ds = amNormHash(((amDetailOf(amSel) || {}).detail || {}).sig);
    if (ds) { n++; if (!hit && q === ds) hit = "dumpsys sig"; }
    res.innerHTML = hit ? '<span class="pill good">match · ' + esc(hit) + "</span>" :
      '<span class="pill crit">no match</span><span class="hint">' + q.length + " hex chars compared with " + n + " digest" + (n === 1 ? "" : "s") + "</span>";
  }
  function amSigPaste() {
    var inp = $("#am-sig-in");
    if (!inp) return;
    if (!(navigator.clipboard && navigator.clipboard.readText)) { toast("clipboard reading is not available here - paste with Ctrl+V", "warn"); inp.focus(); return; }
    navigator.clipboard.readText().then(function (t) { inp.value = t || ""; amSigVerify(); })
      .catch(function () { toast("clipboard not readable - paste with Ctrl+V", "warn"); inp.focus(); });
  }

  /* ---- tab: Prefs & DBs ---- */
  var amPrefSel = {}, amDbSel = {};  // per package: the open prefs file / {file, table, limit}, kept across reloads
  var PREF_KEY_RE = /^[A-Za-z0-9_.:\-]{1,200}$/, PREF_TYPES = ["string", "int", "long", "float", "boolean", "set"];
  function amRootHint(msg) {
    var r = amRoot || {};
    return '<div class="hint am-roothint">' + esc(msg) +
      (r.root && r.use_su ? "" : " · shared_prefs and databases live under /data/data, which needs su (Devices tab: Request su, Use root for actions)") + "</div>";
  }
  function renderAmTabPrefs(d, pkg) {
    var files = d.files || [];
    var left = (d.error ? amRootHint(d.error) : "") + (files.length ? files.map(function (f) {
      return '<div class="am-pfile" data-pfile="' + esc(f.name) + '" title="open ' + esc(f.name) + '"><span class="fn">' + esc(f.name) +
        '</span><span class="fsz">' + (f.entries != null ? esc(f.entries) + " keys · " : "") + fmtBytes(f.size) + "</span></div>";
    }).join("") : (d.error ? "" : '<div class="hint">no shared_prefs files</div>'));
    return '<div class="am-pdb"><div class="am-pdb-col">' +
      amSec('Shared preferences <span class="pill warn" style="text-transform:none;letter-spacing:0" title="prefs-set / prefs-delete rewrite the XML through su, then chown + restorecon">writes need root</span>',
        left + '<div id="am-pref-view"></div>') + "</div>" +
      '<div class="am-pdb-col">' + amSec('Databases <span class="pill mut" style="text-transform:none;letter-spacing:0">read-only</span>',
        '<div id="am-db-list"><div class="hint">loading…</div></div><div id="am-db-view"></div>') + "</div></div>" +
      '<div class="hint" style="padding:0 15px 12px;font-family:var(--ff-mono);font-size:11px;color:var(--fg-mut)">' +
      "Prefs are read with cat through su; a Save rewrites the file and fixes its owner and SELinux label. Databases are pulled " +
      "(with -wal/-shm) and opened read-only on this computer; the app is never touched.</div>";
  }
  function afterAmTabPrefs(d, pkg, force) {
    amLoadDbList(pkg, force);
    var f = amPrefSel[pkg];
    if (f && (d.files || []).some(function (x) { return x.name === f; })) amLoadPrefFile(pkg, f, force);
  }
  function amLoadPrefFile(pkg, file, force) {
    if (!pkg || !file) return;
    amPrefSel[pkg] = file;
    $$("#am-dbody .am-pfile[data-pfile]").forEach(function (r) { r.classList.toggle("sel", r.dataset.pfile === file); });
    var box = $("#am-pref-view");
    if (!box) return;
    box.innerHTML = '<div class="hint">reading ' + esc(file) + "…</div>";
    amTabLoad(pkg, amUserUrl(pkg, "/prefs/" + encodeURIComponent(file)), force).then(function (p) {
      var b = $("#am-pref-view");
      if (b && amSel === pkg && amTab === "prefs") b.innerHTML = renderAmPrefFile(p, pkg, file);
    }).catch(function (err) {
      var b = $("#am-pref-view");
      if (b && amSel === pkg) b.innerHTML = amRootHint(err.message);
    });
  }
  function amPrefRaw(e) {  // the value as editor text: sets one item per line
    if (e.type === "set" && Array.isArray(e.value)) return e.value.join("\n");
    return String(e.value == null ? "" : e.value);
  }
  function renderAmPrefFile(p, pkg, file) {
    var ents = p.entries || [];
    var rows = ents.map(function (e) {
      var raw = amPrefRaw(e), show = e.type === "set" && Array.isArray(e.value) ? "{" + e.value.join(", ") + "}" : raw;
      var cls = e.type === "boolean" ? "info" : e.type === "string" ? "mut" : e.type === "set" ? "warn" : "good";
      return '<div class="am-pref" data-pkey="' + esc(e.key) + '" data-ptype="' + esc(e.type) + '" data-pval="' + esc(raw) + '">' +
        '<span class="pk" title="' + esc(e.key) + '">' + esc(e.key) + '</span><span class="pill ' + cls + '">' + esc(e.type) + "</span>" +
        '<span class="pv" title="' + esc(show.slice(0, 1000)) + '">' + esc(show.length > 120 ? show.slice(0, 120) + "…" : show) + "</span>" +
        '<span class="pa"><button class="btn" data-pedit="1" title="edit the value in place; Save runs prefs-set through su">Edit</button>' +
        amBtn("prefs-delete", pkg, "Delete", "danger", { file: file, key: e.key }, "prefs-delete: remove this key from " + file + " (root)") + "</span></div>";
    }).join("");
    var add = '<div class="am-pref am-pref-add"><input type="text" id="am-padd-key" placeholder="new key" autocomplete="off" spellcheck="false">' +
      '<select id="am-padd-type" title="value type">' + PREF_TYPES.map(function (t) { return '<option value="' + t + '">' + t + "</option>"; }).join("") + "</select>" +
      '<input type="text" id="am-padd-val" placeholder="value (set: JSON list or a,b,c)" autocomplete="off" spellcheck="false">' +
      '<button class="btn p" data-padd="1" title="prefs-set: add or overwrite this key in ' + esc(file) + ' (root)">Add key</button></div>';
    return '<div class="am-pref-h"><b>' + esc(file) + '</b><span class="hint">' + ents.length + " key" + (ents.length === 1 ? "" : "s") + "</span></div>" +
      (rows || '<div class="hint">no entries</div>') + add;
  }
  function amPrefEdit(row) {
    if (!row || row.querySelector(".am-pedit")) return;
    var type = row.dataset.ptype, raw = row.dataset.pval, pv = row.querySelector(".pv"), pa = row.querySelector(".pa"), ed;
    if (type === "boolean") ed = '<select class="am-pedit"><option value="true"' + (raw === "true" ? " selected" : "") + '>true</option>' +
      '<option value="false"' + (raw !== "true" ? " selected" : "") + ">false</option></select>";
    else if (type === "int" || type === "long") ed = '<input class="am-pedit" type="number" step="1" value="' + esc(raw) + '">';
    else if (type === "float") ed = '<input class="am-pedit" type="number" step="any" value="' + esc(raw) + '">';
    else if (type === "set") ed = '<textarea class="am-pedit" rows="3" placeholder="one item per line">' + esc(raw) + "</textarea>";
    else ed = '<input class="am-pedit" type="text" value="' + esc(raw) + '">';
    pv.innerHTML = ed;
    pv.removeAttribute("title");
    pa.innerHTML = '<button class="btn p" data-psave="1" title="prefs-set through su (asks first)">Save</button><button class="btn" data-pcancel="1">Cancel</button>';
    var el = row.querySelector(".am-pedit");
    if (el && el.focus) el.focus();
  }
  function amPrefValue(type, s) {  // editor text -> the JSON value the backend coerces per type
    s = s == null ? "" : String(s);
    if (type === "boolean") return s.trim() === "true";
    if (type === "int" || type === "long") { var n = parseInt(s, 10); return isNaN(n) || String(n) !== s.trim() ? s : n; }
    if (type === "float") { var f = parseFloat(s); return isNaN(f) ? s : f; }
    if (type === "set") {
      var t = s.trim();
      if (t.charAt(0) === "[") { try { var arr = JSON.parse(t); if (Array.isArray(arr)) return arr.map(String); } catch (e) { /* not JSON: lines */ } }
      return t.split(t.indexOf("\n") >= 0 ? "\n" : ",").map(function (x) { return x.trim(); }).filter(Boolean);
    }
    return s;
  }
  function amPrefSave(row, pkg) {
    var ed = row && row.querySelector(".am-pedit"), file = amPrefSel[pkg];
    if (!ed || !file) return;
    amAction("prefs-set", { package: pkg, file: file, key: row.dataset.pkey, type: row.dataset.ptype, value: amPrefValue(row.dataset.ptype, ed.value) });
  }
  function amPrefAdd(pkg) {
    var key = ($("#am-padd-key") || {}).value || "", type = ($("#am-padd-type") || {}).value || "string", val = ($("#am-padd-val") || {}).value || "";
    var file = amPrefSel[pkg];
    key = key.trim();
    if (!file) return;
    if (!PREF_KEY_RE.test(key)) { toast("key: letters, digits, _ . : - only (max 200)", "warn"); return; }
    if ((type === "int" || type === "long") && !/^-?\d+$/.test(val.trim())) { toast("value must be an integer", "warn"); return; }
    if (type === "float" && isNaN(parseFloat(val))) { toast("value must be a number", "warn"); return; }
    amAction("prefs-set", { package: pkg, file: file, key: key, type: type, value: amPrefValue(type, val) });
  }
  function amLoadDbList(pkg, force) {
    amTabLoad(pkg, amAppUrl(pkg, "/db"), force).then(function (d) {
      var box = $("#am-db-list");
      if (!box || amSel !== pkg || amTab !== "prefs") return;
      var files = d.files || [];
      box.innerHTML = (d.error ? amRootHint(d.error) : "") + (files.length ? files.map(function (f) {
        return '<div class="am-pfile" data-dbfile="' + esc(f.name) + '" title="list the tables of ' + esc(f.name) + '"><span class="fn">' + esc(f.name) +
          '</span><span class="fsz">' + fmtBytes(f.size) + "</span></div>";
      }).join("") : (d.error ? "" : '<div class="hint">no databases</div>'));
      var s = amDbSel[pkg];
      if (s && files.some(function (f) { return f.name === s.file; })) amLoadDb(pkg, s.file, s.table, s.limit, force);
    }).catch(function (err) {
      var box = $("#am-db-list");
      if (box && amSel === pkg) box.innerHTML = amRootHint(err.message);
    });
  }
  function amLoadDb(pkg, file, table, limit, force) {
    if (!pkg || !file) return;
    limit = limit || (amDbSel[pkg] || {}).limit || 200;
    amDbSel[pkg] = { file: file, table: table || null, limit: limit };
    $$("#am-dbody .am-pfile[data-dbfile]").forEach(function (r) { r.classList.toggle("sel", r.dataset.dbfile === file); });
    var box = $("#am-db-view");
    if (!box) return;
    box.innerHTML = '<div class="hint">pulling ' + esc(file) + (table ? " · " + esc(table) : "") + "…</div>";
    var url = amAppUrl(pkg, "/db/" + encodeURIComponent(file) + "?limit=" + limit + (table ? "&table=" + encodeURIComponent(table) : ""));
    amTabLoad(pkg, url, force).then(function (d) {
      var b = $("#am-db-view");
      if (b && amSel === pkg && amTab === "prefs") b.innerHTML = renderAmDb(d, pkg, file);
    }).catch(function (err) {
      var b = $("#am-db-view");
      if (b && amSel === pkg) b.innerHTML = amRootHint(err.message);
    });
  }
  function renderAmDb(d, pkg, file) {
    var tables = d.tables || [], cols = d.columns || [], rows = d.rows || [], sel = amDbSel[pkg] || {};
    var chips = tables.map(function (t) {
      return '<span class="pill ' + (t.name === d.table ? "good" : "mut") + ' link" data-dbtable="' + esc(t.name) +
        '" title="show the first rows of ' + esc(t.name) + '">' + esc(t.name) + " · " + (t.rows == null ? "?" : esc(t.rows)) + "</span>";
    }).join("");
    var grid = "";
    if (d.table) {
      grid = '<div class="am-gridwrap"><table class="am-grid"><thead><tr>' + cols.map(function (c) { return "<th>" + esc(c) + "</th>"; }).join("") +
        "</tr></thead><tbody>" + rows.map(function (r) {
          return "<tr>" + (r || []).map(function (v) {
            if (v == null) return '<td><span class="null">NULL</span></td>';
            var s = typeof v === "object" ? JSON.stringify(v) : String(v);
            return "<td" + (s.length > 60 ? ' title="' + esc(s.slice(0, 1000)) + '"' : "") + ">" + esc(s.length > 60 ? s.slice(0, 60) + "…" : s) + "</td>";
          }).join("") + "</tr>";
        }).join("") + "</tbody></table></div>" +
        '<div class="hint" style="margin-top:4px">' + rows.length + " row" + (rows.length === 1 ? "" : "s") + " · " + cols.length + " columns" +
        (d.truncated ? " · truncated at the limit - raise it or query on the device" : "") + "</div>";
    }
    return '<div class="am-pref-h"><b>' + esc(file) + '</b><span class="pill mut">read-only</span>' +
      '<select id="am-db-limit" title="rows to fetch per table">' + [50, 200, 1000].map(function (n) {
        return '<option value="' + n + '"' + (n === (sel.limit || 200) ? " selected" : "") + ">" + n + " rows</option>";
      }).join("") + "</select></div>" +
      '<div class="am-dbtables">' + (chips || '<span class="hint">no tables</span>') + "</div>" +
      (d.table ? grid : (tables.length ? '<div class="hint">click a table</div>' : ""));
  }

  /* ---- Overview: processes block (detail.running + names from /running) ---- */
  function renderAmProcs(run, pkg) {
    var pids = (run && run.pids) || [];
    if (!pids.length) return '<div class="hint">no process right now</div>';
    return pids.map(function (pid) {
      var p = amProcs[pid] || {};
      return '<div class="am-proc"><span class="mono">' + esc(pid) + '</span><span class="pn" title="' + esc(p.name || "") + '">' + esc(p.name || "(name unknown)") + "</span>" +
        '<span class="hint">' + (p.rss_kb != null ? fmtBytes(p.rss_kb * 1024) : "") + (p.state ? " · " + esc(p.state) : "") + (p.cputime ? " · cpu " + esc(p.cputime) : "") + "</span>" +
        amBtn("kill", pkg, "Kill", "danger", { pid: pid }, "kill -9 " + pid + " through su; refused unless the pid belongs to this app's uid") + "</div>";
    }).join("") + (run.rss_kb ? '<div class="hint" style="margin-top:4px">resident total ' + fmtBytes(run.rss_kb * 1024) + "</div>" : "");
  }

  /* ---- tab: Storage ---- */
  function renderAmTabStorage(d, pkg) {
    var sizes = d.sizes || {}, sub = d.subdirs || {};
    var sz = function (p) { return p && sizes[p] != null ? '  <span style="color:var(--accent)">' + fmtBytes(sizes[p]) + "</span>" : ""; };
    var dirs = [["data dir", d.data_dir], ["device-encrypted", d.de_dir], ["external", d.external_dir || sub.external],
      ["obb", d.obb_dir], ["media", d.media_dir]];
    ["cache", "code_cache", "databases", "shared_prefs", "files"].forEach(function (k) { if (sub[k]) dirs.push([k, sub[k]]); });
    Object.keys(sub).forEach(function (k) {
      if (["cache", "code_cache", "databases", "shared_prefs", "files", "external"].indexOf(k) < 0) dirs.push([k, sub[k]]);
    });
    var kv = dirs.filter(function (x) { return x[1]; }).map(function (x) {
      return "<dt>" + esc(x[0]) + "</dt><dd>" + esc(x[1]) + sz(x[1]) + "</dd>";
    }).join("");
    var totals = '<div class="am-state">' +
      (d.data_bytes != null ? '<span class="pill">data ' + fmtBytes(d.data_bytes) + "</span>" : "") +
      (d.cache_bytes != null ? '<span class="pill">cache ' + fmtBytes(d.cache_bytes) + "</span>" : "") +
      (d.app_bytes != null ? '<span class="pill">app ' + fmtBytes(d.app_bytes) + "</span>" : "") +
      (d.data_bytes == null && d.cache_bytes == null && d.app_bytes == null && sizes[d.data_dir] != null
        ? '<span class="pill">data dir ' + fmtBytes(sizes[d.data_dir]) + "</span>" : "") +
      (d.demo ? '<span class="pill warn">demo data</span>' : "") + "</div>";
    var actions = '<div class="am-actions">' +
      '<button class="btn p" data-backup2="' + esc(pkg) + '">Extract APK+data</button>' +
      amBtn("save-apk", pkg, "Save APK") +
      (d.data_dir ? '<button class="btn" data-browse="' + esc(d.data_dir) + '" title="Open the Files tab at this directory">Browse data dir</button>' : "") +
      "</div>";
    var apks = (d.apk_paths || []).map(function (p) {
      var s = null;
      (d.splits || []).forEach(function (x) { if (x.path === p) s = x.size; });
      return '<div class="fentry file">' + FILE + '<span class="fn">' + esc(p) + '</span><span class="fsz">' + (s != null ? fmtBytes(s) : "") + "</span></div>";
    }).join("");
    (d.splits || []).forEach(function (x) {
      if ((d.apk_paths || []).indexOf(x.path) >= 0) return;
      apks += '<div class="fentry file">' + FILE + '<span class="fn">' + esc(x.path) + '</span><span class="fsz">' + fmtBytes(x.size) + "</span></div>";
    });
    var ents = (d.entries || []).map(function (e) {
      var ico = e.kind === "dir" ? FOLDER : e.kind === "link" ? LINKI : FILE;
      return '<div class="fentry ' + esc(e.kind || "file") + '"' + (e.kind === "dir" && d.data_dir ? ' data-browse="' + esc(joinPath(d.data_dir, e.name)) + '"' : "") + ">" +
        ico + '<span class="fn">' + esc(e.name) + (e.target ? " -> " + esc(e.target) : "") + "</span>" +
        '<span class="fsz">' + esc(e.perms || "") + (e.kind === "file" && e.size != null ? " · " + fmtBytes(e.size) : "") + "</span></div>";
    }).join("");
    var logs = (d.log_files || []).slice(0, 60).map(function (f) {
      return '<div class="fentry file">' + FILE + '<span class="fn">' + esc(f) + "</span></div>";
    }).join("");
    return totals + actions +
      amSec("Directories", '<dl class="kv2" style="padding:0">' + (kv || "<dt>data dir</dt><dd>unknown</dd>") + "</dl>") +
      amSec("APK files", apks || '<div class="hint">no APK paths reported</div>') +
      amSec("Top-level entries (" + (d.entries || []).length + ")", ents ? '<div style="margin:0 -15px">' + ents + "</div>" : '<div class="hint">nothing listed (needs root)</div>') +
      amSec("Log-like files (" + (d.log_files || []).length + ")", logs ? '<div style="margin:0 -15px">' + logs + "</div>" : '<div class="hint">none found</div>') +
      amSec("Backups of this app on this computer", renderAmBackupRows(d.backups || [], pkg));
  }

  /* ---- tab: Backups ---- */
  function renderAmBackupRows(list, pkg) {
    if (!list.length) return '<div class="hint">no backups of ' + esc(shortApp(pkg)) + ' yet - press "Extract APK+data"</div>';
    return list.map(function (b) {
      var comps = b.components || [], hasApk = comps.indexOf("apk") >= 0, hasData = comps.indexOf("data") >= 0;
      return '<div class="am-bk" style="padding:8px 0;border-bottom:1px solid var(--border-soft)">' +
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;font-size:12.5px"><b>' + esc(b.name) + "</b>" +
        '<span class="pill mut">' + esc(comps.join("+") || "empty") + '</span><span class="fsz">' + fmtBytes(b.bytes) + "</span>" +
        '<span class="hint">' + esc(b.captured || "") + "</span></div>" +
        '<div class="mono" style="font-size:10.5px;color:var(--fg-mut);word-break:break-all;margin:3px 0 6px">' + esc(b.path) + "</div>" +
        '<div class="am-bulk-row" style="padding:0">' +
        '<label class="am-cklabel"><input type="checkbox" data-ropt="apk"' + (hasApk ? " checked" : " disabled") + "> APK</label>" +
        '<label class="am-cklabel"><input type="checkbox" data-ropt="data"' + (hasData ? " checked" : " disabled") + "> data (over the current data)</label>" +
        '<button class="btn danger" data-restore="' + esc(b.name) + '" data-pkg="' + esc(pkg) + '">Restore</button></div></div>';
    }).join("");
  }
  function renderAmTabBackups(d, pkg) {
    var list = (Array.isArray(d) ? d : (d.backups || [])).filter(function (b) { return b.package === pkg; });
    return '<div class="am-actions"><button class="btn p" data-backup2="' + esc(pkg) + '">Extract APK+data now</button>' +
      '<span class="hint">' + list.length + " backup" + (list.length === 1 ? "" : "s") + " of this app on this computer</span></div>" +
      amSec("Backups", renderAmBackupRows(list, pkg)) +
      '<div class="hint" style="padding:0 15px 12px;font-family:var(--ff-mono);font-size:11px;color:var(--fg-mut)">' +
      "Restore reinstalls the saved APKs (adb install-multiple -r) and, with data ticked, unpacks data.tar over " +
      "/data/data/&lt;pkg&gt; through su, then fixes ownership and SELinux labels. Progress shows in the Live feed.</div>";
  }

  /* ---- tab: History ---- */
  function renderAmTabHistory(d, pkg) {
    var evs = (d.events || []).filter(function (e) { return amHistAll || e.package === pkg; });
    var rows = evs.map(function (e) {
      return '<div class="am-hist"><span class="ts">' + esc(fmtDateTime(e.ts)) + "</span>" +
        '<span class="pill ' + (e.ok ? "good" : "crit") + '">' + esc(e.action) + "</span>" +
        '<span class="mono" style="font-size:11.5px;word-break:break-all">' + esc(e.package) + (e.user != null ? ' <span class="hint">user ' + esc(e.user) + "</span>" : "") + "</span>" +
        (e.output ? '<span class="out">' + esc(String(e.output).slice(0, 300)) + "</span>" : "") + "</div>";
    }).join("");
    return amSec("Actions " + (amHistAll ? "on every app" : "on this app") +
      ' <span class="am-sellink" data-histall="' + (amHistAll ? "0" : "1") + '" style="margin-left:8px;text-transform:none;letter-spacing:0">' +
      (amHistAll ? "only " + esc(shortApp(pkg)) : "show all") + "</span>",
      rows || '<div class="hint">no recorded actions' + (amHistAll ? "" : " for this app") + " (last 200 app.action events)</div>");
  }

  /* ---- "find anywhere": the search box matched nothing in the loaded list ---- */
  function amFindPrompt(q) {
    return '<div class="am-find" id="am-find">' +
      "<p>No app named &ldquo;" + esc(q) + "&rdquo; for " + esc(amUserLabel()) + " (" + amApps.length +
      (amWhich === "all" ? " packages checked, incl. uninstalled and hidden"
                         : " packages checked in the &ldquo;" + esc(amWhich) + "&rdquo; filter") + ").</p>" +
      '<button class="btn p" id="am-find-btn">Search every user and the file system</button></div>';
  }
  function amFind() {
    var q = ($("#am-search").value || "").trim(), box = $("#am-find");
    if (!q || !box) return;
    box.innerHTML = '<div class="empty">searching every user and the APK folders…</div>';
    fetch(dq("/api/appmanager/find?q=" + encodeURIComponent(q))).then(function (r) { return r.json(); })
      .then(function (f) { renderAmFind(q, f); })
      .catch(function () { if ($("#am-find")) $("#am-find").innerHTML = '<div class="hint">search request failed</div>'; });
  }
  function renderAmFind(q, f) {
    var box = $("#am-find");
    if (!box) return;  // the list was re-rendered while the device was searched
    if (f.error) { box.innerHTML = '<div class="hint">' + esc(f.error) + "</div>"; return; }
    var matches = f.matches || [], dirs = f.apk_dirs || [], browsers = f.browsers || [], users = f.users || [];
    var h = "<p>" + esc(f.scanned || 0) + " distinct packages seen across " + users.length +
      " user" + (users.length === 1 ? "" : "s") + ", incl. uninstalled and hidden.</p>";
    if (matches.length) {
      h += '<div class="am-find-rows">' + matches.map(function (m) {
        var inst = (m.users || []).filter(function (u) { return u.installed; });
        return '<div class="am-find-row" data-pkg="' + esc(m.package) + '" data-user="' +
          (inst.length ? esc(inst[0].id) : "") + '" title="open this app">' +
          '<div class="nm">' + esc(m.label || shortApp(m.package)) +
          (m.system ? ' <span class="pill mut">system</span>' : "") +
          '<div class="pk">' + esc(m.package) + "</div></div>" +
          '<div class="us">' + (m.users || []).map(function (u) {
            return '<span class="pill ' + (u.installed ? "good" : "crit") + '">user ' + esc(u.id) +
              (u.installed ? " installed" : " not installed") + "</span>";
          }).join(" ") + "</div></div>";
      }).join("") + "</div>";
    }
    if (dirs.length) {
      h += '<p class="k">APK folders on disk matching:</p><div class="pk">' +
        dirs.map(function (p) { return esc(p); }).join("<br>") + "</div>";
    }
    if (browsers.length) {
      h += '<p class="k">Browsers on this device:</p><div class="chips">' + browsers.map(function (b) {
        return '<span class="pill ' + (b.default ? "good" : "mut") + ' am-link" data-pkg="' + esc(b.package) +
          '" title="' + esc(b.component || "") + '">' + esc(b.label || shortApp(b.package)) + " · " +
          esc(b.package) + (b.default ? " · default" : "") + "</span>";
      }).join(" ") + "</div>";
    }
    if (!matches.length && !dirs.length && !(f.scanned > 0)) {
      // pm answered nothing at all: say so instead of declaring the app absent
      h += '<p class="verdict">The device returned no packages, so nothing could be checked - ' +
        "it is probably unauthorized or offline. Check the Devices &amp; ADB tab and try again.</p>";
    } else if (!matches.length && !dirs.length) {
      h += '<p class="verdict">Nothing named &ldquo;' + esc(q) + "&rdquo; exists on this device for any user. " +
        "It simply is not installed on this ROM (custom ROMs often ship without Chrome or Google Photos, " +
        "for example) and a different app is filling the role - see the browsers above. " +
        "Install it from the Play Store or sideload an APK with the Install APK button.</p>";
    }
    box.innerHTML = h;
  }
  // a hit for another user: switch the picker there, drop filters that could hide it, reload, then open it
  function amOpenFound(pkg, user) {
    if (user !== "" && amUser !== "all" && parseInt(user, 10) !== amUser) {
      amUser = parseInt(user, 10);
      $("#am-user").value = String(amUser);
    }
    if (amWhich !== "all" || amLocal) amResetFilter();
    $("#am-search").value = "";
    amPending = pkg;
    loadAppManager();
  }

  /* ---- "Defaults on this device": fills the detail pane while no app is selected ---- */
  function loadAmDefaults() {
    var key = (DEV || "default") + ":" + (typeof amUser === "number" ? amUser : 0);
    if (amHandlers && amHandlersKey === key) { renderAmDefaults(amHandlers); return; }
    fetch(dq("/api/appmanager/handlers" + (typeof amUser === "number" ? "?user=" + amUser : "")))
      .then(function (r) { return r.json(); })
      .then(function (h) {
        amHandlers = h; amHandlersKey = key;
        if (!amSel) renderAmDefaults(h);
      }).catch(function () { /* the pick-an-app placeholder stays */ });
  }
  // label, role name in roles{}, intent name in handlers{} (fallback when no role holder is set)
  var AM_ROLES = [["Browser", "browser", "browser"], ["Launcher", "home", "launcher"], ["SMS", "sms", "sms"],
                  ["Phone", "dialer", "dialer"], ["Assistant", "assistant", null]];
  function amLink(pkg) {
    return '<span class="am-link" data-pkg="' + esc(pkg) + '">' + esc((amRows[pkg] || {}).label || shortApp(pkg)) +
      '</span> <span class="pk">' + esc(pkg) + "</span>";
  }
  function renderAmDefaults(h) {
    var roles = h.roles || {}, hs = h.handlers || {};
    var rows = AM_ROLES.map(function (r) {
      var holder = (roles[r[1]] || [])[0] || (r[2] === "browser" ? h.default_browser : null) ||
        ((h.defaults || {})[r[2]] || null);  // system resolution; never "first handler" as if it were the default
      return '<div class="am-def"><span class="k">' + r[0] + '</span><span class="v">' +
        (holder ? amLink(holder) : '<span class="pk">none</span>') + "</span></div>";
    }).join("");
    var browsers = hs.browser || [];
    var chips = browsers.length ? '<div class="am-def"><span class="k">All browsers</span><span class="v chips">' +
      browsers.map(function (b) {
        var def = b.package === h.default_browser;
        return '<span class="pill ' + (def ? "good" : "mut") + ' am-link" data-pkg="' + esc(b.package) +
          '" title="' + esc(b.component || "") + '">' +
          esc((amRows[b.package] || {}).label || b.label || shortApp(b.package)) + " · " + esc(b.package) +
          (def ? " · default" : "") + "</span>";
      }).join(" ") + "</span></div>" : "";
    $("#am-tabs").style.display = "none";
    $("#am-dbody").innerHTML = '<div class="am-sec am-defaults"><h4>Defaults on this device' +
      (h.user != null ? " · user " + esc(h.user) : "") + "</h4>" +
      (h.error ? '<div class="hint">' + esc(h.error) + "</div>" : rows + chips) +
      '<div class="hint">Role holders from the system role manager; click a name to open that app.</div></div>' +
      '<div class="empty">Pick an app on the left to see its permissions, components, app-ops, signature and storage, and to manage it.</div>';
  }

  /* ---------- SSL interception (Intercept tab) ----------
     Wired strictly to /api/intercept/*. GET /status is read-only; every active
     POST carries {device:DEV, confirm:true} and refreshes status after. The
     backend validates+quotes every device-bound string and owns the audit
     event, so this stays a thin UI with clean error / loading states. */
  var icStatus = null;      // last /status payload (or null after a failed load)
  var icPkgsDev = false;    // device whose package datalist is loaded (lazy, per device; false != any real DEV incl. null)

  function loadIntercept() {
    loadInterceptStatus();
    icLoadPkgs();           // fill the per-app target datalist from the app list
    loadEngagement();
    loadFridaCard();
    loadCaptureStatus();
    loadMitmCard();
    loadBuiltinCa();
  }

  /* ===== built-in CA + one-click setup (self-contained, like Reqable) ===== */
  function loadBuiltinCa() {
    getJSON("/api/intercept/ca/builtin").then(function (d) {
      var st = $("#oc-castate");
      if (st) st.textContent = d.exists
        ? ("built-in CA ready · " + (d.subject || "Sentinel Proxy CA"))
        : "no built-in CA yet — Set up or Generate to create one";
    }).catch(function () {});
  }
  (function initOneClick() {
    function on(id, fn) { var e = $("#" + id); if (e) e.addEventListener("click", fn); }
    on("oc-gen", function () {
      if (typeof confirm === "function" &&
          !confirm("Generate a new Sentinel CA? Any previously installed Sentinel CA stops being trusted until you install the new one.")) return;
      postJSON("/api/intercept/ca/builtin/generate", { force: true }).then(function (r) {
        toast("built-in CA generated", "good"); loadBuiltinCa();
        if (r && r.sha256) { var o = $("#oc-out"); if (o) { o.style.display = ""; o.textContent = "CA: " + (r.subject || "") + "\nsha256 " + r.sha256; } }
      }).catch(function () { toast("could not generate CA", "warn"); });
    });
    on("oc-setup", function () {
      if (typeof confirm === "function" &&
          !confirm("Set up interception on this device? This installs Sentinel's CA, starts the proxy, and points the device at it. Only on a device you own.")) return;
      var out = $("#oc-out");
      if (out) { out.style.display = ""; out.textContent = "setting up…"; }
      var host = ($("#oc-host").value || "").trim();
      var port = parseInt($("#oc-port").value, 10) || 8080;
      postJSON("/api/intercept/setup", { device: DEV, host: host || undefined, port: port, confirm: true })
        .then(function (r) {
          if (r.ok === false && r.output) { if (out) out.textContent = r.output; toast(r.output, "warn"); loadInterceptStatus(); return; }
          var lines = (r.steps || []).map(function (s) { return (s.ok ? "✓ " : "✗ ") + s.step + " — " + (s.output || "").split("\n")[0]; });
          lines.unshift("proxy → " + r.host + ":" + r.port);
          if (out) out.textContent = lines.join("\n");
          toast(r.ok ? "interception set up — restart the target app" : "setup finished with issues",
                r.ok ? "good" : "warn",
                r.mitm_installed ? "" : "mitmproxy is not installed here: pip install mitmproxy");
          loadInterceptStatus(); loadMitmCard();
        }).catch(function () { if (out) out.textContent = "request failed"; toast("setup failed", "crit"); });
    });
  })();

  function loadInterceptStatus() {
    var box = $("#ic-status");
    if (box) box.innerHTML = '<div class="empty">loading status…</div>';
    // amGet = getJSON(dq(url)) -> adds ?device=DEV; GET never changes the device
    amGet("/api/intercept/status").then(function (s) {
      icStatus = s || {};
      renderInterceptStatus(icStatus);
    }).catch(function () {
      icStatus = null;
      if (box) box.innerHTML = '<div class="empty">could not load interception status — is a device attached?</div>';
      icReflectProxy({});   // keep the proxy card readable even when status failed
    });
  }

  function icShortDate(iso) {       // cert / expiry timestamps -> YYYY-MM-DD, UTC-stable
    if (!iso) return "—";
    var d = new Date(iso);
    return isNaN(d.getTime()) ? String(iso) : d.toISOString().slice(0, 10);
  }

  function renderInterceptStatus(s) {
    var box = $("#ic-status");
    if (!box) return;
    s = s || {};
    var chips = [];
    if (s.demo) chips.push('<span class="pill mut">demo data</span>');
    chips.push('<span class="pill ' + (s.root ? "good" : "warn") + '">root: ' + (s.root ? "yes" : "no") + "</span>");
    var av = s.android ? ("Android " + esc(s.android)) : "Android ?";
    chips.push('<span class="pill info">' + av + (s.sdk != null ? " · SDK " + esc(s.sdk) : "") + "</span>");

    var ca = s.ca || {};
    if (ca.installed) {
      chips.push('<span class="pill good">CA installed' + (ca.store ? " · " + esc(ca.store) : "") + "</span>");
    } else {
      chips.push('<span class="pill mut">no CA installed</span>');
    }

    var px = s.proxy || {};
    if (px.mode === "global") {
      chips.push('<span class="pill warn">proxy: global ' + esc((px.host || "?") + ":" + (px.port || "?")) + "</span>");
    } else if (px.mode === "per-app") {
      chips.push('<span class="pill warn">proxy: ' + esc(shortApp(px.package)) + " " + esc((px.host || "?") + ":" + (px.port || "?")) + "</span>");
    } else {
      chips.push('<span class="pill mut">proxy off</span>');
    }

    var html = '<div class="ic-chips">' + chips.join(" ") + "</div>";

    // CA detail (subject / sha256 / expiry) only when something is installed
    if (ca.installed) {
      var det = [];
      if (ca.subject) det.push(["Subject", ca.subject]);
      if (ca.sha256) det.push(["SHA-256", ca.sha256]);
      if (ca.hash_name) det.push(["Trust-store file", ca.hash_name]);
      if (ca.not_after) det.push(["Expires", icShortDate(ca.not_after)]);
      if (det.length) {
        html += '<dl class="kv2 ic-kv">' + det.map(function (r) {
          return "<dt>" + esc(r[0]) + "</dt><dd>" + esc(r[1]) + "</dd>";
        }).join("") + "</dl>";
      }
    }

    // surface any per-probe errors the backend reported (one note each)
    var errs = s.errors || {};
    Object.keys(errs).forEach(function (k) {
      html += '<div class="ic-err">' + esc(k) + ": " + esc(errs[k]) + "</div>";
    });

    box.innerHTML = html;

    // Android 14 restart hint on the CA card
    var hint14 = $(".ic-hint14");
    if (hint14) hint14.style.display = (s.sdk === 34 || s.android === "14") ? "" : "none";

    icReflectProxy(px);
  }

  // mirror the live proxy into the card: a state pill, the mode select, and the
  // host/port/package inputs when they are still empty (so Apply reuses them)
  function icReflectProxy(px) {
    px = px || {};
    var state = $("#ic-proxy-state");
    if (state) {
      var txt, cls;
      if (px.mode === "global") { txt = "Global proxy → " + (px.host || "?") + ":" + (px.port || "?"); cls = "warn"; }
      else if (px.mode === "per-app") {
        txt = "Per-app proxy → " + (px.host || "?") + ":" + (px.port || "?") +
          " (" + (px.package || "?") + (px.uid != null ? ", uid " + px.uid : "") + ")";
        cls = "warn";
      } else { txt = "Proxy is off."; cls = "mut"; }
      state.innerHTML = '<span class="pill ' + cls + '">' + esc(txt) + "</span>";
    }
    var mode = $("#ic-mode");
    if (mode && (px.mode === "global" || px.mode === "per-app" || px.mode === "off")) mode.value = px.mode;
    var host = $("#ic-host"), port = $("#ic-port"), pkg = $("#ic-pkg");
    if (host && !host.value && px.host) host.value = px.host;
    if (port && !port.value && px.port) port.value = px.port;
    if (pkg && !pkg.value && px.package) pkg.value = px.package;
    icSyncMode();
  }

  function icSyncMode() {            // per-app target shown only in per-app mode
    var mode = $("#ic-mode") ? $("#ic-mode").value : "off";
    var pkgrow = $("#ic-pkgrow");
    if (pkgrow) pkgrow.style.display = (mode === "per-app") ? "" : "none";
    // host/port stay visible in every mode (Off simply ignores them) so the
    // setup fields are never hidden when the device starts with no proxy
  }

  // target datalist from the app list (same source App Manager uses); lazy per device
  function icLoadPkgs() {
    if (icPkgsDev === DEV) return;
    icPkgsDev = DEV;
    var dl = $("#ic-pkglist");
    if (!dl) return;
    amGet("/api/appmanager/list?which=user").then(function (d) {
      var apps = (d && d.apps) || [];
      dl.innerHTML = apps.map(function (a) {
        return '<option value="' + esc(a.package) + '">' + esc(a.label || a.package) + "</option>";
      }).join("");
    }).catch(function () { icPkgsDev = false; });  // retry on the next tab visit
  }

  function icReadPemFile(e) {        // FileReader -> textarea, client-side only
    var f = e.target.files && e.target.files[0];
    if (!f) return;
    var rd = new FileReader();
    rd.onload = function () {
      var ta = $("#ic-pem");
      if (ta) ta.value = String(rd.result || "");
      toast("loaded " + f.name + " into the PEM box", "good");
    };
    rd.onerror = function () { toast("could not read the file", "warn"); };
    rd.readAsText(f);
    e.target.value = "";             // allow re-picking the same file
  }

  function icRenderInspect(j) {
    var out = $("#ic-inspect-out");
    if (!out) return;
    var rows = [
      ["Subject", j.subject], ["Issuer", j.issuer],
      ["Valid from", icShortDate(j.not_before)], ["Valid to", icShortDate(j.not_after)],
      ["SHA-256", j.sha256], ["SHA-1", j.sha1], ["Trust-store file", j.hash_name],
      ["Is a CA", j.is_ca ? "yes" : "no — not a CA certificate"],
    ];
    out.style.display = "block";
    out.innerHTML = (j.is_ca ? "" : '<div class="ic-err">This certificate is not a CA (is_ca=false); installing it may not establish trust for other certs.</div>') +
      '<dl class="kv2 ic-kv">' + rows.map(function (r) {
        return "<dt>" + esc(r[0]) + "</dt><dd>" + esc(r[1] == null ? "—" : r[1]) + "</dd>";
      }).join("") + "</dl>";
  }

  function icInspect() {             // OFFLINE: no device, changes nothing
    var pem = ($("#ic-pem") ? $("#ic-pem").value : "").trim();
    if (!pem) { toast("paste the proxy CA PEM first", "warn"); return; }
    var out = $("#ic-inspect-out");
    if (out) { out.style.display = "block"; out.textContent = "inspecting…"; }
    postJSON("/api/intercept/ca/inspect", { pem: pem }).then(function (res) {
      var j = res.j || {};
      if (!j.ok) {
        if (out) out.innerHTML = '<div class="ic-err">' + esc(j.output || "not an X.509 certificate") + "</div>";
        toast("inspect failed — " + (j.output || "not a certificate"), "warn");
        return;
      }
      icRenderInspect(j);
      if (!j.is_ca) toast("this certificate is not a CA (is_ca=false)", "warn");
    }).catch(function () {
      if (out) out.innerHTML = '<div class="ic-err">inspect request failed</div>';
      toast("inspect request failed", "crit");
    });
  }

  function icInstall() {
    var pem = ($("#ic-pem") ? $("#ic-pem").value : "").trim();
    if (!pem) { toast("paste the proxy CA PEM first", "warn"); return; }
    if (typeof confirm === "function" && !confirm(
      "Install this CA into the device trust store? It affects every non-pinning app on the device. " +
      "Only on a device you own, for apps you are authorized to test. Use Revert when you are done.")) return;
    postJSON("/api/intercept/ca", { device: DEV, pem: pem, confirm: true }).then(function (res) {
      var j = res.j || {};
      toast((j.ok ? "CA installed — " : "Install failed — ") + ((j.output || "").split("\n")[0] || ""), j.ok ? "good" : "warn");
      if (j.ca) renderInterceptStatus(Object.assign({}, icStatus || {}, { ca: j.ca }));  // instant reflect
      loadInterceptStatus();        // then re-poll the authoritative state
    }).catch(function () { toast("install request failed", "crit"); });
  }

  function icRevert() {
    if (typeof confirm === "function" && !confirm(
      "Remove the proxy CA and tear down the trust-store overlay on the device? Continue?")) return;
    postJSON("/api/intercept/ca/revert", { device: DEV, confirm: true }).then(function (res) {
      var j = res.j || {};
      toast((j.ok ? "CA reverted — " : "Revert failed — ") + ((j.output || "").split("\n")[0] || ""), j.ok ? "good" : "warn");
      loadInterceptStatus();
    }).catch(function () { toast("revert request failed", "crit"); });
  }

  var IC_HOST_RE = /^[A-Za-z0-9_.-]{1,255}$/;           // mirrors _HOST_RE server-side
  var IC_PKG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}$/; // mirrors _PKG server-side

  function icApplyProxy() {
    var mode = $("#ic-mode") ? $("#ic-mode").value : "off";
    var host = ($("#ic-host") ? $("#ic-host").value : "").trim();
    var portRaw = ($("#ic-port") ? $("#ic-port").value : "").trim();
    var port = parseInt(portRaw, 10);
    var pkg = ($("#ic-pkg") ? $("#ic-pkg").value : "").trim();
    if (mode !== "off") {
      if (!IC_HOST_RE.test(host)) { toast("enter a valid proxy host (IPv4 or hostname)", "warn"); return; }
      if (!(port >= 1 && port <= 65535)) { toast("enter a valid port (1-65535)", "warn"); return; }
    }
    if (mode === "per-app" && !IC_PKG_RE.test(pkg)) { toast("pick a target package for per-app mode", "warn"); return; }
    var what = mode === "off" ? "Turn the proxy off?" :
      mode === "global" ? ("Point the whole device at " + host + ":" + port + "?") :
      ("Redirect " + shortApp(pkg) + " through " + host + ":" + port + "?");
    if (typeof confirm === "function" && !confirm(what + " Only on a device you own, for authorized testing.")) return;
    var body = { device: DEV, mode: mode, confirm: true };
    if (mode !== "off") { body.host = host; body.port = port; }
    if (mode === "per-app") body.package = pkg;
    postJSON("/api/intercept/proxy", body).then(function (res) {
      var j = res.j || {};
      toast((j.ok ? "proxy " + mode + " — " : "proxy change failed — ") + ((j.output || "").split("\n")[0] || ""), j.ok ? "good" : "warn");
      if (j.proxy) icReflectProxy(j.proxy);
      loadInterceptStatus();
    }).catch(function () { toast("proxy request failed", "crit"); });
  }

  function icProxyOff() {            // quick off: reverting, so no extra dialog
    postJSON("/api/intercept/proxy", { device: DEV, mode: "off", confirm: true }).then(function (res) {
      var j = res.j || {};
      toast((j.ok ? "proxy off — " : "could not turn proxy off — ") + ((j.output || "").split("\n")[0] || ""), j.ok ? "good" : "warn");
      loadInterceptStatus();
    }).catch(function () { toast("proxy request failed", "crit"); });
  }

  /* ===== engagement / scope gate ===== */
  var engCur = null;
  function loadEngagement() {
    getJSON("/api/engagement").then(function (d) {
      engCur = d.current;
      var st = $("#eng-state");
      if (st) st.textContent = engCur
        ? (engCur.name + " · " + engCur.mode + " mode")
        : "no engagement — own-device mode";
      var pick = $("#eng-pick");
      if (pick) {
        var opts = ['<option value="">— no engagement —</option>'];
        (d.list || []).forEach(function (e) {
          opts.push('<option value="' + esc(e.id) + '"' + (e.active ? " selected" : "") +
                    ">" + esc(e.name) + "</option>");
        });
        pick.innerHTML = opts.join("");
      }
      var mb = $("#eng-mode");
      if (mb) mb.textContent = engCur ? (engCur.mode === "active" ? "→ observe" : "→ active") : "mode";
    }).catch(function () {});
  }
  function engReload() { loadEngagement(); }
  (function initEngagement() {
    function on(id, fn, ev) { var e = $("#" + id); if (e) e.addEventListener(ev || "click", fn); }
    on("eng-pick", function () {
      var id = this.value;
      if (!id) return;
      postJSON("/api/engagement/activate", { id: id }).then(engReload)
        .then(function () { toast("engagement activated", "good"); });
    }, "change");
    on("eng-mode", function () {
      if (!engCur) { toast("create an engagement first", "warn"); return; }
      var next = engCur.mode === "active" ? "observe" : "active";
      postJSON("/api/engagement/mode", { mode: next }).then(engReload);
    });
    on("eng-new", function () { var f = $("#eng-form"); if (f) f.style.display = ""; });
    on("eng-cancel", function () { var f = $("#eng-form"); if (f) f.style.display = "none"; });
    on("eng-create", function () {
      var body = {
        name: ($("#eng-name").value || "").trim(),
        authorization_ref: ($("#eng-auth").value || "").trim(),
        scope_packages: ($("#eng-pkgs").value || ""),
        scope_hosts: ($("#eng-hosts").value || ""),
        deny: ($("#eng-deny").value || ""),
      };
      if (!body.name) { toast("an engagement needs a name", "warn"); return; }
      postJSON("/api/engagement", body).then(function (r) {
        if (r.ok === false) { toast(r.output || "could not create", "warn"); return; }
        $("#eng-form").style.display = "none";
        toast("engagement created & active", "good");
        engReload();
      }).catch(function () { toast("request failed", "crit"); });
    });
  })();

  /* ===== Frida unpinning ===== */
  function loadFridaCard() {
    var sel = $("#fr-preset");
    if (sel && !sel.dataset.filled) {
      getJSON("/api/frida/presets").then(function (d) {
        sel.innerHTML = (d.presets || []).map(function (p) {
          return '<option value="' + esc(p.id) + '">' + esc(p.title) + "</option>";
        }).join("");
        sel.dataset.filled = "1";
      }).catch(function () {});
    }
    amGet("/api/frida/status").then(function (s) {
      var box = $("#fr-status");
      if (!box) return;
      box.innerHTML = [
        pill(s.host_frida ? "good" : "warn", s.host_frida ? ("frida on host" + (s.host_version ? " " + esc(s.host_version) : "")) : "no frida-tools here — pip install frida-tools"),
        pill(s.server_running ? "good" : "mut", s.server_running ? "server running" : "server stopped"),
        s.arch ? pill("mut", esc(s.arch)) : "",
        s.unpinning ? pill("good", "unpinning active — drive the app") : "",
      ].join(" ");
    }).catch(function () {});
  }
  function fridaServer(action) {
    var dctx = DEV;
    postJSON("/api/frida/server", { device: dctx, action: action, confirm: true })
      .then(function (r) {
        toast((r.ok ? "" : "failed: ") + (r.output || action), r.ok ? "good" : "warn");
        loadFridaCard();
      }).catch(function () { toast("request failed", "crit"); });
  }
  (function initFrida() {
    function on(id, fn) { var e = $("#" + id); if (e) e.addEventListener("click", fn); }
    on("fr-start", function () { fridaServer("start"); });
    on("fr-stop", function () { fridaServer("stop"); });
    on("fr-unpin", function () {
      var pkg = ($("#fr-pkg").value || "").trim();
      if (!pkg) { toast("pick a target app", "warn"); return; }
      if (typeof confirm === "function" &&
          !confirm("Run a pinning-bypass on " + shortApp(pkg) + "? Only on an app you are authorized to test.")) return;
      var out = $("#fr-out");
      if (out) { out.style.display = ""; out.textContent = "running…"; }
      postJSON("/api/frida/unpin", {
        device: DEV, package: pkg, preset: $("#fr-preset").value || "all",
        mode: $("#fr-mode").value || "spawn", confirm: true,
      }).then(function (r) {
        if (out) out.textContent = (r.output || "");
        if (r.ok) {
          toast("Frida hooks injected — now drive the app; watch the Console", "good",
                "open the Console tab to see each bypass fire");
        } else {
          toast("unpin failed: " + (r.output || "").split("\n")[0], "warn");
        }
        loadFridaCard();
      }).catch(function () { if (out) out.textContent = "request failed"; toast("request failed", "crit"); });
    });
    on("fr-stop-unpin", function () {
      postJSON("/api/frida/unpin/stop", { device: DEV }).then(function (r) {
        toast(r.output || "unpinning stopped", "good"); loadFridaCard();
      }).catch(function () {});
    });
    on("fr-toconsole", function () { go("console"); });

    on("cap-start", function () {
      var pkg = ($("#cap-pkg").value || "").trim();
      if (!pkg) { toast("pick an app", "warn"); return; }
      if (typeof confirm === "function" &&
          !confirm("Capture " + shortApp(pkg) + "'s requests into the Requests tab?\nOnly on an app you are authorized to test. This restarts the app.")) return;
      postJSON("/api/frida/capture/start", { device: DEV, package: pkg, mode: "spawn" }).then(function (r) {
        toast(r.ok ? "capturing — open the Requests tab and use the app" : ("capture failed: " + (r.output || "").split("\n")[0]),
              r.ok ? "good" : "warn");
        loadCaptureStatus();
      }).catch(function () { toast("request failed", "crit"); });
    });
    on("cap-stop", function () {
      postJSON("/api/frida/capture/stop", { device: DEV }).then(function (r) {
        toast(r.output || "capture stopped", "good"); loadCaptureStatus();
      }).catch(function () {});
    });
    on("cap-toreq", function () { go("requests"); });
  })();

  function loadCaptureStatus() {
    var el = $("#cap-status");
    if (!el) return;
    getJSON(dq("/api/frida/capture/status")).then(function (s) {
      if (s && s.capturing) { el.className = "pill good"; el.textContent = "capturing " + shortApp(s.package || ""); }
      else { el.className = "pill mut"; el.textContent = "idle"; }
    }).catch(function () {});
  }

  /* ===== mitmproxy ===== */
  function loadMitmCard() {
    getJSON("/api/mitm/status").then(function (s) {
      var box = $("#mitm-status");
      if (!box) return;
      box.innerHTML = [
        pill(s.installed ? "good" : "warn", s.installed ? "mitmproxy installed" : "not installed (pip install mitmproxy)"),
        pill(s.running ? "good" : "mut", s.running ? ("running on " + s.port) : "stopped"),
      ].join(" ");
    }).catch(function () {});
  }
  (function initMitm() {
    function on(id, fn) { var e = $("#" + id); if (e) e.addEventListener("click", fn); }
    on("mitm-start", function () {
      var port = parseInt($("#mitm-port").value, 10);
      if (!(port >= 1 && port <= 65535)) { toast("enter a port", "warn"); return; }
      postJSON("/api/mitm/start", { port: port, mode: $("#mitm-mode").value || "regular", confirm: true })
        .then(function (r) { toast(r.output || (r.ok ? "started" : "failed"), r.ok ? "good" : "warn"); loadMitmCard(); })
        .catch(function () { toast("request failed", "crit"); });
    });
    on("mitm-stop", function () {
      postJSON("/api/mitm/stop", {}).then(function (r) { toast(r.output || "stopped", "good"); loadMitmCard(); })
        .catch(function () { toast("request failed", "crit"); });
    });
  })();

  function pill(cls, text) { return '<span class="pill ' + cls + '">' + text + "</span>"; }

  (function initIntercept() {        // DOM is present (script at end of body)
    function on(id, fn, ev) { var e = $("#" + id); if (e) e.addEventListener(ev || "click", fn); }
    on("ic-refresh", loadInterceptStatus);
    on("ic-inspect", icInspect);
    on("ic-install", icInstall);
    on("ic-revert", icRevert);
    on("ic-apply", icApplyProxy);
    on("ic-proxyoff", icProxyOff);
    on("ic-mode", icSyncMode, "change");
    on("ic-pemfile", icReadPemFile, "change");
    on("ic-camodule", icCaModule);
    on("ic-builtin", icBuiltinInstall);
  })();

  function icBuiltinInstall() {
    if (typeof confirm === "function" &&
        !confirm("Create Sentinel's CA (if needed) and install it into this device's trust store over root? Only on a device you own.")) return;
    var out = $("#ic-inspect-out");
    if (out) { out.style.display = ""; out.textContent = "creating & installing over su…"; }
    postJSON("/api/intercept/ca/builtin/install", { device: DEV, confirm: true })
      .then(function (r) {
        if (out) out.textContent = (r.ok ? "✓ installed: " : "✗ ") +
          ((r.ca && r.ca.subject) || "") + "\n" + (r.output || "");
        toast(r.ok ? "Sentinel CA created & installed" : "failed: " + (r.output || "").split("\n")[0],
              r.ok ? "good" : "warn",
              r.ok ? "restart the target app to pick up the CA" : "");
        loadInterceptStatus();
        loadBuiltinCa();
      }).catch(function () { if (out) out.textContent = "request failed"; toast("request failed", "crit"); });
  }

  function icCaModule() {
    var pem = ($("#ic-pem").value || "").trim();
    if (!pem) { toast("paste the CA PEM first", "warn"); return; }
    // POST then download the returned zip
    fetch("/api/intercept/ca/module", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pem: pem }),
    }).then(function (r) {
      if (!r.ok) return r.json().then(function (j) { throw new Error(j.output || "failed"); });
      return r.blob();
    }).then(function (blob) {
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "sentinel-ca-module.zip";
      document.body.appendChild(a); a.click(); a.remove();
      toast("Magisk module downloaded", "good", "flash it in Magisk so the CA survives reboot");
    }).catch(function (e) { toast(e.message || "could not build module", "warn"); });
  }

  /* ================= requests monitor ================= */
  var rqRows = [];
  function rqFilters() {
    var q = {};
    var h = ($("#rq-host").value || "").trim(); if (h) q.host = h;
    var p = ($("#rq-path").value || "").trim(); if (p) q.path = p;
    var m = $("#rq-method").value; if (m) q.method = m;
    var s = $("#rq-status").value; if (s) q.status_class = s;
    var sc = $("#rq-scheme").value; if (sc) q.scheme = sc;
    if ($("#rq-auth").checked) q.has_auth = "1";
    if ($("#rq-new").checked) q.new_host = "1";
    return q;
  }
  function rqUrl(base) {
    var pkg = ($("#rq-pkg").value || "").trim();
    var q = rqFilters();
    var parts = [];
    if (pkg) parts.push("package=" + encodeURIComponent(pkg));
    Object.keys(q).forEach(function (k) { parts.push(k + "=" + encodeURIComponent(q[k])); });
    return base + (parts.length ? "?" + parts.join("&") : "");
  }
  function loadRequests() {
    rqLoadPkgs();
    amGet(rqUrl("/api/requests")).then(function (d) {
      rqRows = d.flows || [];
      renderRequests(d);
    }).catch(function () {
      $("#rq-list").innerHTML = '<div class="empty">could not load requests</div>';
    });
    loadWatches();
  }
  function renderRequests(d) {
    var c = $("#rq-count");
    if (c) c.textContent = (d.demo ? "demo · " : "") + d.count + " requests" +
      (($("#rq-pkg").value || "").trim() ? " for this app" : "");
    $("#rq-list").innerHTML = rqRows.map(function (r, i) {
      var cls = r.scheme === "http" ? "crit" : ((r.status || 0) >= 400 ? "warn" : "good");
      return '<div class="rq-row" data-i="' + i + '">' +
        '<span class="pill ' + cls + '">' + esc(r.method) + "</span>" +
        '<span class="rq-host">' + esc(r.host) + '</span>' +
        '<span class="rq-path">' + esc(r.path) + "</span>" +
        '<span class="rq-st">' + (r.status == null ? "—" : r.status) + "</span>" +
        (r.has_auth ? '<span class="pill warn" title="carries an Authorization/Cookie/token">auth</span>' : "") +
        (r.scheme === "http" ? '<span class="pill crit">cleartext</span>' : "") +
        (r.new_host ? '<span class="pill mut">new</span>' : "") +
        '</div>';
    }).join("") || '<div class="empty">no requests — start mitmproxy, set the proxy, and drive the app</div>';
    $$("#rq-list .rq-row").forEach(function (row) {
      row.addEventListener("click", function () { rqShowDetail(rqRows[+row.dataset.i]); });
    });
  }
  function rqShowDetail(r) {
    if (!r) return;
    var hdr = function (h) { return Object.keys(h || {}).map(function (k) {
      return esc(k) + ": " + esc(String(h[k])); }).join("\n"); };
    var out = $("#rq-count");
    if (out) {
      out.innerHTML = '<pre class="rq-det mono">' + esc("» " + r.method + " " + r.scheme + "://" + r.host + r.path) +
        "\n" + esc(hdr(r.req_headers)) + "\n\n« " + (r.status || "") + "\n" + esc(hdr(r.resp_headers)) + "</pre>";
    }
    // load it into the Repeater so it can be edited and resent
    rqToRepeater(r);
  }
  function rqToRepeater(r) {
    var m = $("#rp-method"), u = $("#rp-url"), h = $("#rp-headers"), b = $("#rp-body");
    if (m) m.value = r.method || "GET";
    if (u) u.value = r.scheme + "://" + r.host + r.path;
    if (h) h.value = Object.keys(r.req_headers || {}).map(function (k) {
      return k + ": " + r.req_headers[k]; }).join("\n");
    if (b) b.value = r.req_body_preview || "";
  }
  function rpSpec() {
    var headers = {};
    ($("#rp-headers").value || "").split("\n").forEach(function (line) {
      var i = line.indexOf(":");
      if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
    return { method: $("#rp-method").value, url: ($("#rp-url").value || "").trim(),
             headers: headers, body: $("#rp-body").value || "" };
  }
  (function initRepeater() {
    function on(id, fn) { var e = $("#" + id); if (e) e.addEventListener("click", fn); }
    on("rp-send", function () {
      var spec = rpSpec();
      if (!/^https?:\/\//.test(spec.url)) { toast("enter an http(s) URL", "warn"); return; }
      var out = $("#rp-out");
      if (out) { out.style.display = ""; out.textContent = "sending…"; }
      spec.device = DEV; spec.through_proxy = true;
      postJSON("/api/requests/replay", spec).then(function (r) {
        if (r.ok === false) { if (out) out.textContent = r.output || "failed"; toast(r.output || "replay failed", "warn"); return; }
        var hdr = Object.keys(r.headers || {}).map(function (k) { return k + ": " + r.headers[k]; }).join("\n");
        if (out) out.textContent = "« " + r.status + "  (" + r.bytes + " B, " + r.duration_ms + " ms)\n" + hdr + "\n\n" + (r.body_preview || "");
        toast("replay: " + r.status, r.status < 400 ? "good" : "warn");
        if (currentTab === "requests") setTimeout(loadRequests, 400);  // the resend is re-captured
      }).catch(function () { if (out) out.textContent = "request failed"; toast("replay failed", "crit"); });
    });
    on("rp-curl", function () {
      var s = rpSpec();
      var parts = ["curl -X " + s.method, "'" + s.url.replace(/'/g, "'\\''") + "'"];
      Object.keys(s.headers).forEach(function (k) {
        parts.push("-H '" + (k + ": " + s.headers[k]).replace(/'/g, "'\\''") + "'");
      });
      if (s.body) parts.push("--data '" + s.body.replace(/'/g, "'\\''") + "'");
      var cmd = parts.join(" ");
      var done = function () { toast("cURL copied", "good"); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(cmd).then(done, function () { rpFallbackCopy(cmd, done); });
      } else { rpFallbackCopy(cmd, done); }
    });
  })();
  function rpFallbackCopy(text, done) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); ta.remove(); done();
    } catch (e) { toast("copy failed", "warn"); }
  }
  function rqLoadPkgs() {
    var dl = $("#rq-pkglist");
    if (!dl || dl.dataset.dev === String(DEV)) return;
    amGet("/api/appmanager/list?which=user").then(function (d) {
      dl.innerHTML = (d.apps || []).map(function (a) {
        return '<option value="' + esc(a.package) + '">' + esc(a.label || a.package) + "</option>";
      }).join("");
      dl.dataset.dev = String(DEV);
    }).catch(function () {});
  }
  function loadWatches() {
    amGet("/api/requests/watches").then(function (d) {
      $("#rq-watches").innerHTML = (d.watches || []).length
        ? (d.watches).map(function (w) {
          return '<div class="rq-watch"><span class="fn">' + esc(w.name) + "</span>" +
            '<button class="btn danger" data-wd="' + esc(w.id) + '">remove</button></div>';
        }).join("")
        : '<div class="empty">no watches — save a filter to get alerted on a match</div>';
      $$("#rq-watches [data-wd]").forEach(function (b) {
        b.addEventListener("click", function () {
          postJSON("/api/requests/watches/delete", { device: DEV, id: b.dataset.wd }).then(loadWatches);
        });
      });
    }).catch(function () {});
  }
  (function initRequests() {
    function on(id, fn, ev) { var e = $("#" + id); if (e) e.addEventListener(ev || "click", fn); }
    on("rq-refresh", loadRequests);
    on("rq-pkg", loadRequests, "change");
    ["rq-host", "rq-path"].forEach(function (id) { on(id, loadRequests, "change"); });
    ["rq-method", "rq-status", "rq-scheme"].forEach(function (id) { on(id, loadRequests, "change"); });
    ["rq-auth", "rq-new"].forEach(function (id) { on(id, loadRequests, "change"); });
    on("rq-watch", function () {
      var name = prompt("Name this watch (alerts when the current filter matches):", "cleartext");
      if (!name) return;
      postJSON("/api/requests/watches", {
        device: DEV, name: name, package: ($("#rq-pkg").value || "").trim() || null,
        filter: rqFilters(),
      }).then(function (r) {
        if (r.ok === false) { toast(r.output || "could not save", "warn"); return; }
        toast("watch saved", "good"); loadWatches();
      }).catch(function () { toast("request failed", "crit"); });
    });
    on("rq-export", function () {
      var fmt = this.value; this.value = "";
      if (!fmt) return;
      window.open(rqUrl("/api/requests/export").replace(/\?|$/, function (m) {
        return (m === "?" ? "?format=" + fmt + "&" : "?format=" + fmt); }), "_blank");
    }, "change");
    on("rq-endpoints", function () {
      var pkg = ($("#rq-pkg").value || "").trim();
      amGet("/api/requests/endpoints" + (pkg ? "?package=" + encodeURIComponent(pkg) : "")).then(function (d) {
        $("#rq-list").innerHTML = (d.endpoints || []).length
          ? (d.endpoints).map(function (e) {
            return '<div class="rq-row"><span class="pill mut">' + esc((e.method_set || []).join(",")) +
              '</span><span class="rq-host">' + esc(e.host) + '</span><span class="rq-path">' +
              esc(e.path) + '</span><span class="rq-st">' + e.count + "×</span></div>";
          }).join("")
          : '<div class="empty">no endpoints yet</div>';
        var c = $("#rq-count"); if (c) c.textContent = (d.endpoints || []).length + " endpoints";
      }).catch(function () {});
    });
  })();

  /* ================= product polish ================= */

  /* ---- toasts ---- */
  function toast(msg, cls, meta) {
    var box = $("#toasts");
    if (!box) return;
    var el = document.createElement("div");
    el.className = "toast " + (cls || "");
    el.innerHTML = esc(msg) + (meta ? '<div class="tmeta">' + esc(meta) + "</div>" : "");
    box.appendChild(el);
    setTimeout(function () {
      el.style.opacity = "0";
      el.style.transition = "opacity .3s";
      setTimeout(function () { el.remove(); }, 350);
    }, 4200);
  }

  /* ---- tooltips: [data-tip] rendered into a fixed singleton so overflow
         containers (.card.pad0, .applist, collapsed cards) cannot clip them ---- */
  var tipbox = document.createElement("div");
  tipbox.id = "tipbox";
  document.body.appendChild(tipbox);
  var tipTarget = null;
  function hideTip() { tipTarget = null; tipbox.style.display = "none"; }
  document.addEventListener("mouseover", function (e) {
    var t = e.target && e.target.closest ? e.target.closest("[data-tip]") : null;
    if (t === tipTarget) return;
    if (!t) { hideTip(); return; }
    tipTarget = t;
    tipbox.textContent = t.getAttribute("data-tip") || "";
    tipbox.style.display = "block";
    var r = t.getBoundingClientRect();
    var x = Math.max(8, Math.min(r.left, window.innerWidth - tipbox.offsetWidth - 8));
    var y = r.bottom + 7;
    if (y + tipbox.offsetHeight > window.innerHeight - 8)
      y = Math.max(8, r.top - tipbox.offsetHeight - 7);
    tipbox.style.left = x + "px";
    tipbox.style.top = y + "px";
  });
  document.addEventListener("mouseout", function (e) {
    if (!e.relatedTarget) hideTip();  // pointer left the window
  });
  document.addEventListener("scroll", function () { if (tipTarget) hideTip(); }, true);

  /* ---- global search: filters whatever the current tab shows ---- */
  function gQuery() {
    var el = $("#gsearch");
    return el ? (el.value || "").trim().toLowerCase() : "";
  }
  var ROW_SEL = ".ev, .approw, .logln, .alertrow, .devrow, .fentry, tbody tr";
  function applyGlobalSearch() {
    var panel = $('.panel[data-panel="' + currentTab + '"]');
    if (!panel) return;
    var q = gQuery();
    $$(ROW_SEL, panel).forEach(function (row) {
      if (row.querySelector(".empty") || row.classList.contains("empty")) return;
      var id = (row.closest(".feed") || {}).id || "";
      row.style.display = rowMatchesFilters(row, id) ? "" : "none";
    });
    void q;
  }
  $("#gsearch").addEventListener("input", applyGlobalSearch);
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && !/input|select|textarea/i.test((document.activeElement || {}).tagName || "")) {
      e.preventDefault();
      $("#gsearch").focus();
    }
    if (e.key === "Escape" && document.activeElement === $("#gsearch")) {
      $("#gsearch").value = "";
      applyGlobalSearch();
      $("#gsearch").blur();
    }
  });
  setInterval(function () { if (gQuery()) applyGlobalSearch(); }, 1200);

  /* ---- monitor severity chips ---- */
  $$("#sevchips button").forEach(function (b) {
    b.addEventListener("click", function () {
      $$("#sevchips button").forEach(function (x) { x.classList.remove("on"); });
      b.classList.add("on");
      sevFilter = b.dataset.sev;
      $$("#feed-mon .ev").forEach(function (row) { applyRowFilters(row, "feed-mon"); });
    });
  });

  /* ---- generic sortable table headers ---- */
  function wireSortable(tableSel, state, rerender) {
    $$(tableSel + " th.sortable").forEach(function (th) {
      th.addEventListener("click", function () {
        var col = th.dataset.col;
        if (state.col === col) state.dir = -state.dir;
        else { state.col = col; state.dir = th.dataset.num ? -1 : 1; }
        rerender();
      });
    });
  }
  function paintSortArrows(tableSel, state) {
    $$(tableSel + " th.sortable").forEach(function (th) {
      var arr = th.querySelector(".arr");
      if (!arr) {
        arr = document.createElement("span");
        arr.className = "arr";
        th.appendChild(arr);
      }
      arr.textContent = th.dataset.col === state.col ? (state.dir > 0 ? "▴" : "▾") : "";
    });
  }
  function cmpBy(state, getters) {
    var get = getters[state.col] || function () { return ""; };
    return function (a, b) {
      var x = get(a), y = get(b);
      if (typeof x === "string") return state.dir * x.localeCompare(String(y));
      return state.dir * ((x || 0) - (y || 0));
    };
  }

  /* ---- per-app storage table (sortable, clickable rows) ---- */
  function renderStorageTable() {
    var rows = lastStorApps.slice().sort(cmpBy(storSort, {
      name: function (a) { return shortApp(a.package).toLowerCase(); },
      data: function (a) { return a.data_size || 0; },
      cache: function (a) { return a.cache_size || 0; },
      apk: function (a) { return a.apk_size || 0; },
    }));
    paintSortArrows("#storagetbl", storSort);
    $("#storagetbl tbody").innerHTML = rows.map(function (a) {
      return '<tr class="srow rowlink" data-pkg="' + esc(a.package) +
        '" title="Click to inspect where this app stores its data and logs">' +
        '<td><div style="font-weight:500">' + esc(shortApp(a.package)) + "</div>" +
        '<div class="mono" style="font-size:11px;color:var(--fg-mut);overflow:hidden;text-overflow:ellipsis;max-width:200px;white-space:nowrap">' + esc(a.package) + "</div></td>" +
        '<td class="mono tnum">' + fmtBytes(a.data_size) + "</td>" +
        '<td class="mono tnum">' + fmtBytes(a.cache_size) + "</td>" +
        '<td class="mono tnum">' + fmtBytes(a.apk_size) + "</td>" +
        '<td><div class="act"><button class="btn" data-inspect="' + esc(a.package) +
        '" title="Show data directories, sizes and log files">inspect</button>' +
        '<button class="btn p" data-backup="' + esc(a.package) +
        '" title="Pull the APK and its data to this computer">extract</button></div></td></tr>';
    }).join("") || '<tr><td colspan="5" class="empty">no app storage data yet (needs a device)</td></tr>';
    $$("#storagetbl [data-inspect]").forEach(function (b) {
      b.addEventListener("click", function (e) { e.stopPropagation(); inspectApp(b.dataset.inspect); });
    });
    $$("#storagetbl [data-backup]").forEach(function (b) {
      b.addEventListener("click", function (e) { e.stopPropagation(); startBackup(b.dataset.backup); });
    });
    $$("#storagetbl tbody tr.rowlink").forEach(function (tr) {
      tr.addEventListener("click", function () { inspectApp(tr.dataset.pkg); });
    });
    applyGlobalSearch();
  }
  wireSortable("#storagetbl", storSort, renderStorageTable);

  /* ---- top destinations table (sortable, click to filter) ---- */
  var destSort = { col: "count", dir: -1 };
  var lastDestHTML = null;
  function renderDestTable() {
    var tbody = $("#desttbl tbody");
    if (!tbody) return;
    var rows = Object.keys(destStats).map(function (k) { return destStats[k]; });
    var html;
    if (!rows.length) {
      // keep the table honest after a device switch: show the placeholder
      html = '<tr><td colspan="4" class="empty">destinations appear as traffic flows</td></tr>';
    } else {
      rows.sort(cmpBy(destSort, {
        host: function (d) { return (d.label || "").toLowerCase(); },
        count: function (d) { return d.count || 0; },
        tracker: function (d) { return d.tracker || ""; },
        last: function (d) { return d.last || 0; },
      }));
      html = rows.slice(0, 80).map(function (d) {
        return '<tr class="rowlink" data-host="' + esc(d.label) +
          '" title="Click to filter the connection feed to this destination">' +
          '<td class="mono" style="font-size:12px;word-break:break-all">' + esc(d.label) +
          (d.alerted ? ' <span class="pill crit">alerted</span>' : "") + "</td>" +
          '<td class="mono tnum">' + d.count + "</td>" +
          "<td>" + (d.tracker ? '<span class="pill info">' + esc(d.tracker) + "</span>"
            : '<span style="color:var(--fg-mut)">—</span>') + "</td>" +
          '<td class="mono tnum">' + fmtTime(d.last) + "</td></tr>";
      }).join("");
    }
    paintSortArrows("#desttbl", destSort);
    if (html === lastDestHTML) return;  // unchanged: keep DOM, selection and hover intact
    lastDestHTML = html;
    tbody.innerHTML = html;
    applyGlobalSearch();
  }
  wireSortable("#desttbl", destSort, renderDestTable);
  // one delegated listener: survives every repaint, no mid-click listener loss
  $("#desttbl tbody").addEventListener("click", function (e) {
    var tr = e.target && e.target.closest ? e.target.closest("tr.rowlink") : null;
    if (!tr || !tr.dataset.host) return;
    $("#gsearch").value = tr.dataset.host;
    applyGlobalSearch();
    toast("Filtering to " + tr.dataset.host, "", "clear the search box to see everything again");
  });

  /* ---- click a feed row -> open that app ---- */
  ["#feed-mon", "#feed-net", "#feed-priv"].forEach(function (sel) {
    var el = $(sel);
    if (!el) return;
    el.addEventListener("click", function (e) {
      var row = e.target.closest(".ev[data-app]");
      if (!row) return;
      var app = row.dataset.app;
      go("apps");
      $("#appsearch").value = app;
      renderApps();
      toast("Showing " + shortApp(app), "", "clear the filter box to see all apps");
    });
  });

  /* ---- draggable layout + collapsible cards (persisted) ---- */
  function keyOf(el, i) {
    if (el.id) return el.id;
    var idEl = el.querySelector("[id]");
    if (idEl) return "k-" + idEl.id;
    var h = el.querySelector(".ch h3");
    if (h) return "h-" + h.textContent.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 30);
    return "i-" + i;
  }
  function loadJSON(key, fallback) {
    try { return JSON.parse(localStorage.getItem(key)) || fallback; } catch (e) { return fallback; }
  }
  function saveJSON(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {}
  }
  var layout = loadJSON("sentinel-layout", {});
  var collapsed = loadJSON("sentinel-collapsed", {});
  var draggedEl = null;

  function initDragZones() {
    $$(".panel").forEach(function (panel) {
      $$(".grid.tiles, .cols, .cols3", panel).forEach(function (zone, zi) {
        var zoneKey = panel.dataset.panel + ":" + zi;
        var kids = Array.prototype.slice.call(zone.children);
        // restore saved order
        var saved = layout[zoneKey];
        if (saved && saved.length) {
          var byKey = {};
          kids.forEach(function (k, i) { byKey[keyOf(k, i)] = k; });
          saved.forEach(function (k) { if (byKey[k]) zone.appendChild(byKey[k]); });
        }
        Array.prototype.slice.call(zone.children).forEach(function (child, ci) {
          var handle = document.createElement("div");
          handle.className = "dragh";
          handle.textContent = "⠿";
          handle.title = "Drag to rearrange this panel";
          child.style.position = "relative";
          child.appendChild(handle);
          handle.addEventListener("mousedown", function () {
            child.draggable = true;
            // a click with no drag must not leave the card drag-armed
            // (draggable=true hijacks text selection inside the card)
            document.addEventListener("mouseup", function armOff() {
              document.removeEventListener("mouseup", armOff);
              child.draggable = false;
            });
          });
          child.addEventListener("dragstart", function (e) {
            draggedEl = child;
            child.classList.add("dragging");
            try { e.dataTransfer.setData("text/plain", ""); } catch (err) {}
            e.dataTransfer.effectAllowed = "move";
          });
          child.addEventListener("dragend", function () {
            child.classList.remove("dragging");
            child.draggable = false;
            draggedEl = null;
            layout[zoneKey] = Array.prototype.slice.call(zone.children)
              .map(function (k, i) { return keyOf(k, i); });
            saveJSON("sentinel-layout", layout);
          });
          child.addEventListener("dragover", function (e) {
            if (!draggedEl || draggedEl === child || draggedEl.parentNode !== zone) return;
            e.preventDefault();
            var order = Array.prototype.slice.call(zone.children);
            if (order.indexOf(draggedEl) < order.indexOf(child)) child.after(draggedEl);
            else child.before(draggedEl);
          });
          void ci;
        });
      });
      // collapsible cards: any card with a header gets a collapser
      $$(".card", panel).forEach(function (card, ci) {
        var ch = card.querySelector(":scope > .ch");
        if (!ch || ch.querySelector(".collapser")) return;
        var ckey = "c:" + panel.dataset.panel + ":" + keyOf(card, ci);
        var btn = document.createElement("button");
        btn.className = "collapser";
        btn.title = "Collapse / expand";
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg>';
        ch.appendChild(btn);
        if (collapsed[ckey]) card.classList.add("collapsed");
        btn.addEventListener("click", function (e) {
          e.stopPropagation();
          card.classList.toggle("collapsed");
          collapsed[ckey] = card.classList.contains("collapsed");
          saveJSON("sentinel-collapsed", collapsed);
        });
      });
    });
  }
  initDragZones();

  /* ---------- initial feed backfill ---------- */
  // Buffer live WS events until the backfill has rendered, then replay them,
  // so history and live events land in order; stored events dedupe by id.
  var backfillDone = false, wsBuffer = [], seenIds = {};
  function flushBuffer() {
    backfillDone = true;
    wsBuffer.forEach(routeEvent);
    wsBuffer = [];
  }
  fetch(dq("/api/events?limit=60")).then(function (r) { return r.json(); }).then(function (evs) {
    (evs || []).reverse().forEach(routeEvent);
    flushBuffer();
  }).catch(flushBuffer);

  /* ---------- websocket ---------- */
  function routeEvent(ev) {
    // the WS carries every device; show only the selected one (device-less
    // sentinel notices always pass)
    if (DEV && ev.device && ev.device !== DEV) return;
    if (ev.id != null) {
      if (seenIds[ev.id]) return;
      if (Object.keys(seenIds).length > 5000) seenIds = {};
      seenIds[ev.id] = 1;
    }
    var group = ev.kind.split(".")[0];
    if (ev.kind === "log.line") {
      var buf = (ev.data || {}).buffer;
      if (buf === "radio") {
        radioLogs.unshift(ev); radioLogs = radioLogs.slice(0, 300);
        if (currentTab === "radio") renderRadioLog();
      } else {
        sysLogs.unshift(ev); sysLogs = sysLogs.slice(0, 500);
        if (currentTab === "logs") renderLogs();
      }
      return;
    }
    if (ev.kind === "net.stats") return;  // panels poll REST for this
    pushFeed($("#feed-mon"), ev, 80);
    if (group === "net") {
      pushFeed($("#feed-net"), ev, 80);
      if (ev.kind === "net.conn") { noteDest(ev); }
      if (curTransport !== "all") {
        var first = $("#feed-net .ev");
        if (first && first.dataset.transport !== curTransport) first.style.display = "none";
      }
    }
    if (group === "sensor") {
      pushFeed($("#feed-priv"), ev, 80);
      sensorLast[ev.kind] = ev;
      renderSensorCards(lastStatus.camera_active || []);
    }
    if (group === "radio") {
      radioLogs.unshift({ ts: ev.ts, data: { level: "I", tag: ev.kind }, app: null,
        detail: ev.title + (ev.detail ? " — " + ev.detail : "") });
      if (ev.kind === "radio.cell") $("#r-change").textContent = fmtTime(ev.ts);
      if (currentTab === "radio") renderRadioLog();
    }
    if (ev.kind === "alert") {
      if (ev.data && ev.data.ip) alertedIPs[ev.data.ip] = 1;
      loadAlerts(); pollStatus();
    }
    // the activity console shows what Sentinel ran on the device + its output
    if (ev.kind === "app.action" || ev.kind === "intercept.action" ||
        ev.kind === "alert" || ev.kind === "app.backup" || ev.kind === "frida.log") {
      consolePush(ev);
    }
    if (ev.kind === "app.backup" && currentTab === "storage") loadBackups();
    if (ev.kind === "app.backup" && currentTab === "appmgr" && amSel) {  // one event per finished job
      amInvalidate(amSel);
      if (amTab === "backups" || amTab === "storage") amShowTab(amTab);
    }
  }

  /* ================= activity console ================= */
  var conLog = [], conPaused = false, conMax = 500;
  function consolePush(ev) {
    conLog.push(ev);
    if (conLog.length > conMax) conLog = conLog.slice(-conMax);
    if (currentTab === "console" && !conPaused) conRender(ev);
  }
  function conGroup(ev) {
    if (ev.kind === "intercept.action") return "intercept";
    if (ev.kind === "app.action") return "app";
    if (ev.kind === "frida.log") return "frida";
    if (ev.kind === "alert") return "alert";
    return ev.kind.split(".")[0];
  }
  function conLineHtml(ev) {
    var d = ev.data || {};
    var ok = d.ok;
    var sev = ev.kind === "alert" ? "crit" : (ok === false ? "warn" : (ok ? "good" : "mut"));
    var grp = conGroup(ev);
    var head = '<span class="con-t">' + esc(fmtTime(ev.ts)) + "</span> " +
      '<span class="con-g con-' + sev + '">' + esc(grp) + "</span> " +
      '<span class="con-ti">' + esc(ev.title || ev.kind) + "</span>";
    var out = d.output || ev.detail || "";
    var body = out ? '\n<span class="con-out">' + esc(String(out).replace(/\s+$/, "")) + "</span>" : "";
    return '<div class="con-line">' + head + body + "</div>";
  }
  function conRender(ev) {
    var box = $("#con-log");
    if (!box) return;
    if (ev) {
      if (box.querySelector(".con-dim")) box.innerHTML = "";
      box.insertAdjacentHTML("beforeend", conLineHtml(ev));
    } else {
      var f = $("#con-filter") ? $("#con-filter").value : "";
      var rows = conLog.filter(function (e) { return !f || conGroup(e) === f; });
      box.innerHTML = rows.length
        ? rows.map(conLineHtml).join("")
        : '<span class="con-dim">no activity yet for this filter.</span>';
    }
    if ($("#con-auto") && $("#con-auto").checked) box.scrollTop = box.scrollHeight;
  }
  function loadConsole() { conRender(null); }
  (function initConsole() {
    function on(id, fn, ev) { var e = $("#" + id); if (e) e.addEventListener(ev || "click", fn); }
    on("con-clear", function () { conLog = []; conRender(null); });
    on("con-pause", function () {
      conPaused = !conPaused;
      this.textContent = conPaused ? "Resume" : "Pause";
      if (!conPaused) conRender(null);
    });
    on("con-filter", function () { conRender(null); }, "change");
  })();

  var wsRetry = 1000;
  function connectWS() {
    var proto = location.protocol === "https:" ? "wss://" : "ws://";
    var ws = new WebSocket(proto + location.host + "/ws");
    ws.onopen = function () {
      wsRetry = 1000;
      $("#wsstate").classList.remove("off");
      $("#wstext").textContent = "CAPTURING";
    };
    ws.onmessage = function (m) {
      try {
        var ev = JSON.parse(m.data);
        if (!backfillDone) { wsBuffer.push(ev); return; }
        routeEvent(ev);
      } catch (e) {}
    };
    ws.onclose = function () {
      $("#wsstate").classList.add("off");
      $("#wstext").textContent = "RECONNECTING";
      setTimeout(connectWS, wsRetry);
      wsRetry = Math.min(wsRetry * 2, 15000);
    };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
  }
  connectWS();
})();
