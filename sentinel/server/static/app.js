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
    else if (currentTab === "devices") loadDevices();
    else if (currentTab === "logs") renderLogs();
    else if (currentTab === "radio") renderRadioLog();
    else if (currentTab === "network") { renderFlow(); renderDestTable(); }
    else if (currentTab === "appmgr") loadAppManager();
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
    alerts: ["Alerts & Rules", "What tripped, and the detections watching your device"],
    devices: ["Devices & ADB", "Every device ADB sees, their state, and connection controls"],
  };
  var currentTab = "monitor";
  function go(tab) {
    currentTab = tab;
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
    if (tab === "devices") loadDevices();
    if (tab === "appmgr") loadAppManager();
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
          '<div style="padding:0 15px 12px"><button class="btn p" data-backup2="' + esc(pkg) + '">extract this app (APK + data)</button></div>' +
          logs;
        var bb = $("#appstorage [data-backup2]");
        if (bb) bb.addEventListener("click", function () { startBackup(pkg); });
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

  function loadDevices() {
    fetch("/api/devices").then(function (r) { return r.json(); })
      .then(function (data) { populatePicker(data); renderDeviceList(data); })
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

  /* ================= app manager ================= */
  var amApps = [], amWhich = "all", amSel = null, amMeta = {}, amUser = null, amRows = {};
  var amDev = DEV, amPending = null;  // device the list belongs to; package to open after a reload
  var amHandlers = null, amHandlersKey = "";  // "Defaults on this device", cached per device + user
  var amAutoDone = {}, amResolveIv = null;
  function amUserLabel() {
    if (amUser === "all") return "all users";
    var id = amUser == null ? 0 : amUser, name = "";
    (amMeta.users || []).forEach(function (u) { if (u.id === id) name = u.name; });
    return "user " + id + (name ? " (" + name + ")" : "");
  }
  function loadAppManager(quiet) {
    if (amDev !== DEV) {  // device switched: user ids and the selection belong to the old one
      amDev = DEV; amUser = null; amSel = null; amHandlers = null;
      $("#am-dtitle").textContent = "App details";
      $("#am-dsub").textContent = "select an app";
    }
    if (!quiet) { $("#am-applist").innerHTML = '<div class="empty">loading apps…</div>'; amHandlers = null; }
    var url = "/api/appmanager/list?which=" + amWhich + (amUser != null ? "&user=" + amUser : "");
    fetch(dq(url)).then(function (r) { return r.json(); })
      .then(function (d) {
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
        renderAmList();
        if (amPending) {  // a "find anywhere" hit asked for this package once the list is in
          var p = amPending; amPending = null;
          if (amRows[p]) amSelect(p);
          else toast(shortApp(p) + " is not in this list", "warn", "try the uninstalled filter or All users");
        }
        if (!amSel) loadAmDefaults();
        maybeAutoResolve(d);
      })
      .catch(function () { $("#am-applist").innerHTML = '<div class="empty">could not load apps</div>'; });
  }
  $("#am-user").addEventListener("change", function () {
    amUser = this.value === "all" ? "all" : parseInt(this.value, 10);
    loadAppManager();
  });
  function renderAmList() {
    var q = ($("#am-search").value || "").trim().toLowerCase();
    var multi = (amMeta.users || []).length > 1;
    var rows = amApps.filter(function (a) {
      if (!q) return true;
      return a.package.toLowerCase().indexOf(q) >= 0 ||
        (a.label || "").toLowerCase().indexOf(q) >= 0;
    });
    $("#am-applist").innerHTML = rows.map(function (a) {
      var name = a.label || shortApp(a.package);
      var init = name.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?";
      var nm = a.label_source === "guess"
        ? ' class="am-nm guess" title="name guessed from the package id - press Resolve names for the real one"'
        : a.label_source === "apk" ? ' class="am-nm" title="name read from the APK"' : ' class="am-nm"';
      var ui = a.users_installed || [];
      return '<div class="am-row" data-pkg="' + esc(a.package) + '">' +
        '<div class="ai"' + (a.system ? ' style="background:var(--fg-mut)"' : "") + ">" + esc(init) + "</div>" +
        '<div class="am-meta"><div' + nm + ">" + esc(name) +
        (a.system ? ' <span class="pill mut">system</span>' : "") +
        (amUser === "all" && multi && ui.length
          ? ' <span class="pill mut" title="Android users this package is installed for">' +
            (ui.length > 1 ? "users " : "user ") + esc(ui.join(", ")) + "</span>" : "") +
        (a.installed === false ? ' <span class="pill crit" title="Removed for this user (debloated); still on the device">not installed</span>' : "") +
        (!a.enabled && a.installed !== false ? ' <span class="pill warn">disabled</span>' : "") +
        (a.godmode ? ' <span class="pill crit">god-mode</span>' : "") + "</div>" +
        '<div class="am-pk">' + esc(a.package) + "</div></div>" +
        (a.data_size ? '<span class="fsz">' + fmtBytes(a.data_size) + "</span>" : "") + "</div>";
    }).join("") || (q ? amFindPrompt(q) : '<div class="empty">no apps</div>');
    if (amSel) {
      var s = $('#am-applist .am-row[data-pkg="' + CSS.escape(amSel) + '"]');
      if (s) s.classList.add("sel");
    }
    applyGlobalSearch();
  }
  // one delegated handler for the list: app rows, and the "find anywhere" block that replaces them
  $("#am-applist").addEventListener("click", function (e) {
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
  $("#am-search").addEventListener("input", renderAmList);
  $("#am-search").addEventListener("keydown", function (e) {  // Enter with no match = search everywhere
    if (e.key === "Enter" && $("#am-find-btn")) amFind();
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
      if (!auto) toast("Resolving " + res.packages + " app names", "good");
      var ticks = 0;
      if (amResolveIv) clearInterval(amResolveIv);
      amResolveIv = setInterval(function () {
        if (currentTab === "appmgr") loadAppManager(true);
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
    } catch (e) { /* storage may be blocked */ }
    startResolve(true);
  }
  $$("#am-filter button").forEach(function (b) {
    b.addEventListener("click", function () {
      $$("#am-filter button").forEach(function (x) { x.classList.remove("on"); });
      b.classList.add("on");
      amWhich = b.dataset.which;
      loadAppManager();
    });
  });

  function loadAmDetail(pkg) {
    amSel = pkg;
    $("#am-dtitle").textContent = (amRows[pkg] || {}).label || shortApp(pkg);
    $("#am-dsub").textContent = pkg;
    $("#am-dbody").innerHTML = '<div class="empty">reading ' + esc(pkg) + " …</div>";
    fetch(dq("/api/appmanager/app/" + encodeURIComponent(pkg))).then(function (r) { return r.json(); })
      .then(renderAmDetail).catch(function () {
        $("#am-dbody").innerHTML = '<div class="empty">could not read this app</div>';
      });
  }

  var DESTRUCTIVE_AM = { disable: 1, "clear-data": 1, uninstall: 1 };
  function amAction(action, params) {
    var destructive = !!DESTRUCTIVE_AM[action];
    if (destructive && typeof confirm === "function" &&
        !confirm("This will " + action.replace("-", " ") + " " +
          shortApp(params.package) + " on the device. Continue?")) return;
    var row = amRows[params.package] || {};
    var user = typeof amUser === "number" ? amUser
      : ((row.users_installed && row.users_installed[0]) || 0);  // all-users mode: act where it lives
    var body = Object.assign({ device: DEV, confirm: destructive, user: user }, params, { action: action });
    fetch("/api/appmanager/action", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then(function (r) { return r.json(); }).then(function (res) {
      toast((res.ok ? "" : "Failed: ") + action + " — " + (res.output || "").split("\n")[0],
            res.ok ? "good" : "warn");
      setTimeout(function () { if (amSel) loadAmDetail(amSel); }, 600);
    }).catch(function () { toast("action failed", "crit"); });
  }
  // one delegated handler for the detail pane: package links and all action buttons
  $("#am-dbody").addEventListener("click", function (e) {
    var l = e.target.closest(".am-link");
    if (l) { amJump(l.dataset.pkg); return; }
    var b = e.target.closest("[data-act]");
    if (!b) return;
    amAction(b.dataset.act, {
      package: b.dataset.pkg, permission: b.dataset.perm, op: b.dataset.op, mode: b.dataset.mode,
    });
  });

  function renderAmDetail(d) {
    var det = d.detail || {};
    var pkg = d.package;
    var gy = function (k, v) { return v == null || v === "" ? "" : "<dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd>"; };
    var meta = d.meta || {}, ui = d.users_installed || [];  // meta: WebAPK manifest (host browser, start URL)
    var host = meta.host_browser;
    var ident = '<div class="am-sec"><h4>Identity</h4><dl class="kv2" style="padding:0">' +
      gy("package", pkg) + gy("version", (det.version_name || "?") + " (" + (det.version || "?") + ")") +
      gy("type", det.system ? "system" : "user app") +
      gy("enabled", det.enabled ? "yes" : "no — disabled") +
      gy("installed for", ui.length ? ui.map(function (u) { return "user " + u; }).join(", ") : null) +
      gy("installer", det.installer || "unknown") +
      gy("web app URL", meta.start_url) + gy("scope", meta.scope) +
      gy("opened by", host ? ((amRows[host] || {}).label || shortApp(host)) + " (" + host + ")" : null) +
      gy("target SDK", det.target_sdk) + gy("min SDK", det.min_sdk) + gy("ABI", det.abi) +
      gy("installed", det.first_install) + gy("updated", det.last_update) +
      gy("data dir", det.data_dir) + gy("signature", det.sig) +
      "</dl></div>";

    var ap = ' data-pkg="' + esc(pkg) + '"';
    var row = amRows[pkg] || {};
    var actions = '<div class="am-actions">' +
      (row.installed === false
        ? '<button class="btn p" data-act="reinstall"' + ap +
          ' title="Reinstall for this user from the copy still on the device">Reinstall</button>'
        : "") +
      (det.enabled
        ? '<button class="btn danger" data-act="disable"' + ap + ">Disable</button>"
        : '<button class="btn" data-act="enable"' + ap + ">Enable</button>") +
      '<button class="btn" data-act="force-stop"' + ap + ">Force stop</button>" +
      '<button class="btn" data-act="clear-cache"' + ap + ">Clear cache</button>" +
      '<button class="btn danger" data-act="clear-data"' + ap + ">Clear data</button>" +
      '<button class="btn danger" data-act="uninstall"' + ap + ">Uninstall</button>" +
      "</div>";

    var granted = det.granted || [], requested = det.requested || [];
    var gset = {};
    granted.forEach(function (p) { gset[p] = 1; });
    var perms = '<div class="am-sec"><h4>Permissions (' + granted.length + " of " + requested.length + " granted)</h4>" +
      (requested.length ? requested.map(function (p) {
        var on = gset[p];
        var danger = DANGEROUS.indexOf(p.split(".").pop()) >= 0;
        return '<div class="permrow"><span class="pn' + (danger ? '" style="color:var(--crit)' : "") + '">' +
          esc(p.replace("android.permission.", "")) + "</span>" +
          '<span class="pill ' + (on ? "good" : "mut") + '">' + (on ? "granted" : "denied") + "</span>" +
          '<button class="btn" data-act="' + (on ? "revoke" : "grant") +
          '" data-pkg="' + esc(pkg) + '" data-perm="' + esc(p) + '">' +
          (on ? "revoke" : "grant") + "</button></div>";
      }).join("") : '<div class="empty">no permissions declared</div>') + "</div>";

    var ops = d.appops || [];
    var opsec = '<div class="am-sec"><h4>App-ops activity</h4>' +
      (ops.length ? '<div class="opchips">' + ops.map(function (o) {
        return '<span class="pill ' + (o.background ? "crit" : "good") + '">' + esc(o.op) +
          (o.background ? " · bg" : "") + "</span>";
      }).join("") + "</div>" : '<div class="empty" style="padding:6px 0">no recent sensor/op access recorded</div>') + "</div>";

    var dc = det.disabled_components || [], ec = det.enabled_components || [];
    var comps = (dc.length || ec.length)
      ? '<div class="am-sec"><h4>Component overrides</h4>' +
        dc.map(function (c) { return '<span class="comp off" title="disabled">' + esc(c.split(".").pop()) + "</span>"; }).join("") +
        ec.map(function (c) { return '<span class="comp" title="force-enabled">' + esc(c.split(".").pop()) + "</span>"; }).join("") +
        "</div>"
      : "";

    var godsec = (d.godmode && d.godmode.length)
      ? '<div class="am-sec"><h4>God-mode access</h4>' +
        d.godmode.map(function (g) { return '<span class="pill crit">' + esc(g) + "</span> "; }).join("") + "</div>"
      : "";

    $("#am-dbody").innerHTML = actions + ident + godsec + perms + opsec + comps;
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
    if (!matches.length && !dirs.length) {
      h += '<p class="verdict">Nothing named &ldquo;' + esc(q) + "&rdquo; exists on this device for any user. " +
        "It simply is not installed on this ROM (custom ROMs often ship without Chrome or Google Photos, " +
        "for example) and a different app is filling the role - see the browsers above. " +
        "Install it from the Play Store or sideload an APK from the Files tab.</p>";
    }
    box.innerHTML = h;
  }
  // a hit for another user: switch the picker there, drop filters that could hide it, reload, then open it
  function amOpenFound(pkg, user) {
    if (user !== "" && amUser !== "all" && parseInt(user, 10) !== amUser) {
      amUser = parseInt(user, 10);
      $("#am-user").value = String(amUser);
    }
    if (amWhich !== "all") {
      amWhich = "all";
      $$("#am-filter button").forEach(function (x) { x.classList.toggle("on", x.dataset.which === "all"); });
    }
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
        (r[2] && hs[r[2]] && hs[r[2]][0] ? hs[r[2]][0].package : null);
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
    $("#am-dbody").innerHTML = '<div class="am-sec am-defaults"><h4>Defaults on this device' +
      (h.user != null ? " · user " + esc(h.user) : "") + "</h4>" +
      (h.error ? '<div class="hint">' + esc(h.error) + "</div>" : rows + chips) +
      '<div class="hint">Role holders from the system role manager; click a name to open that app.</div></div>' +
      '<div class="empty">Pick an app on the left to see its permissions, components, app-ops, signature and storage, and to manage it.</div>';
  }

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
    if (ev.kind === "app.backup" && currentTab === "storage") loadBackups();
  }

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
