/* Android Sentinel dashboard — live wiring to /ws + REST. Vanilla JS, no deps. */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

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
    logs: ["Logcat", "System log attributed to the owning app"],
    radio: ["Cellular & Radio", "Telephony state, serving cell and the radio log"],
    alerts: ["Alerts & Rules", "What tripped, and the detections watching your device"],
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
      esc((ev.data || {}).transport || "") + '">' +
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
      $$("#feed-net .ev").forEach(function (row) {
        row.style.display = (curTransport === "all" ||
          row.dataset.transport === curTransport) ? "" : "none";
      });
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
  setInterval(renderFlow, 5000);

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
  }
  function pollStatus() {
    fetch("/api/status").then(function (r) { return r.json(); })
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
  function loadApps() {
    fetch("/api/apps").then(function (r) { return r.json(); }).then(function (apps) {
      $("#t-apps").textContent = apps.length;
      var god = 0, side = 0;
      var h = apps.map(function (a) {
        if (a.godmode && a.godmode.length) god++;
        var sideloaded = !a.installer || a.installer.indexOf("vending") < 0;
        if (sideloaded) side++;
        var granted = (a.granted || []).map(function (p) { return p.split(".").pop(); });
        var hot = granted.filter(function (p) { return DANGEROUS.indexOf(p) >= 0; });
        var init = shortApp(a.package).slice(0, 2).toUpperCase();
        return '<div class="approw"><div class="appicon">' + esc(init) + "</div>" +
          '<div class="appmeta"><div class="nm">' + esc(shortApp(a.package)) +
          (a.godmode || []).map(function (g) { return ' <span class="pill crit">' + esc(g) + "</span>"; }).join("") +
          "</div>" +
          '<div class="pk">' + esc(a.package) + " · " +
          (sideloaded ? "sideloaded" : esc(a.installer)) +
          (a.version_name ? " · v" + esc(a.version_name) : "") + "</div>" +
          '<div class="chips">' +
          (a.mtx ? '<span class="pill">' + fmtBytes(a.mtx) + " cellular</span>" : "") +
          (a.tx ? '<span class="pill">' + fmtBytes(a.tx) + " total tx</span>" : "") +
          (sideloaded ? '<span class="pill warn">not Play</span>' : "") + "</div>" +
          (hot.length ? '<div class="perms">' + hot.map(function (p) {
            return '<span class="perm hot">' + esc(p) + "</span>";
          }).join("") + "</div>" : "") +
          "</div></div>";
      }).join("");
      $("#applist").innerHTML = h || '<div class="empty">no third-party apps found yet</div>';
      $("#t-god2").textContent = god;
      $("#t-side").textContent = side;
    }).catch(function () {});
  }

  /* ---------- alerts + rules ---------- */
  function loadAlerts() {
    fetch("/api/alerts?state=open").then(function (r) { return r.json(); }).then(function (alerts) {
      (alerts || []).forEach(function (a) {
        if (a.data && a.data.ip) alertedIPs[a.data.ip] = 1;
      });
      var h = (alerts || []).map(function (a) {
        return '<div class="alertrow"><div class="ic alert" style="width:30px;height:30px;flex:0 0 30px">' +
          icon("alert") + "</div>" +
          '<div class="ab"><div class="at">' + esc(a.title) +
          ' <span class="pill ' + (a.severity === "crit" ? "crit" : "warn") + '">' + esc(a.severity) + "</span></div>" +
          (a.detail ? '<div class="ad">' + esc(a.detail) + "</div>" : "") +
          '<div class="aa"><button class="btn p" data-ack="' + a.id + '">Acknowledge</button>' +
          '<button class="btn" data-mute="' + a.id + '">Mute</button>' +
          '<span style="margin-left:auto;font-size:11px;color:var(--fg-mut);font-family:var(--ff-mono)">' +
          fmtTime(a.ts) + "</span></div></div></div>";
      }).join("");
      $("#alertlist").innerHTML = h || '<div class="empty">no open alerts</div>';
      $("#monalerts").innerHTML = (alerts || []).slice(0, 5).map(function (a) {
        return '<div class="ev"><div class="ic alert">' + icon("alert") +
          '</div><div class="body"><div class="t1"><b>' + esc(a.title) +
          '</b></div><div class="t2">' + esc(a.detail || a.rule) + "</div></div>" +
          '<span class="pill ' + (a.severity === "crit" ? "crit" : "warn") + '">' +
          esc(a.severity) + "</span></div>";
      }).join("") || '<div class="empty">no open alerts</div>';
      $$("#alertlist [data-ack], #alertlist [data-mute]").forEach(function (b) {
        b.addEventListener("click", function () {
          var id = b.dataset.ack || b.dataset.mute;
          fetch("/api/alerts/" + id + "/state", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ state: b.dataset.ack ? "acked" : "muted" }),
          }).then(function () { loadAlerts(); pollStatus(); });
        });
      });
    }).catch(function () {});
  }
  function loadRules() {
    fetch("/api/rules").then(function (r) { return r.json(); }).then(function (rules) {
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
          });
        });
      });
    }).catch(function () {});
  }
  loadAlerts(); loadRules();
  setInterval(function () { if (currentTab === "alerts" || currentTab === "monitor") loadAlerts(); }, 20000);
  setInterval(function () {
    fetch("/api/netstats").then(function (r) { return r.json(); })
      .then(renderEgress).catch(function () {});
  }, 12000);
  fetch("/api/netstats").then(function (r) { return r.json(); }).then(renderEgress).catch(function () {});

  /* ---------- initial feed backfill ---------- */
  fetch("/api/events?limit=60").then(function (r) { return r.json(); }).then(function (evs) {
    (evs || []).reverse().forEach(routeEvent);
  }).catch(function () {});

  /* ---------- websocket ---------- */
  function routeEvent(ev) {
    var group = ev.kind.split(".")[0];
    if (ev.kind === "log.line") {
      var buf = (ev.data || {}).buffer;
      if (buf === "radio") {
        radioLogs.unshift(ev); radioLogs = radioLogs.slice(0, 300);
        if (currentTab === "radio") {
          $("#radiolog").innerHTML = radioLogs.map(logLineHTML).join("");
        }
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
      if (currentTab === "radio") $("#radiolog").innerHTML = radioLogs.map(logLineHTML).join("");
    }
    if (ev.kind === "alert") {
      if (ev.data && ev.data.ip) alertedIPs[ev.data.ip] = 1;
      loadAlerts(); pollStatus();
    }
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
      try { routeEvent(JSON.parse(m.data)); } catch (e) {}
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
