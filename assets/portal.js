/* Copia partner portal.
   Lead data ships encrypted (data/leads.enc.js). Signing in derives an AES key from
   "email:password" with PBKDF2 and decrypts it in the browser. Wrong credentials
   simply fail to decrypt, so nothing readable is in the public repo. */
(function () {
  "use strict";
  var CFG = window.COPIA_CONFIG || {};
  var ENC = window.COPIA_LEADS_ENC;
  var SESSION_KEY = "copia.session";
  var $ = function (id) { return document.getElementById(id); };

  // ---------- helpers ----------
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function b64ToBytes(b64) { var bin = atob(b64), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function bytesToB64(buf) { var a = new Uint8Array(buf), s = ""; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function store(k, v) { try { if (v === undefined) return JSON.parse(localStorage.getItem(k) || "null"); localStorage.setItem(k, JSON.stringify(v)); } catch (e) { return null; } }
  function sess(v) { try { if (v === undefined) return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null"); if (v === null) sessionStorage.removeItem(SESSION_KEY); else sessionStorage.setItem(SESSION_KEY, JSON.stringify(v)); } catch (e) { return null; } }
  var toastTimer;
  function toast(msg) { var t = $("toast"); t.textContent = msg; t.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(function () { t.hidden = true; }, 3200); }

  // ---------- crypto ----------
  function deriveKey(email, password) {
    var enc = new TextEncoder();
    return crypto.subtle.importKey("raw", enc.encode(email.trim().toLowerCase() + ":" + password), "PBKDF2", false, ["deriveKey"])
      .then(function (base) {
        return crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64ToBytes(ENC.salt), iterations: ENC.iter, hash: "SHA-256" },
          base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
      });
  }
  function decryptWith(key) {
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(ENC.iv) }, key, b64ToBytes(ENC.data))
      .then(function (buf) { return JSON.parse(new TextDecoder().decode(buf)); });
  }
  function importRaw(b64) { return crypto.subtle.importKey("raw", b64ToBytes(b64), { name: "AES-GCM" }, true, ["decrypt"]); }

  // ---------- state ----------
  var S = {
    email: "", leads: [], tab: "all", sector: "all", seat: "any", state: "", min: 0,
    sort: "opp", hideStale: false, namedOnly: false, researchedOnly: false, status: "any", q: "", sel: null,
    watch: {}, req: {}
  };
  var SECTORS = [["all", "All"], ["Student Housing", "Student housing"], ["Multifamily", "Multifamily"], ["Senior Living", "Senior living"], ["other", "Other"]];
  var STATUSES = [["any", "Any"], ["stable", "Stabilized"], ["leaseup", "Lease-up or rehab"]];
  function leaseUp(l) { var st = l.research && l.research.status; if (st) return st === "lease-up" || st === "rehab"; return !!l.recentIssue; }
  var SEATS = [["any", "Any"], ["open", "Opening soon"], ["rfp", "RFP noticed"], ["expiring", "Expiring or holdover"], ["unknown", "Not disclosed"]];

  function seatGroup(w) {
    if (w === "Change/RFP noticed") return "rfp";
    if (w === "Expired / holdover?") return "holdover";
    if (w === "0-6 mo" || w === "6-12 mo" || w === "12-24 mo") return "expiring";
    if (w === "24+ mo") return "later";
    return "unknown";
  }
  var SEAT_LABEL = { "Change/RFP noticed": "Change / RFP noticed", "Expired / holdover?": "Holdover", "0-6 mo": "Expires in 0–6 mo", "6-12 mo": "Expires in 6–12 mo", "12-24 mo": "Expires in 12–24 mo", "24+ mo": "Expires in 24+ mo" };
  function isOpening(l) { var g = seatGroup(l.window); return g === "rfp" || g === "holdover" || g === "expiring"; }
  function sizeNum(l) { if (!l.size) return 0; var m = l.size.replace(/,/g, "").match(/\d+/); return m ? parseInt(m[0], 10) : 0; }

  function filtered() {
    var q = S.q.trim().toLowerCase();
    var list = S.leads.filter(function (l) {
      if (S.tab === "watch" && !S.watch[l.id]) return false;
      if (S.tab === "req" && !S.req[l.id]) return false;
      if (S.sector === "other" && ["Student Housing", "Multifamily", "Senior Living"].indexOf(l.sector) >= 0) return false;
      if (S.sector !== "all" && S.sector !== "other" && l.sector !== S.sector) return false;
      var g = seatGroup(l.window);
      if (S.seat === "open" && !isOpening(l)) return false;
      if (S.seat === "rfp" && g !== "rfp") return false;
      if (S.seat === "expiring" && g !== "expiring" && g !== "holdover") return false;
      if (S.seat === "unknown" && g !== "unknown") return false;
      if (S.state && l.state !== S.state) return false;
      if (l.opp < S.min) return false;
      if (S.hideStale && l.stale) return false;
      if (S.namedOnly && l.generic) return false;
      if (S.researchedOnly && !l.research) return false;
      if (S.status === "stable" && leaseUp(l)) return false;
      if (S.status === "leaseup" && !leaseUp(l)) return false;
      if (q) {
        var r = l.research || {};
        var hay = [l.name, l.state, l.sector, l.mgr, l.issuer, l.region, l.borrower, r.owner, r.ownerParent, r.address, r.manager, l.cusips, l.contact && l.contact.name].join(" ").toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });
    var by = {
      opp: function (a, b) { return b.opp - a.opp || a.perf - b.perf; },
      perf: function (a, b) { return a.perf - b.perf; },
      gap: function (a, b) { return (a.occVs == null ? 1e9 : a.occVs) - (b.occVs == null ? 1e9 : b.occVs); },
      expiry: function (a, b) {
        var k = function (l) { var g = seatGroup(l.window); if (g === "holdover") return -2; if (g === "rfp") return -1; return l.months == null ? 1e9 : l.months; };
        return k(a) - k(b) || b.opp - a.opp;
      },
      size: function (a, b) { return sizeNum(b) - sizeNum(a); },
      occ: function (a, b) { return a.occ - b.occ; }
    };
    return list.sort(by[S.sort] || by.opp);
  }

  // ---------- formatting ----------
  function fOcc(v) { return v == null ? "—" : v.toFixed(1) + "%"; }
  function fVs(v, unit) { return v == null ? "—" : (v > 0 ? "+" : "") + v.toFixed(1) + (unit === false ? "" : " pts"); }
  function vsColor(v) { return v == null ? "var(--muted)" : v < -10 ? "var(--red)" : v < 0 ? "var(--amber)" : "var(--mint)"; }
  function shortDate(d) { if (!d) return ""; var p = d.split("-"); var m = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][+p[1] - 1]; return m ? m + " " + p[0].slice(2) : d; }
  function money(v) { return v == null ? "—" : "$" + Math.round(v).toLocaleString(); }
  function fPct(v) { return v == null ? "—" : (v > 0 ? "+" : "") + v.toFixed(1) + "%"; }
  function scoreColor(o) { return o >= 80 ? "#3DDC97" : o >= 60 ? "#9BE3C0" : o >= 40 ? "#F5B454" : "#93A89E"; }
  function ring(o, size) {
    var r = size / 2 - 5, c = 2 * Math.PI * r, d = (c * o / 100).toFixed(1);
    return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + " " + size + '" role="img" aria-label="Opportunity score ' + o + '">' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="#1E3229" stroke-width="4"/>' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + scoreColor(o) + '" stroke-width="4" stroke-linecap="round" stroke-dasharray="' + d + " " + c.toFixed(1) + '" transform="rotate(-90 ' + size / 2 + " " + size / 2 + ')"/>' +
      '<text x="50%" y="50%" dy=".35em" text-anchor="middle" font-family="Geist Mono, ui-monospace, monospace" font-size="' + (size > 54 ? 15 : 14) + '" fill="#fff">' + o + "</text></svg>";
  }
  function mgrOf(l) { return l.mgr || (l.research && l.research.manager && !/^Not confirmed/.test(l.research.manager) ? l.research.manager : "Not disclosed"); }
  function meta(l) { return [l.sector, l.state, l.size, l.generic && l.issuer ? (l.issuer.length > 56 ? l.issuer.slice(0, 55) + "…" : l.issuer) : null].filter(Boolean).join(" · "); }
  var STAR = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z"/></svg>';

  // ---------- rendering ----------
  function renderChips(id, items, cur, key) {
    $(id).innerHTML = items.map(function (it) {
      return '<button type="button" class="chip" data-key="' + key + '" data-val="' + esc(it[0]) + '" aria-pressed="' + (cur === it[0]) + '">' + esc(it[1]) + "</button>";
    }).join("");
  }

  function render() {
    var list = filtered();
    renderChips("f-sector", SECTORS, S.sector, "sector");
    renderChips("f-seat", SEATS, S.seat, "seat");
    renderChips("f-status", STATUSES, S.status, "status");
    document.querySelectorAll(".tab").forEach(function (t) { t.setAttribute("aria-selected", String(t.dataset.tab === S.tab)); });
    $("ct-all").textContent = S.leads.length;
    $("ct-watch").textContent = Object.keys(S.watch).length;
    $("ct-req").textContent = Object.keys(S.req).length;

    $("k-count").textContent = list.length;
    $("k-avg").textContent = list.length ? Math.round(list.reduce(function (t, l) { return t + l.opp; }, 0) / list.length) : 0;
    $("k-open").textContent = list.filter(isOpening).length;
    $("k-units").textContent = list.filter(function (l) { return l.research; }).length;
    var act = (S.sector !== "all") + (S.seat !== "any") + (S.status !== "any") + !!S.state + (S.min > 0) + S.hideStale + S.namedOnly + S.researchedOnly;
    $("f-active").textContent = act ? act + " active" : "";
    $("list-summary").textContent = list.length + " of " + S.leads.length + " leads";

    $("rows").innerHTML = list.map(function (l) {
      var badges = "";
      if (SEAT_LABEL[l.window]) badges += '<span class="badge amber">' + esc(SEAT_LABEL[l.window]) + "</span>";
      if (l.distressed) badges += '<span class="badge red">Distressed</span>';
      if (l.stale) badges += '<span class="badge outline">Data &gt;2y</span>';
      if (l.research) badges += '<span class="badge mint-o">Owner researched</span>';
      if (l.research && (l.research.status === "lease-up" || l.research.status === "rehab")) badges += '<span class="badge outline">' + (l.research.status === "rehab" ? "Rehab" : "Lease-up") + "</span>";
      else if (!l.research && l.recentIssue) badges += '<span class="badge outline">New issue 2023+</span>';
      if (l.failureToFile) badges += '<span class="badge red">Missed filing</span>';
      if (S.req[l.id]) badges += '<span class="badge mint">Intro requested</span>';
      return '<div class="row" role="button" tabindex="0" data-id="' + l.id + '" aria-current="' + (S.sel === l.id) + '">' +
        ring(l.opp, 58) +
        '<div class="row-main"><div class="row-title"><b class="' + (l.generic ? "dim" : "") + '">' + esc(l.name) + "</b>" + badges + '</div><span class="meta">' + esc(meta(l)) + "</span></div>" +
        '<div class="metrics">' +
          '<div class="metric"><span>Occ. ' + esc(shortDate(l.occAsof)) + '</span><b class="num">' + fOcc(l.occ) + "</b></div>" +
          '<div class="metric"><span>vs. peers (pts)</span><b class="num" style="color:' + vsColor(l.occVs) + '">' + fVs(l.occVs, false) + "</b></div>" +
          '<div class="metric"><span>Manager</span><b class="txt" title="' + esc(mgrOf(l)) + '">' + esc(mgrOf(l)) + "</b></div>" +
        "</div>" +
        '<button type="button" class="star" data-star="' + l.id + '" aria-pressed="' + !!S.watch[l.id] + '" aria-label="' + (S.watch[l.id] ? "Remove from" : "Add to") + ' watchlist">' + STAR + "</button>" +
      "</div>";
    }).join("");

    var empty = $("empty");
    if (!list.length) {
      empty.hidden = false;
      empty.innerHTML = S.tab === "watch" ? "<span>Your watchlist is empty. Star a lead to keep it here.</span>" :
        S.tab === "req" ? "<span>No introductions requested yet. Open a lead and choose “Request introduction”.</span>" :
        '<span>No leads match these filters.</span><button type="button" class="btn" data-reset>Reset filters</button>';
    } else empty.hidden = true;

    renderDetail();
  }

  function section(title, body, open) {
    if (!body) return "";
    return '<details class="sec"' + (open ? " open" : "") + '><summary>' + esc(title) + "</summary><div class=\"sec-body\">" + body + "</div></details>";
  }
  function kv(rows) {
    rows = rows.filter(function (r) { return r[1] != null && r[1] !== "" && r[1] !== "—"; });
    if (!rows.length) return "";
    return '<dl class="kv">' + rows.map(function (r) { return "<div><dt>" + esc(r[0]) + "</dt><dd>" + (r[2] ? r[1] : esc(r[1])) + "</dd></div>"; }).join("") + "</dl>";
  }
  function link(href, label) { return href ? '<a href="' + esc(href) + '" target="_blank" rel="noopener">' + esc(label || "Open") + "</a>" : ""; }
  function host(u) { try { return new URL(u).hostname.replace(/^www\./, ""); } catch (e) { return "source"; } }
  function personCard(p) {
    var lines = ['<b>' + esc(p.name || p.org || "") + "</b>"];
    var sub = [p.title, p.name ? p.org : null].filter(Boolean).join(" · ");
    if (sub) lines.push('<span class="meta">' + esc(sub) + "</span>");
    if (p.email) lines.push('<a href="mailto:' + esc(p.email) + '">' + esc(p.email) + "</a>");
    if (p.phone) lines.push('<a href="tel:' + esc(p.phone.replace(/[^\d+]/g, "")) + '">' + esc(p.phone) + "</a>");
    if (p.info) lines.push(/@/.test(p.info) ? p.info.split(/;\s*/).map(function (x) { return /@/.test(x) ? '<a href="mailto:' + esc(x.trim()) + '">' + esc(x.trim()) + "</a>" : esc(x); }).join(" · ") : esc(p.info));
    if (p.emailNote) lines.push('<span class="meta">' + esc(p.emailNote) + "</span>");
    return '<div class="person">' + lines.join("") + "</div>";
  }

  function renderDetail() {
    var d = $("detail"), l = S.leads.find(function (x) { return x.id === S.sel; });
    var overlay = window.matchMedia("(max-width: 1180px)").matches;
    $("detail-ph").hidden = !!l;
    $("backdrop").hidden = !(l && overlay);
    if (!l) { d.hidden = true; d.innerHTML = ""; return; }
    d.hidden = false;
    var r = l.research || null, m = l.mgmt || {}, oi = l.occInfo || {};
    var requested = !!S.req[l.id];

    // status banner
    var banner = "";
    if (r && r.statusNote) banner = '<div class="note-box ' + (r.status === "stabilized" || r.status === "stabilizing" ? "hot" : "") + '"><b>' + esc({ "lease-up": "In lease-up", rehab: "Under rehab", stabilized: "Stabilized property", stabilizing: "Should be stabilized" }[r.status] || "Status") + "</b>" + esc(r.statusNote) + "</div>";
    else if (l.recentIssue) banner = '<div class="note-box"><b>Recent bond issue</b>Financed or refinanced in 2023 or later; low occupancy may reflect a lease-up or rehab. Confirm before outreach.</div>';
    if (l.failureToFile) banner += '<div class="note-box warn"><b>Missed disclosure</b>EMMA shows a failure-to-file notice for this issue.</div>';

    // owner & contacts
    var owner = "";
    if (r) {
      owner += kv([["Owner", r.owner], ["Parent / sponsor", r.ownerParent], ["Owner address", r.ownerAddress],
        ["Owner phone", r.ownerPhone ? '<a href="tel:' + esc(r.ownerPhone.replace(/[^\d+]/g, "")) + '">' + esc(r.ownerPhone) + "</a>" : null, true],
        ["Website", r.website ? link(r.website, host(r.website)) : null, true], ["Property address", r.address],
        ["Property phone", r.propertyPhone], ["Manager", r.manager]]);
      if (r.contacts && r.contacts.length) owner += '<div class="people">' + r.contacts.map(personCard).join("") + "</div>";
      if (r.sources && r.sources.length) owner += '<p class="srcs">Sources: ' + r.sources.map(function (u) { return link(u, host(u)); }).join(" · ") + "</p>";
    }
    var filingPeople = [];
    if (l.contact && (l.contact.name || l.contact.info)) filingPeople.push({ name: l.contact.name, title: [l.contact.title, l.contact.role].filter(Boolean).join(", "), org: l.contact.org, info: l.contact.info });
    Object.keys(l.stakeholders || {}).forEach(function (grp) { l.stakeholders[grp].forEach(function (p) { filingPeople.push({ name: p.name, title: p.title + " · " + grp, org: p.org }); }); });
    if (filingPeople.length) owner += '<h4>Named in bond filings</h4><div class="people">' + filingPeople.slice(0, 8).map(personCard).join("") + "</div>" + (l.contact && l.contact.source ? '<p class="srcs">' + link(l.contact.source, "Source filing") + "</p>" : "");
    if (l.borrower) owner = kv([["Borrower (per filing)", l.borrower]]) + owner;
    if (!owner) owner = '<p class="meta">No owner contact identified in the filings yet.</p>';

    // occupancy & performance
    var occ = kv([["Occupancy", fOcc(l.occ) + (l.occAsof ? " as of " + l.occAsof : "")], ["Basis", oi.basis], ["vs. peer median", l.occVs != null ? fVs(l.occVs) : null],
      ["Peer percentile", l.occPctl != null ? l.occPctl + "th" : null], ["Physical occupancy", l.physOcc != null && l.physOcc !== l.occ ? fOcc(l.physOcc) : null], ["Sense check", l.senseCheck]]);
    if (oi.quote) occ += '<blockquote class="quote">…' + esc(oi.quote) + '…</blockquote><p class="srcs">' + link(oi.link, "Filing" + (oi.page ? ", page " + oi.page : "")) + "</p>";
    var rent = l.rent && Object.keys(l.rent).length ? kv([["Potential rent", money(l.rent.potential)], ["Vacancy loss", money(l.rent.vacancyLoss)],
      ["Concessions", l.rent.concessions != null ? money(l.rent.concessions) : null], ["Net rent", money(l.rent.netRent)], ["Total revenue", money(l.rent.totalRevenue)],
      ["Vacancy loss, % of potential rent", l.rent.vacancyPctPotential != null ? l.rent.vacancyPctPotential + "%" : null], ["Figures as of", l.rentAsof],
      ["Source", l.rentSource ? link(l.rentSource, "Filing") : null, true]]) : "";
    var kp = l.kpis && l.kpis.length ? '<table class="tbl"><thead><tr><th>KPI</th><th>Value</th><th>vs. peers</th><th>Pctl</th><th>As of</th></tr></thead><tbody>' +
      l.kpis.map(function (k) { return "<tr><td>" + esc(k.k) + '</td><td class="num">' + k.v.toLocaleString() + '</td><td class="num">' + (k.vs == null ? "—" : (k.vs > 0 ? "+" : "") + k.vs.toLocaleString()) + '</td><td class="num">' + (k.pctl == null ? "—" : k.pctl) + "</td><td>" + esc(k.asof || "—") + "</td></tr>"; }).join("") +
      "</tbody></table>" + kv([["KPIs scored", l.kpiCount], ["Data completeness", l.complete != null ? l.complete + "%" : null], ["Latest annual report", l.latestAnnual], ["Latest report of any kind", l.latestReport],
        ["Budget underspend", l.underspend], ["Capex status", l.capex], ["HUD inspection", l.hud], ["HUD match", l.hudProperty], ["Distress flags", l.distressFlags]]) : "";

    // management agreement
    var mg = kv([["Current manager", mgrOf(l)], ["Agreement status", SEAT_LABEL[l.window] || "Not disclosed"], ["Next renewal / expiry", m.nextRenewal],
      ["Months to expiry", m.monthsToExpiry], ["Expiry basis", m.expiryBasis], ["Agreement date", m.agreementDate], ["Commencement", m.commencement],
      ["Initial term", m.initialTermYrs != null ? m.initialTermYrs + " years" : null], ["Last renewal / amendment", m.lastRenewal], ["Stated expiration", m.statedExpiration],
      ["Auto-renewal", m.autoRenewal], ["Termination rights", m.termination], ["Trustee / bondholder replacement rights", m.trusteeReplace],
      ["Management fee", m.feePct != null ? m.feePct + "%" : null], ["Manager change / RFP notice", m.rfpNotice]]);
    if (l.mgrQuote) mg += '<blockquote class="quote">…' + esc(l.mgrQuote) + "…</blockquote>" + (l.mgrLink ? '<p class="srcs">' + link(l.mgrLink, "Manager source") + "</p>" : "");
    if (m.quote && m.quote !== l.mgrQuote) mg += '<blockquote class="quote">…' + esc(m.quote) + "…</blockquote>" + (m.quoteLink ? '<p class="srcs">' + link(m.quoteLink, "Agreement source") + "</p>" : "");

    // EMMA
    var em = kv([["Issuer", l.issuer], ["CUSIPs", l.cusips], ["Documents on file", l.docCount], ["EMMA issue page", l.emma ? link(l.emma, "Open on EMMA") : null, true]]);
    if (l.docs && l.docs.length) em += '<ul class="docs">' + l.docs.map(function (x) {
      return '<li><span class="num">' + esc(x.date || "—") + '</span><span class="dt">' + esc((x.type || "").replace(/_/g, " ")) + "</span>" + (x.link ? '<a href="' + esc(x.link) + '" target="_blank" rel="noopener">' + esc(x.title || "Document") + "</a>" : esc(x.title || "")) + "</li>";
    }).join("") + "</ul>";

    d.innerHTML =
      '<div class="d-head"><div style="min-width:0"><span class="d-kicker">' + esc(l.sector) + " · " + esc(l.state || "") + (l.region ? " · " + esc(l.region) : "") + '</span><h2 id="d-title">' + esc(l.name) + '</h2><span class="meta">' + esc([r && r.address, l.size].filter(Boolean).join(" · ") || "Size not disclosed") + "</span></div>" +
      '<button type="button" class="icon-btn" data-close aria-label="Close lead detail"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div>' +
      banner +
      '<div class="tiles">' +
        '<div class="tile"><span>Opportunity</span><b class="m">' + l.opp + '</b><div class="bar"><i style="width:' + l.opp + '%"></i></div></div>' +
        '<div class="tile"><span>Performance vs. peers</span><b>' + (l.perf != null ? l.perf.toFixed(0) : "—") + '<small style="color:var(--muted)"> /100</small></b><div class="bar"><i style="width:' + (l.perf || 0) + '%;background:#93A89E"></i></div></div>' +
        '<div class="tile"><span>Occupancy · ' + esc(l.occAsof || "") + '</span><b>' + fOcc(l.occ) + '</b><small style="color:' + vsColor(l.occVs) + '">' + (l.occVs != null ? fVs(l.occVs) + " vs. peers" : "&nbsp;") + "</small></div>" +
        '<div class="tile"><span>DSCR' + (l.dscrCovenant != null ? " (covenant " + l.dscrCovenant.toFixed(2) + "x)" : "") + '</span><b>' + (l.dscr != null ? l.dscr.toFixed(2) + "x" : "—") + '</b><small style="color:var(--muted)">' + (l.daysCash != null ? l.daysCash + " days cash" : "&nbsp;") + "</small></div>" +
      "</div>" +
      '<div class="d-actions">' +
        (requested
          ? '<div class="ok" role="status"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3DDC97" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="flex:none;margin-top:2px"><path d="M5 12l5 5L19 7"/></svg><div><b>Introduction requested</b>Requested ' + esc(S.req[l.id]) + ".</div></div>" +
            '<button type="button" class="btn" data-withdraw="' + l.id + '">Withdraw request</button>'
          : '<button type="button" class="btn btn-mint" data-request="' + l.id + '">Request introduction</button>') +
        '<div class="row2"><button type="button" class="btn" data-star="' + l.id + '" aria-pressed="' + !!S.watch[l.id] + '">' + (S.watch[l.id] ? "Remove from watchlist" : "Add to watchlist") + "</button>" +
        (l.emma ? '<a class="btn" href="' + esc(l.emma) + '" target="_blank" rel="noopener">Open on EMMA</a>' : "") + "</div>" +
      "</div>" +
      section("Owner & contacts" + (r ? " (researched)" : ""), owner, true) +
      section("Occupancy evidence", occ, true) +
      section("Rent roll", rent, false) +
      section("KPIs vs. peers", kp, false) +
      section("Management agreement", mg, false) +
      section("EMMA filings (" + (l.docs ? l.docs.length : 0) + ")", em, false);
  }

  // ---------- actions ----------
  function persist() { store("copia.watch." + S.email, S.watch); store("copia.req." + S.email, S.req); }
  function toggleWatch(id) {
    if (S.watch[id]) { delete S.watch[id]; toast("Removed from watchlist"); } else { S.watch[id] = 1; toast("Added to watchlist"); }
    persist(); render();
  }
  function requestIntro(id) {
    var l = S.leads.find(function (x) { return x.id === id; }); if (!l) return;
    S.req[id] = new Date().toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
    persist(); render(); toast("Introduction requested");
    if (CFG.contactEmail) {
      var body = "Partner: " + S.email + "\n\nPlease make an introduction for:\n" + l.name + "\n" + meta(l) +
        "\nOpportunity score: " + l.opp + "\nCurrent manager: " + mgrOf(l) + (l.research && l.research.owner ? "\nOwner: " + l.research.owner : "") + "\nAgreement status: " + (SEAT_LABEL[l.window] || "Not disclosed") +
        (l.emma ? "\nEMMA: " + l.emma : "") + "\n\nLead #" + l.id;
      var a = document.createElement("a");
      a.href = "mailto:" + CFG.contactEmail + "?subject=" + encodeURIComponent("Intro request: " + l.name) + "&body=" + encodeURIComponent(body);
      a.click();
    }
  }
  function withdraw(id) { delete S.req[id]; persist(); render(); toast("Request withdrawn"); }
  function select(id) {
    S.sel = S.sel === id ? null : id; render();
    if (S.sel != null && window.matchMedia("(max-width: 1180px)").matches) $("detail").focus();
  }
  function resetFilters() {
    Object.assign(S, { sector: "all", seat: "any", status: "any", state: "", min: 0, sort: "opp", hideStale: false, namedOnly: false, researchedOnly: false, q: "" });
    $("q").value = ""; $("f-state").value = ""; $("f-min").value = 0; $("f-min-out").textContent = "0"; $("f-sort").value = "opp";
    $("f-stale").checked = $("f-named").checked = $("f-res").checked = false;
    render();
  }
  function exportCsv() {
    var list = filtered();
    var cols = [["Lead #", "id"], ["Property", "name"], ["Sector", "sector"], ["State", "state"], ["Region", "region"], ["Size", "size"], ["Opportunity", "opp"], ["Performance", "perf"],
      ["Occupancy %", "occ"], ["Occupancy vs peers (pts)", "occVs"], ["DSCR", "dscr"], ["Days cash", "daysCash"],
      ["Current manager", "mgr"], ["Agreement status", "window"], ["Months to expiry", function (l) { return l.mgmt && l.mgmt.monthsToExpiry; }], ["Stale data", "stale"],
      ["Occupancy as of", "occAsof"], ["Occupancy basis", function (l) { return l.occInfo && l.occInfo.basis; }], ["Physical occupancy %", "physOcc"], ["DSCR covenant", "dscrCovenant"],
      ["Status", function (l) { return l.research ? l.research.status : (l.recentIssue ? "recent issue (2023+)" : ""); }],
      ["Owner", function (l) { return l.research && l.research.owner; }], ["Owner parent", function (l) { return l.research && l.research.ownerParent; }],
      ["Owner address", function (l) { return l.research && l.research.ownerAddress; }], ["Owner phone", function (l) { return l.research && l.research.ownerPhone; }],
      ["Property address", function (l) { return l.research && l.research.address; }],
      ["Researched contacts", function (l) { return l.research && (l.research.contacts || []).map(function (c) { return [c.name, c.title, c.org, c.email].filter(Boolean).join(" / "); }).join("; "); }],
      ["Filing contact", function (l) { return l.contact && [l.contact.name, l.contact.title, l.contact.org, l.contact.info].filter(Boolean).join(" / "); }],
      ["Borrower", "borrower"], ["Issuer", "issuer"], ["CUSIPs", "cusips"], ["Latest EMMA document", function (l) { return l.docs && l.docs[0] && (l.docs[0].date + " " + l.docs[0].title); }],
      ["EMMA link", "emma"]];
    var q = function (v) { v = v == null ? "" : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    var csv = cols.map(function (c) { return c[0]; }).join(",") + "\n" + list.map(function (l) { return cols.map(function (c) { var f = c[1]; var v = typeof f === "function" ? f(l) : (f === "mgr" ? mgrOf(l) : l[f]); return q(v); }).join(","); }).join("\n");
    var blob = new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "copia-leads-" + new Date().toISOString().slice(0, 10) + ".csv";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    toast("Exported " + list.length + " leads");
  }

  // ---------- boot ----------
  function enterApp(payload, email) {
    S.email = email;
    S.leads = payload.leads;
    S.watch = store("copia.watch." + email) || {};
    S.req = store("copia.req." + email) || {};
    var states = Array.from(new Set(S.leads.map(function (l) { return l.state; }).filter(Boolean))).sort();
    $("f-state").innerHTML = '<option value="">All states</option>' + states.map(function (s) { return '<option value="' + esc(s) + '">' + esc(s) + "</option>"; }).join("");
    if (payload.generated) $("source-note").textContent += " Data updated " + payload.generated + ". Every lead has occupancy dated " + ((payload.rules && payload.rules.minOccupancyDate) || "Sep 2025") + " or later, checked against the filing text.";
    $("who").textContent = email; $("who").title = email;
    $("login-view").hidden = true; $("app-view").hidden = false;
    document.title = "Lead feed — Copia Partner Portal";
    render();
  }

  function showLoginError(msg) {
    var e = $("login-err");
    e.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>' + esc(msg);
    e.hidden = false;
  }

  function wire() {
    $("pw-toggle").addEventListener("click", function () {
      var p = $("password"), show = p.type === "password";
      p.type = show ? "text" : "password"; this.textContent = show ? "Hide" : "Show";
    });
    $("login-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var email = $("email").value.trim(), pw = $("password").value;
      $("email").removeAttribute("aria-invalid"); $("password").removeAttribute("aria-invalid"); $("login-err").hidden = true;
      if (!email || !pw) {
        showLoginError("Enter your email and password.");
        (email ? $("password") : $("email")).setAttribute("aria-invalid", "true");
        (email ? $("password") : $("email")).focus(); return;
      }
      if (!ENC) { showLoginError("Lead data is missing. Check that data/leads.enc.js was uploaded."); return; }
      if (!window.crypto || !crypto.subtle) { showLoginError("This browser can’t sign in here. Open the portal over https (e.g. GitHub Pages) in a current browser."); return; }
      var btn = $("login-btn"); btn.disabled = true; btn.querySelector("span").textContent = "Signing in…";
      var key;
      deriveKey(email, pw).then(function (k) { key = k; return decryptWith(k); })
        .then(function (payload) {
          return crypto.subtle.exportKey("raw", key).then(function (raw) {
            sess({ email: email.toLowerCase(), k: bytesToB64(raw) });
            $("password").value = "";
            enterApp(payload, email.toLowerCase());
          });
        })
        .catch(function () {
          showLoginError("That email and password don’t match a partner account.");
          $("password").setAttribute("aria-invalid", "true"); $("password").select();
        })
        .then(function () { btn.disabled = false; btn.querySelector("span").textContent = "Sign in"; });
    });

    $("logout-btn").addEventListener("click", function () {
      sess(null); S.leads = []; S.sel = null; $("rows").innerHTML = "";
      $("app-view").hidden = true; $("login-view").hidden = false; document.title = "Copia Partner Portal";
      $("email").value = S.email; $("password").focus();
    });
    $("export-btn").addEventListener("click", exportCsv);
    $("reset-btn").addEventListener("click", resetFilters);

    document.querySelector(".tabs").addEventListener("click", function (e) {
      var t = e.target.closest(".tab"); if (!t) return; S.tab = t.dataset.tab; S.sel = null; render();
    });
    document.querySelector(".filters").addEventListener("click", function (e) {
      var c = e.target.closest(".chip"); if (!c) return; S[c.dataset.key] = c.dataset.val; render();
    });
    $("f-state").addEventListener("change", function () { S.state = this.value; render(); });
    $("f-sort").addEventListener("change", function () { S.sort = this.value; render(); });
    $("f-min").addEventListener("input", function () { S.min = +this.value; $("f-min-out").textContent = this.value; render(); });
    $("f-stale").addEventListener("change", function () { S.hideStale = this.checked; render(); });
    $("f-named").addEventListener("change", function () { S.namedOnly = this.checked; render(); });
    $("f-res").addEventListener("change", function () { S.researchedOnly = this.checked; render(); });
    var qt; $("q").addEventListener("input", function () { var v = this.value; clearTimeout(qt); qt = setTimeout(function () { S.q = v; render(); }, 120); });

    $("rows").addEventListener("click", function (e) {
      var st = e.target.closest("[data-star]"); if (st) { e.stopPropagation(); toggleWatch(+st.dataset.star); return; }
      var r = e.target.closest(".row"); if (r) select(+r.dataset.id);
    });
    $("rows").addEventListener("keydown", function (e) {
      if ((e.key === "Enter" || e.key === " ") && e.target.classList.contains("row")) { e.preventDefault(); select(+e.target.dataset.id); }
    });
    $("empty").addEventListener("click", function (e) { if (e.target.closest("[data-reset]")) resetFilters(); });
    $("detail").addEventListener("click", function (e) {
      var t;
      if (e.target.closest("[data-close]")) { S.sel = null; render(); return; }
      if ((t = e.target.closest("[data-request]"))) { requestIntro(+t.dataset.request); return; }
      if ((t = e.target.closest("[data-withdraw]"))) { withdraw(+t.dataset.withdraw); return; }
      if ((t = e.target.closest("[data-star]"))) { toggleWatch(+t.dataset.star); return; }
    });
    $("backdrop").addEventListener("click", function () { S.sel = null; render(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && S.sel != null) { S.sel = null; render(); } });
    window.addEventListener("resize", function () { if (S.leads.length) renderDetail(); });
  }

  wire();
  if (window.matchMedia("(max-width: 900px)").matches) $("f-details").open = false;
  // Resume a session in this tab without re-entering the password.
  var saved = sess();
  if (saved && saved.k && ENC && window.crypto && crypto.subtle) {
    importRaw(saved.k).then(decryptWith).then(function (p) { enterApp(p, saved.email); })
      .catch(function () { sess(null); });
  }
})();
