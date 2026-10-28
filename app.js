/* =========================================================
   CyberPulse – frontend
   ---------------------------------------------------------
   1. CONFIG / constants
   2. DATA LAYER   -> WebSocket (server.js) or offline simulator
   3. MAP LAYER    -> D3 map, arcs, hover, click, IP marker
   4. UI LAYER     -> stats, timeline, country panel, alerts, intel,
                      Cloudflare Radar trends
   ========================================================= */

/* ---------------- 1. CONFIG ---------------- */
// If the page is opened from the node server (localhost:3000) use the same host; if opened from Live Server (5500) use localhost:3000
const SAME = location.protocol !== 'file:' && (location.port === '3000' || location.protocol === 'https:');
const HOST = SAME ? location.host : 'localhost:3000';
const API = SAME ? '' : 'http://localhost:3000';
const WS_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + HOST + '/ws';
const CONFIG = {
  MAX_ARCS: 90,
  WORLD_URL: 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'
};

const TYPES = {
  web:      { label: 'Web Attackers', color: '#ff2d55' },
  ddos:     { label: 'DDoS Attackers', color: '#ffd400' },
  intruder: { label: 'Intruders',      color: '#29d3ff' },
  scanner:  { label: 'Scanners',       color: '#7b8cff' },
  anon:     { label: 'Anonymizers',    color: '#c04dff' }
};
// COUNTRIES comes from countries.js (shared by both browser and server)
const byName = Object.fromEntries(COUNTRIES.map(c => [c.name, c]));
const byGeo  = Object.fromEntries(COUNTRIES.map(c => [c.geo, c]));
const byCC   = Object.fromEntries(COUNTRIES.map(c => [c.cc, c]));

const VECTORS = [['TCP Flood',91],['Low and Slow Attack',4],['IP Flood',3],['DNS Flood',1],['UDP Flood',1]];
const VIOLATIONS = [['Access violations',62],['Injections',27],['Exploits',7],['Data theft',3],['Cross-site scripting',1]];
const UDP_PORTS = [[5353,20],[3478,18],[27015,16],[5060,10],[1604,8],[111,7],[1900,6],[10001,6],[137,5],[389,4]];
const TCP_PORTS = [[80,30],[443,26],[5900,10],[23,8],[8080,6],[25,5],[8000,4],[22,4],[3389,4],[8081,3]];

/* ---------------- helpers ---------------- */
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = n => Math.round(n).toLocaleString();
const hhmmss = t => new Date(t).toLocaleTimeString('en-GB');
const pickW = (arr, wf) => {
  let t = arr.reduce((s, x) => s + wf(x), 0), r = Math.random() * t;
  for (const x of arr) { r -= wf(x); if (r <= 0) return x; }
  return arr[0];
};

/* ---------------- state ---------------- */
const state = {
  events: [],            // sampled events (weighted by w) -> top lists, tooltip, country fallback
  counts: [],            // {t,type,n} raw per-second counts -> counters + timeline
  alerts: [],            // newest first
  paused: false, windowMs: 300000,
  active: new Set(Object.keys(TYPES)),
  wsOpen: false, serverSource: 'connecting', offset: 0,
  arcCount: 0, projection: null,
  selectedCC: null, cpTimer: null,
  spikeUntil: 0, spikeSev: 'medium', sound: true, spikeIdx: 0
};

/* ---------------- 2. DATA LAYER ---------------- */
function addDetail(ev) {      // vector / violation / port are not provided by the attack-map API -> ESTIMATED
  const type = ev.type;
  if (type === 'ddos')  ev.detail = pickW(VECTORS, v => v[1])[0];
  if (type === 'web')   ev.detail = pickW(VIOLATIONS, v => v[1])[0];
  if (type === 'scanner' || type === 'intruder') {
    ev.proto = Math.random() < .45 ? 'udp' : 'tcp';
    ev.port = pickW(ev.proto === 'udp' ? UDP_PORTS : TCP_PORTS, p => p[1])[0];
    ev.detail = ev.proto.toUpperCase() + '/' + ev.port;
  }
  if (type === 'anon') ev.detail = Math.random() < .5 ? 'Tor exit node' : 'VPN / Proxy';
  return ev;
}

function ingest(ev, localCount) {
  if (!byName[ev.src] || !byName[ev.dst] || !TYPES[ev.type]) return;
  ev.t = Date.now();
  if (!ev.detail) addDetail(ev);
  if (localCount) state.counts.push({ t: ev.t, type: ev.type, n: 1 });
  state.events.push(ev);
  if (!state.active.has(ev.type)) return;
  drawAttack(ev);
  addFeedRow(ev);
}

/* --- WebSocket client (auto-reconnect) --- */
let ws, retry = 0;
function connectWS() {
  try { ws = new WebSocket(WS_URL); } catch (e) { startLocalSim(); return setTimeout(connectWS, 3000); }
  ws.onopen = () => { retry = 0; state.wsOpen = true; setSource(); };
  ws.onmessage = e => { let m; try { m = JSON.parse(e.data); } catch { return; } onMsg(m); };
  ws.onclose = () => {
    state.wsOpen = false; setSource(); retry++;
    if (retry >= 2) startLocalSim();                       // server not found -> offline demo
    setTimeout(connectWS, Math.min(10000, 1000 * retry));
  };
  ws.onerror = () => { try { ws.close(); } catch {} };
}
function onMsg(m) {
  if (m.type === 'hello') {
    state.serverSource = m.source; state.offset = Date.now() - m.serverTime;
    state.counts = [];
    (m.rates || []).forEach(r => Object.entries(r.byType).forEach(([type, n]) => state.counts.push({ t: r.t + state.offset, type, n })));
    state.alerts = (m.alerts || []).map(a => ({ ...a, rt: a.ts + state.offset }));
    renderAlertList(); setSource(); loadIntel();
  } else if (m.type === 'event') {
    if (state.paused) return;
    const s = byCC[m.src], d = byCC[m.dst];
    if (s && d) ingest({ src: s.name, dst: d.name, type: m.atk, w: m.w, dstEst: m.dstEst });
  } else if (m.type === 'rate') {
    Object.entries(m.byType).forEach(([type, n]) => state.counts.push({ t: Date.now(), type, n }));
  } else if (m.type === 'alert') {
    addAlert({ ...m, rt: Date.now() });
  } else if (m.type === 'status') {
    state.serverSource = m.source; setSource();
  }
}

/* --- offline simulator (only when there is no connection to the server) --- */
let simStarted = false;
function startLocalSim() {
  if (simStarted) return; simStarted = true;
  const loop = () => {
    if (!state.paused && !state.wsOpen) {
      const burst = Math.random() < .12 ? 3 + (Math.random() * 4 | 0) : 1;
      for (let i = 0; i < burst; i++) setTimeout(() => !state.wsOpen && ingest(simulateEvent(), true), i * 90);
    }
    setTimeout(loop, 160 + Math.random() * 280);
  };
  loop();
}
function simulateEvent() {
  const type = pickW(Object.keys(TYPES), t => ({ ddos:45, web:20, scanner:22, intruder:8, anon:7 })[t]);
  const src = pickW(COUNTRIES, c => c.ws); let dst = pickW(COUNTRIES, c => c.wd), g = 0;
  while (dst === src && g++ < 10) dst = pickW(COUNTRIES, c => c.wd);
  return { src: src.name, dst: dst.name, type };
}

/* ---------------- 3. MAP LAYER ---------------- */
const svg = d3.select('#map');
const gMap = svg.append('g'), gArcs = svg.append('g'), gFx = svg.append('g'), gIp = svg.append('g');
let pathGen;

function layout() {
  const el = $('mapWrap'), w = el.clientWidth, h = el.clientHeight;
  svg.attr('viewBox', `0 0 ${w} ${h}`);
  state.projection = d3.geoNaturalEarth1().fitExtent([[10, 70], [w - 10, h - 175]], { type: 'Sphere' });
  pathGen = d3.geoPath(state.projection);
  gMap.selectAll('.sphere, .graticule, .country').attr('d', pathGen);
}

async function initMap() {
  gMap.append('path').datum({ type: 'Sphere' }).attr('class', 'sphere');
  gMap.append('path').datum(d3.geoGraticule10()).attr('class', 'graticule');
  const world = await d3.json(CONFIG.WORLD_URL);
  const feats = topojson.feature(world, world.objects.countries).features;
  gMap.selectAll('.country').data(feats).join('path')
    .attr('class', 'country')
    .on('mousemove', (e, d) => showTip(e, d.properties.name))
    .on('mouseleave', () => (tip.style.opacity = 0))
    .on('click', (e, d) => openCountry(d.properties.name));
  layout();
}

/* tooltip */
const tip = $('tooltip');
function showTip(e, geoName) {
  const c = byGeo[geoName];
  let html = `<b>${esc(geoName)}</b>`;
  if (c) {
    const now = Date.now(); let sent = 0, recv = 0;
    for (const ev of state.events) {
      if (now - ev.t > state.windowMs) continue;
      if (ev.src === c.name) sent += ev.w || 1;
      if (ev.dst === c.name && !ev.dstEst) recv += ev.w || 1;
    }
    html += `<span>Attacks sent: <em>${fmt(sent)}</em></span><span>Attacks received: <em>${fmt(recv)}</em></span><span class="hint">click for details</span>`;
  } else html += '<span>No live data</span>';
  tip.innerHTML = html;
  const r = $('mapWrap').getBoundingClientRect();
  tip.style.left = (e.clientX - r.left + 16) + 'px';
  tip.style.top = (e.clientY - r.top + 16) + 'px';
  tip.style.opacity = 1;
}

/* animated attack arc */
function drawAttack(ev) {
  if (state.arcCount > CONFIG.MAX_ARCS) return;
  const a = byName[ev.src], b = byName[ev.dst], col = TYPES[ev.type].color;
  const p1 = state.projection([a.lon, a.lat]), p2 = state.projection([b.lon, b.lat]);
  if (!p1 || !p2) return;
  if (a === b) { impact(p2, col, b); return; }
  const mx = (p1[0] + p2[0]) / 2, my = (p1[1] + p2[1]) / 2 - Math.hypot(p2[0] - p1[0], p2[1] - p1[1]) * 0.28;
  const d = `M${p1[0]},${p1[1]}Q${mx},${my} ${p2[0]},${p2[1]}`;
  state.arcCount++;

  const trail = gArcs.append('path').attr('d', d).attr('fill', 'none')
    .attr('stroke', col).attr('stroke-width', .8).attr('opacity', .35)
    .attr('stroke-dasharray', ev.dstEst ? '3 4' : null);       // dotted = target estimated
  const comet = gArcs.append('path').attr('d', d).attr('fill', 'none')
    .attr('stroke', col).attr('stroke-width', 2.2).attr('stroke-linecap', 'round')
    .style('filter', `drop-shadow(0 0 4px ${col})`);
  const len = comet.node().getTotalLength(), seg = len * 0.22;
  comet.attr('stroke-dasharray', `${seg} ${len + seg}`).attr('stroke-dashoffset', seg)
    .transition().duration(1300).ease(d3.easeSinInOut).attr('stroke-dashoffset', -len)
    .on('end', () => {
      comet.remove(); impact(p2, col, b);
      trail.transition().duration(900).attr('opacity', 0).remove().on('end', () => state.arcCount--);
    });
  gFx.append('circle').attr('cx', p1[0]).attr('cy', p1[1]).attr('r', 2).attr('fill', col)
    .transition().duration(700).attr('r', 9).attr('opacity', 0).remove();
}

function impact(p, col, country) {
  gFx.append('circle').attr('cx', p[0]).attr('cy', p[1]).attr('r', 2.5).attr('fill', col)
    .transition().duration(1000).attr('opacity', 0).remove();
  gFx.append('circle').attr('cx', p[0]).attr('cy', p[1]).attr('r', 3).attr('fill', 'none')
    .attr('stroke', col).attr('stroke-width', 2)
    .transition().duration(1000).attr('r', 24).attr('opacity', 0).remove();
  const node = gMap.selectAll('.country').filter(d => d.properties.name === country.geo);
  node.classed('hit', false); void (node.node() && node.node().getBoundingClientRect());
  node.classed('hit', true);
}

function bigPulse(cc) {            // big red ripple on the top target during a spike
  const c = byCC[cc]; if (!c || !state.projection) return;
  const p = state.projection([c.lon, c.lat]);
  for (let i = 0; i < 3; i++)
    gFx.append('circle').attr('cx', p[0]).attr('cy', p[1]).attr('r', 4).attr('fill', 'none')
      .attr('stroke', '#ff2d55').attr('stroke-width', 3)
      .transition().delay(i * 450).duration(1800).attr('r', 70).attr('opacity', 0).remove();
}

function plotIP(lat, lon, label) { // marker for IP lookup
  gIp.selectAll('*').remove();
  if (lat == null || lon == null || !state.projection) return;
  const p = state.projection([lon, lat]); if (!p) return;
  const g = gIp.append('g').attr('class', 'ipmark').attr('transform', `translate(${p[0]},${p[1]})`);
  g.append('circle').attr('r', 5).attr('fill', '#fff');
  g.append('circle').attr('class', 'ring').attr('r', 8).attr('fill', 'none').attr('stroke', '#00e5ff').attr('stroke-width', 2);
  g.append('text').attr('x', 12).attr('y', 4).text(label);
  setTimeout(() => g.remove(), 45000);
}

/* ---------------- 4. UI LAYER ---------------- */
/* type filter + timeline legend */
const typeList = $('typeList'), legend = $('tlLegend');
Object.entries(TYPES).forEach(([k, v]) => {
  const li = document.createElement('li'); li.style.color = v.color; li.style.setProperty('--c', v.color);
  li.innerHTML = `<span class="chk">✓</span><span style="color:#fff">${v.label}</span><small id="n_${k}">0</small>`;
  li.onclick = () => { state.active.has(k) ? state.active.delete(k) : state.active.add(k); li.classList.toggle('off'); };
  typeList.appendChild(li);
  const lg = document.createElement('li'); lg.style.setProperty('--c', v.color); lg.textContent = v.label.toUpperCase();
  legend.appendChild(lg);
});

/* live feed */
const feed = $('feed');
function addFeedRow(ev) {
  const now = performance.now();                 // too many rows during a spike -> show only up to ~8/sec
  if (now - (addFeedRow.last || 0) < 120) return; addFeedRow.last = now;
  const row = document.createElement('div'); row.className = 'row';
  row.style.setProperty('--c', TYPES[ev.type].color);
  row.innerHTML = `<span class="t">${hhmmss(ev.t)}</span><span>[${byName[ev.src].cc}] ${esc(ev.src)}</span><span>[${byName[ev.dst].cc}] ${esc(ev.dst)}${ev.dstEst ? '*' : ''}</span><span class="t">${TYPES[ev.type].label.split(' ')[0]}</span><span>${esc(ev.detail || '-')}</span>`;
  feed.prepend(row);
  while (feed.children.length > 9) feed.lastChild.remove();
}

/* statistics */
function topN(arr, keyFn, n = 5) {
  const m = new Map(); arr.forEach(x => { const k = keyFn(x); if (k) m.set(k, (m.get(k) || 0) + (x.w || 1)); });
  const total = [...m.values()].reduce((a, b) => a + b, 0) || 1;
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => [k, Math.round(v / total * 100)]);
}
function renderBars(id, rows, withCC) {
  const max = Math.max(1, ...rows.map(r => r[1]));
  $(id).innerHTML = rows.map(([k, p]) =>
    `<li style="--w:${p / max * 100}%"><span>${withCC && byName[k] ? `<i class="cc">${byName[k].cc}</i>` : ''}${esc(k)}</span><span>${p} %</span></li>`).join('');
}
function renderTiles(id, rows) {
  const max = Math.max(1, ...rows.map(r => r[1]));
  $(id).innerHTML = rows.map(([k, c]) => {
    const w = Math.max(22, c / max * 100);
    return `<div class="tile" style="--w:${w}%;--fs:${12 + c / max * 22}px">${esc(k)}</div>`;
  }).join('');
}

function renderStats() {
  const now = Date.now();
  state.events = state.events.filter(e => now - e.t < 900000);
  state.counts = state.counts.filter(c => now - c.t < 900000);
  const win = state.events.filter(e => now - e.t < state.windowMs && state.active.has(e.type));

  renderBars('lAttackers', topN(win, e => e.src), true);
  renderBars('lTargets', topN(win.filter(e => !e.dstEst), e => e.dst), true);   // estimated targets are not counted at all
  renderBars('lVectors', topN(win.filter(e => e.type === 'ddos'), e => e.detail));
  renderBars('lViol', topN(win.filter(e => e.type === 'web'), e => e.detail));
  const sc = win.filter(e => e.port);
  renderTiles('tUdp', topN(sc.filter(e => e.proto === 'udp'), e => e.port, 8));
  renderTiles('tTcp', topN(sc.filter(e => e.proto === 'tcp'), e => e.port, 8));

  // counters: raw per-second counts (from server) -> not affected by sampling
  let total = 0, last10 = 0; const per = {};
  for (const c of state.counts) {
    if (now - c.t < state.windowMs) { per[c.type] = (per[c.type] || 0) + c.n; if (state.active.has(c.type)) total += c.n; }
    if (now - c.t < 10000 && state.active.has(c.type)) last10 += c.n;
  }
  Object.keys(TYPES).forEach(k => $('n_' + k).textContent = fmt(per[k] || 0));
  $('cTotal').textContent = fmt(total);
  $('cRate').textContent = (last10 / 10).toFixed(1);

  let lvl = 'OFFLINE';
  if (state.wsOpen) lvl = now < state.spikeUntil ? (state.spikeSev === 'medium' ? 'ELEVATED' : 'SPIKE') : 'NORMAL';
  const s = $('cSev'); s.textContent = lvl; s.className = lvl;
}

/* timeline */
const cv = $('tl'), ctx = cv.getContext('2d');
function renderTimeline() {
  const dpr = window.devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight;
  if (!W || !H) return;
  if (cv.width !== Math.round(W * dpr)) { cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
  const keys = Object.keys(TYPES), lane = (H - 24) / keys.length, B = 160, now = Date.now(), span = state.windowMs;
  keys.forEach((k, i) => {
    const bins = new Array(B).fill(0);
    for (const c of state.counts) if (c.type === k) { const a = now - c.t; if (a >= 0 && a < span) bins[B - 1 - Math.floor(a / span * B)] += c.n; }
    const max = Math.max(1, ...bins), y0 = 8 + (i + 1) * lane, col = TYPES[k].color;
    ctx.fillStyle = col + '14'; ctx.fillRect(0, 8 + i * lane + 2, W, lane - 4);
    ctx.strokeStyle = col; ctx.lineWidth = 1.2; ctx.beginPath();
    bins.forEach((v, j) => { const x = j / (B - 1) * W, y = y0 - 4 - v / max * (lane - 10); j ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.stroke();
  });
  // anomaly markers
  for (const a of state.alerts) {
    const age = now - a.rt; if (age < 0 || age > span) continue;
    const x = W * (1 - age / span);
    ctx.strokeStyle = '#ff2d55'; ctx.setLineDash([4, 3]); ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(x, 4); ctx.lineTo(x, H - 16); ctx.stroke(); ctx.setLineDash([]);
    ctx.fillStyle = '#ff2d55'; ctx.font = '12px Rajdhani'; ctx.fillText('⚠', x - 5, 14);
  }
  ctx.fillStyle = '#00e5ff'; ctx.font = '12px Orbitron';
  ctx.fillText('-' + span / 60000 + 'm', 8, H - 4); ctx.fillText('NOW', W - 40, H - 4);
}

/* ---------- anomaly alerts ---------- */
function addAlert(a) {
  state.alerts.unshift(a); if (state.alerts.length > 50) state.alerts.pop();
  state.spikeUntil = Date.now() + 30000; state.spikeSev = a.severity;
  renderAlertList();
  const b = $('alertBanner');
  b.className = a.severity; b.hidden = false;
  b.innerHTML = `<b>⚠ SPIKE DETECTED${a.simulated ? ' <small>(TEST)</small>' : ''}</b> ${esc(a.message)}${a.topDst ? ` · target <em>${esc(a.topDst.name)}</em>` : ''}`;
  clearTimeout(addAlert.t); addAlert.t = setTimeout(() => (b.hidden = true), 9000);
  $('stage').classList.add('alarm'); setTimeout(() => $('stage').classList.remove('alarm'), 3000);
  if (a.topDst) bigPulse(a.topDst.cc);
  beep(a.severity);
}
function renderAlertList() {
  const ul = $('alertList');
  if (!state.alerts.length) { ul.innerHTML = '<li class="empty">No anomalies detected yet</li>'; return; }
  ul.innerHTML = state.alerts.slice(0, 20).map(a => `<li class="${esc(a.severity)}">
    <time>${hhmmss(a.ts)}</time> <span class="sev">${esc(a.severity.toUpperCase())}</span>${a.simulated ? '<span class="test">TEST</span>' : ''}
    <div>${esc(a.message)}</div>
    ${a.topSrc || a.topDst ? `<small>${a.topSrc ? esc(a.topSrc.cc) : '?'} → ${a.topDst ? esc(a.topDst.cc) : '?'} · z=${esc(a.z)}</small>` : ''}</li>`).join('');
}
function beep(sev) {
  if (!state.sound) return;
  try {
    const ac = state.ac || (state.ac = new (window.AudioContext || window.webkitAudioContext)());
    const o = ac.createOscillator(), g = ac.createGain();
    o.type = 'square'; o.frequency.value = sev === 'critical' ? 880 : 620; g.gain.value = .04;
    o.connect(g); g.connect(ac.destination); o.start(); setTimeout(() => o.stop(), 280);
  } catch {}
}
function toast(msg) {
  const b = $('alertBanner'); b.className = 'info'; b.hidden = false; b.textContent = msg;
  clearTimeout(addAlert.t); addAlert.t = setTimeout(() => (b.hidden = true), 5000);
}

/* ---------- country detail panel ---------- */
function openCountry(geoName) {
  const c = byGeo[geoName];
  gMap.selectAll('.country').classed('selected', d => c && d.properties.name === geoName);
  clearInterval(state.cpTimer);
  $('cpanel').hidden = false; $('alertPanel').hidden = true;
  if (!c) {
    state.selectedCC = null;
    $('cpTitle').textContent = geoName;
    $('cpBody').innerHTML = '<p class="muted">No live data for this country (only countries with attack-data are tracked on the map).</p>';
    return;
  }
  state.selectedCC = c.cc;
  $('cpTitle').innerHTML = `<i class="cc">${c.cc}</i> ${esc(c.name)}`;
  $('cpBody').innerHTML = '<p class="muted">Loading…</p>';
  refreshCountry();
  state.cpTimer = setInterval(refreshCountry, 5000);
}
function closeCountry() {
  clearInterval(state.cpTimer); state.selectedCC = null;
  $('cpanel').hidden = true; $('alertPanel').hidden = false;
  gMap.selectAll('.country').classed('selected', false);
}
async function refreshCountry() {
  const c = byCC[state.selectedCC]; if (!c) return;
  let info;
  try { const r = await fetch(API + '/api/country/' + c.cc); if (!r.ok) throw 0; info = await r.json(); }
  catch { info = localCountryInfo(c); }
  if (state.selectedCC === c.cc) renderCountry(info);
}
function localCountryInfo(c) {       // if server is down, only this session's data
  const sent = {}, recv = {}, tgt = {}, src = {};
  for (const e of state.events) {
    const w = e.w || 1;
    if (e.src === c.name) { sent[e.type] = (sent[e.type] || 0) + w; if (!e.dstEst) tgt[byName[e.dst].cc] = (tgt[byName[e.dst].cc] || 0) + w; }
    if (e.dst === c.name && !e.dstEst) { recv[e.type] = (recv[e.type] || 0) + w; src[byName[e.src].cc] = (src[byName[e.src].cc] || 0) + w; }
  }
  const sum = o => Object.values(o).reduce((a, b) => a + b, 0);
  const top = o => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => ({ cc: k, name: byCC[k].name, count: v }));
  return {
    local: true, since: Date.now(), sent: { total: sum(sent), byType: sent }, recv: { total: sum(recv), byType: recv },
    topTargets: top(tgt), topSources: top(src), series: [],
    recent: state.events.filter(e => e.src === c.name || e.dst === c.name).slice(-12).reverse()
      .map(e => ({ t: e.t, src: byName[e.src].cc, dst: byName[e.dst].cc, atk: e.type, dstEst: e.dstEst })),
    intelEnabled: false, intel: null,
    radarEnabled: false, radar: null, radarError: null,
    alerts: []
  };
}
function spark(series) {
  if (!series || !series.length) return '';
  const W = 296, H = 56, n = series.length, mx = Math.max(1, ...series.map(s => Math.max(s[0], s[1])));
  const pts = i => series.map((s, k) => `${(k / (n - 1) * W).toFixed(1)},${(H - 3 - s[i] / mx * (H - 8)).toFixed(1)}`).join(' ');
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><polyline points="${pts(0)}" fill="none" stroke="#ff2d55" stroke-width="1.6"/><polyline points="${pts(1)}" fill="none" stroke="#00e5ff" stroke-width="1.6"/></svg>
    <div class="legendline"><span style="color:#ff2d55">● sent</span><span style="color:#00e5ff">● received</span><span class="muted">last 60 min</span></div>`;
}

/* Cloudflare Radar section of the country panel.
   Radar provides aggregated trends (rank + share of the top-10 lists), not individual attacks. */
function renderRadar(i) {
  if (i.local) return '<p class="muted">Server offline: Cloudflare Radar data unavailable.</p>';
  if (!i.radarEnabled) return '<p class="muted">Cloudflare token not set (<code>CLOUDFLARE_API_TOKEN</code> in .env).</p>';
  const rd = i.radar;
  if (!rd) return `<p class="muted">${i.radarError ? esc(i.radarError) : 'No Radar data yet'}</p>`;
  const cell = (label, x) => `<div class="kv"><span>${label}</span><b>${x ? '#' + esc(x.rank) + ' · ' + Number(x.value).toFixed(1) + '%' : 'not in top 10'}</b></div>`;
  const range = rd.dateRange === '1d' ? 'last 24 hours' : esc(rd.dateRange || '');
  const updated = rd.generatedAt ? new Date(rd.generatedAt).toLocaleString('en-GB') : '-';
  return `<p class="muted">Top-10 rankings for the ${range}</p>
    ${cell('Layer 7 · attack origin', rd.layer7 && rd.layer7.origin)}
    ${cell('Layer 7 · attack target', rd.layer7 && rd.layer7.target)}
    ${cell('Layer 3 · attack origin', rd.layer3 && rd.layer3.origin)}
    ${cell('Layer 3 · attack target', rd.layer3 && rd.layer3.target)}
    <p class="note">Aggregated trend data, not individual attacks. Updated ${updated}.${i.radarError ? '<br>' + esc(i.radarError) : ''}</p>`;
}

function renderCountry(i) {
  const sent = i.sent.total, recv = i.recv.total;
  const posture = sent > recv * 1.5 ? 'NET ATTACK SOURCE' : recv > sent * 1.5 ? 'NET TARGET' : 'BALANCED';
  const bars = o => { const mx = Math.max(1, ...Object.values(o)); return Object.keys(TYPES).map(k =>
    `<div class="tb"><span style="color:${TYPES[k].color}">${TYPES[k].label.split(' ')[0]}</span><i style="--w:${(o[k] || 0) / mx * 100}%;--c:${TYPES[k].color}"></i><b>${fmt(o[k] || 0)}</b></div>`).join(''); };
  const rows = l => l.length ? l.map(x => `<li><i class="cc">${esc(x.cc)}</i>${esc(x.name)}<b>${fmt(x.count)}</b></li>`).join('') : '<li class="muted">—</li>';
  const recent = (i.recent || []).map(e => `<li style="--c:${(TYPES[e.atk] || {}).color || '#fff'}"><time>${hhmmss(e.t)}</time> ${esc(e.src)} → ${esc(e.dst)}${e.dstEst ? '*' : ''} <em>${esc(e.atk)}</em></li>`).join('') || '<li class="muted">No events yet</li>';

  let intel;
  if (i.local) intel = '<p class="muted">Server offline: showing data for this session only.</p>';
  else if (!i.intelEnabled) intel = '<p class="muted">AbuseIPDB key not set (<code>ABUSEIPDB_KEY</code> in .env).</p>';
  else if (i.intel) intel = `<p><b>${fmt(i.intel.count)}</b> blacklisted IPs (confidence ≥90%)</p><ul class="iplist">${i.intel.top.map(x =>
    `<li data-ip="${esc(x.ip)}"><span>${esc(x.ip)}</span><b class="sc">${esc(x.score)}%</b></li>`).join('')}</ul>`;
  else intel = `<p class="muted">${i.intelError ? esc(i.intelError) : 'No IP from this country in the blacklist'}</p>`;

  $('cpBody').innerHTML = `
    <div class="kpis">
      <div><span>${fmt(sent)}</span><label>ATTACKS SENT</label></div>
      <div><span>${fmt(recv)}</span><label>ATTACKS RECEIVED</label></div>
    </div>
    <p class="posture ${posture.replace(/ /g, '')}">${posture}</p>
    ${spark(i.series)}
    <h4>AS SOURCE · by type</h4>${bars(i.sent.byType)}
    <h4>AS TARGET · by type</h4>${bars(i.recv.byType)}
    <div class="two"><div><h4>TOP TARGETS</h4><ul class="lst">${rows(i.topTargets)}</ul></div>
    <div><h4>TOP SOURCES</h4><ul class="lst">${rows(i.topSources)}</ul></div></div>
    <h4>RECENT EVENTS</h4><ul class="recent">${recent}</ul>
    <h4>ABUSEIPDB</h4>${intel}
    <h4>CLOUDFLARE RADAR</h4>${renderRadar(i)}
    <p class="note">History since ${new Date(i.since).toLocaleString('en-GB')}${i.source === 'simulated' ? ' · server in SIMULATION mode' : ''}.<br>* the API does not provide web-attack targets (estimated, not included in received).</p>`;
}

/* ---------- threat intel (AbuseIPDB) ---------- */
async function loadIntel() {
  const ul = $('ipTop');
  try {
    const r = await fetch(API + '/api/intel'); const j = await r.json();
    if (!j.enabled) ul.innerHTML = '<li class="muted">AbuseIPDB key not set. Create <code>.env</code> in the project folder: <code>ABUSEIPDB_KEY=...</code></li>';
    else if (!j.top.length) ul.innerHTML = `<li class="muted">${esc(j.error || 'No data')}</li>`;
    else ul.innerHTML = j.top.map(x => `<li data-ip="${esc(x.ip)}"><span>${esc(x.ip)}</span><em>${esc(x.cc)}</em><b class="sc">${esc(x.score)}%</b></li>`).join('');
  } catch { ul.innerHTML = '<li class="muted">Server offline</li>'; }
}
async function checkIP(ip) {
  const box = $('ipResult'); box.innerHTML = '<p class="muted">Checking…</p>';
  try {
    const r = await fetch(API + '/api/ip/' + encodeURIComponent(ip)); const j = await r.json();
    if (!r.ok && !j.ip) { box.innerHTML = `<p class="err">${esc(j.error || 'Error')}</p>`; return; }
    renderIP(j);
  } catch { box.innerHTML = '<p class="err">No connection to server (run node server.js)</p>'; }
}
function renderIP(r) {
  const a = r.abuse, g = r.geo, row = (k, v) => v ? `<div class="kv"><span>${k}</span><b>${esc(v)}</b></div>` : '';
  let h = `<div class="ipcard"><strong>${esc(r.ip)}</strong>`;
  if (a) {
    const col = a.score < 25 ? '#2dff9a' : a.score < 75 ? '#ffd400' : '#ff2d55';
    h += `<div class="score" style="--w:${a.score}%;--c:${col}"><i></i><span>${esc(a.score)}% ABUSE CONFIDENCE</span></div>`
      + row('Reports', `${a.totalReports} (${a.distinctUsers} users)`) + row('Last reported', a.lastReportedAt ? new Date(a.lastReportedAt).toLocaleString('en-GB') : 'never')
      + row('Usage', a.usageType) + row('ISP', a.isp) + row('Domain', a.domain) + (a.whitelisted ? row('Status', 'Whitelisted') : '');
  } else if (r.error) h += `<p class="err">${esc(r.error)}</p>`;
  if (g) h += row('Location', [g.city, g.region, g.country].filter(Boolean).join(', ')) + row('Coordinates', `${g.lat}, ${g.lon}`) + (!a ? row('ISP', g.isp) : '');
  else h += '<p class="muted">Geolocation unavailable (private IP OR ip-api.com unreachable).</p>';
  $('ipResult').innerHTML = h + '</div>';

  let lat = g && g.lat, lon = g && g.lon;
  if (lat == null) { const cc = byCC[(a && a.countryCode) || '']; if (cc) { lat = cc.lat; lon = cc.lon; } }
  plotIP(lat, lon, r.ip);
}

/* ---------- controls ---------- */
$('interval').onchange = e => state.windowMs = +e.target.value;
$('btnPause').onclick = e => { state.paused = !state.paused; e.target.textContent = state.paused ? '▶ RESUME' : '❚❚ PAUSE'; };
$('btnFull').onclick = () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen();
$('btnSound').onclick = e => { state.sound = !state.sound; e.target.textContent = state.sound ? '🔔' : '🔕'; };
$('cpClose').onclick = closeCountry;
$('ipForm').onsubmit = e => { e.preventDefault(); const v = $('ipInput').value.trim(); if (v) checkIP(v); };
document.addEventListener('click', e => {                   // click on IP list -> check
  const li = e.target.closest('li[data-ip]'); if (li) { $('ipInput').value = li.dataset.ip; checkIP(li.dataset.ip); }
});
$('btnSpike').onclick = async () => {
  const types = ['ddos', 'web', 'scanner', 'intruder'], type = types[state.spikeIdx++ % types.length];
  if (!state.wsOpen) return toast('You need to run "node server.js" for the spike detector');
  try {
    const r = await fetch(API + '/api/simulate-spike?type=' + type, { method: 'POST' });
    if (r.status === 409) { const j = await r.json(); return toast(`Detector warm-up in progress (${j.have}/${j.need} sec), try again in a moment`); }
    toast(`Test spike (${type}) sent, the detector will catch it in 2-5 sec`);
  } catch { toast('No connection to server'); }
};
setInterval(() => $('clock').textContent = new Date().toLocaleTimeString('en-GB'), 1000);

function setSource() {
  const p = $('srcPill'); let t, cls, txt;
  if (state.wsOpen && state.serverSource === 'live') { t = 'LIVE · WEBSOCKET'; cls = 'live'; txt = 'Radware live feed via WebSocket (attacks real; vectors/ports estimated)'; }
  else if (state.wsOpen) { t = 'SERVER SIMULATION'; cls = 'warn'; txt = 'Server simulation (Radware unreachable)'; }
  else { t = simStarted ? 'OFFLINE SIMULATION' : 'CONNECTING…'; cls = 'off'; txt = simStarted ? 'Offline simulation (server.js not running)' : 'Connecting to server…'; }
  p.textContent = t; p.className = 'pill ' + cls; $('srcText').textContent = txt;
}

/* ---------- boot ---------- */
window.addEventListener('resize', () => { layout(); renderTimeline(); });
(async function boot() {
  setSource();
  connectWS();
  await initMap();
  setInterval(() => { renderStats(); renderTimeline(); }, 1000);
  setInterval(() => state.wsOpen && loadIntel(), 600000);
})();