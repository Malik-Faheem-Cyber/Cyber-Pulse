/* =====================================================================
   CyberPulse backend  —  node server.js   (Node 18+, no npm packages)

   1. Polls Radware API server-side (no CORS issues)
   2. PUSHes every attack to browsers via WebSocket (/ws)
   3. Keeps history for each country in memory + saves to history.json
   4. Anomaly detection: rolling baseline + z-score  ->  "spike" alert
   5. AbuseIPDB: blacklist (top malicious IPs) + single IP check
      + IP geolocation (ip-api.com)
   6. Cloudflare Radar: global attack trends (top origin / target
      countries, top attack routes) for Layer 3 and Layer 7
   7. Falls back to self-simulation if Radware is unavailable
   ===================================================================== */
'use strict';
const http = require('http'), fs = require('fs'), path = require('path');
const crypto = require('crypto'), net = require('net');
const COUNTRIES = require('./countries.js');

/* ---------------- .env (without dotenv) ---------------- */
(function loadEnv() {
  try {
    fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
      if (/^\s*#/.test(l)) return;
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(l);
      if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    });
  } catch { /* .env optional */ }
})();

const CFG = {
  PORT: +process.env.PORT || 3000,
  HOST: process.env.HOST || '127.0.0.1',      // to show on LAN, set HOST=0.0.0.0
  UPSTREAM: 'https://ltm-prod-api.radware.com/map/attacks?limit=10',
  POLL_MS: 8000,
  CAP: 120,                                    // send max this many events to browser per batch (rest in weight)
  ABUSE_KEY: process.env.ABUSEIPDB_KEY || '',
  CF_TOKEN: process.env.CLOUDFLARE_API_TOKEN || ''
};

/* ---------------- helpers ---------------- */
const TYPES = ['web', 'ddos', 'intruder', 'scanner', 'anon'];
const LABEL = { all: 'Total attack traffic', web: 'Web attacks', ddos: 'DDoS / botnet traffic', intruder: 'Intrusion attempts', scanner: 'Port scanning', anon: 'Anonymizer traffic' };
const byCC = Object.fromEntries(COUNTRIES.map(c => [c.cc, c]));
const TYPE_MAP = { scanners: 'scanner', webattackers: 'web', intruders: 'intruder', anonymizers: 'anon', botnets: 'ddos', iotbotnets: 'ddos', ddosattackers: 'ddos' };

const pickW = (arr, wf) => {
  let t = arr.reduce((s, x) => s + wf(x), 0), r = Math.random() * t;
  for (const x of arr) { r -= wf(x); if (r <= 0) return x; }
  return arr[0];
};
function shuffleTake(list, n) {            // partial Fisher-Yates
  const a = list.slice();
  for (let i = 0; i < n; i++) { const j = i + Math.floor(Math.random() * (a.length - i)); [a[i], a[j]] = [a[j], a[i]]; }
  return a.slice(0, n);
}
const randDst = src => { let d, g = 0; do { d = pickW(COUNTRIES, c => c.wd).cc; } while (d === src && g++ < 10); return d; };
const randSrc = avoid => { let s, g = 0; do { s = pickW(COUNTRIES, c => c.ws).cc; } while (s === avoid && g++ < 10); return s; };

/* ---------------- global state ---------------- */
const S = { source: 'connecting', lastOk: 0, watermark: 0, alerts: [], rates: [], startedAt: Date.now() };
const clients = new Set();
const recent = {};                          //  cc -> last events (only broadcast ones)
const warnedTypes = new Set();

/* ---------------- history (persistent) ---------------- */
const DB_FILE = path.join(__dirname, 'history.json');
let db = { since: Date.now(), c: {} };
try { const j = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); if (j && j.c) db = j; } catch { /* fresh start */ }
const cs = cc => db.c[cc] || (db.c[cc] = { sent: {}, recv: {}, tgt: {}, src: {}, min: {} });

function rec(src, dst, type, at) {
  const m = Math.floor(at / 60000), a = cs(src);
  a.sent[type] = (a.sent[type] || 0) + 1;
  (a.min[m] || (a.min[m] = [0, 0]))[0]++;
  if (dst && byCC[dst]) {
    a.tgt[dst] = (a.tgt[dst] || 0) + 1;
    const b = cs(dst);
    b.recv[type] = (b.recv[type] || 0) + 1;
    b.src[src] = (b.src[src] || 0) + 1;
    (b.min[m] || (b.min[m] = [0, 0]))[1]++;
  }
}
function saveDB() {
  const cutoff = Math.floor(Date.now() / 60000) - 1440;       //  only 24 hours of minute buckets
  for (const d of Object.values(db.c)) for (const k of Object.keys(d.min)) if (+k < cutoff) delete d.min[k];
  try { fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(db)); fs.renameSync(DB_FILE + '.tmp', DB_FILE); }
  catch (e) { console.warn('[db] save failed:', e.message); }
}
function pushRecent(cc, ev) { const r = recent[cc] || (recent[cc] = []); r.push(ev); if (r.length > 40) r.shift(); }

/* ---------------- WebSocket (RFC 6455, send-only server) ---------------- */
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function frame(str, op = 1) {
  const p = Buffer.from(str), n = p.length; let h;
  if (n < 126) h = Buffer.from([0x80 | op, n]);
  else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(n, 2); }
  else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  return Buffer.concat([h, p]);
}
function broadcast(obj) {
  if (!clients.size) return;
  const f = frame(JSON.stringify(obj));
  for (const s of clients) {
    if (s.destroyed || !s.writable) { clients.delete(s); continue; }
    if (s.writableLength > 2e6) { s.destroy(); clients.delete(s); continue; }   // slow client
    s.write(f);
  }
}
function okOrigin(origin, host) {
  if (!origin) return true;
  return /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(origin) || origin === 'http://' + host || origin === 'https://' + host;
}

/* ---------------- anomaly detection ---------------- */
// Rolling 90-sample (~90 sec) baseline for each channel (total + 5 types).
// Spike  <=>  z >= 3  AND  rate >= 1.6 x mean  AND  rate >= minimum  (cooldown 25 sec)
const CH = ['all', ...TYPES];
const hist = Object.fromEntries(CH.map(c => [c, []]));
const lastAlert = {};
function analyse(ch, x) {
  const h = hist[ch]; let mean = 0, sd = 0, alert = null;
  if (h.length >= 25) {
    mean = h.reduce((s, v) => s + v, 0) / h.length;
    sd = Math.sqrt(h.reduce((s, v) => s + (v - mean) ** 2, 0) / h.length);
    const scale = Math.max(sd, mean * 0.15, 1), z = (x - mean) / scale;
    const minAbs = ch === 'all' ? 30 : 12;
    if (z >= 3 && x >= mean * 1.6 && x >= minAbs && Date.now() - (lastAlert[ch] || 0) > 25000) {
      lastAlert[ch] = Date.now(); alert = { ch, x, mean, z };
    }
    x = Math.min(x, mean + 3 * scale);       // don't let the spike poison the baseline
  }
  h.push(x); if (h.length > 90) h.shift();
  return { mean, sd, alert };
}
const tops = (items, key) => {
  const m = {}; items.forEach(a => { if (a[key]) m[a[key]] = (m[a[key]] || 0) + 1; });
  const e = Object.entries(m).sort((a, b) => b[1] - a[1])[0];
  return e ? { cc: e[0], name: byCC[e[0]] ? byCC[e[0]].name : e[0], count: e[1] } : null;
};
function feedSecond(g, o) {
  const res = {}, found = [];
  for (const ch of CH) {
    const x = ch === 'all' ? g.items.length : (g.byType[ch] || 0);
    res[ch] = analyse(ch, x);
    if (res[ch].alert) found.push(res[ch].alert);
  }
  const rate = { type: 'rate', t: Date.now(), all: g.items.length, byType: g.byType, mean: Math.round(res.all.mean) };
  S.rates.push(rate); if (S.rates.length > 900) S.rates.shift();
  broadcast(rate);

  // one incident = one alert: suppress new alerts for 8 seconds after an alert
  if (found.length && Date.now() - (S.lastAny || 0) > 8000) {   // prioritize type-specific
    S.lastAny = lastAlert.all = Date.now();
    const typed = found.filter(f => f.ch !== 'all').sort((a, b) => b.z - a.z);
    const f = typed[0] || found[0];
    const sub = f.ch === 'all' ? g.items : g.items.filter(a => a.type === f.ch);
    const ratio = f.x / Math.max(1, f.mean);
    const al = {
      type: 'alert', id: crypto.randomUUID(), ts: Date.now(), channel: f.ch, label: LABEL[f.ch],
      rate: f.x, baseline: Math.round(f.mean), z: +f.z.toFixed(1), simulated: !!o.simulated,
      severity: f.z >= 8 ? 'critical' : f.z >= 5 ? 'high' : 'medium',
      topSrc: tops(sub, 'src'), topDst: tops(sub, 'dst')
    };
    al.message = `${al.label}: ${al.rate}/s vs baseline ${al.baseline}/s (${ratio.toFixed(1)}x)`;
    S.alerts.unshift(al); if (S.alerts.length > 50) S.alerts.pop();
    console.log(`[ALERT:${al.severity}]${al.simulated ? ' (simulated)' : ''}`, al.message);
    broadcast(al);
  }
}

/* ---------------- batch pipeline (both live and simulation pass through here) ---------------- */
// items = [{src:'US', dst:'JP'|'' , type:'scanner', at:ms}]
function processBatch(items, paceMs, o = {}) {
  if (!items.length) return;
  if (!o.synthetic) items.forEach(a => rec(a.src, a.dst, a.type, a.at));
  let t0 = Infinity, t1 = 0; items.forEach(a => { if (a.at < t0) t0 = a.at; if (a.at > t1) t1 = a.at; });
  const span = Math.max(1, t1 - t0), delay = at => Math.max(0, (at - t0) / span * paceMs);

  // 1) sample -> events to browser (each type with its own quota, w = how many real attacks it represents)
  const cap = o.cap || CFG.CAP, byType = {};
  items.forEach(a => (byType[a.type] || (byType[a.type] = [])).push(a));
  for (const [type, list] of Object.entries(byType)) {
    const q = Math.max(8, Math.round(cap * list.length / items.length));
    const pick = list.length <= q ? list : shuffleTake(list, q), w = list.length / pick.length;
    for (const a of pick) {
      const est = !a.dst || !byCC[a.dst];
      const dst = est ? randDst(a.src) : a.dst;
      setTimeout(() => {
        const ev = { type: 'event', t: Date.now(), src: a.src, dst, atk: type, w: +w.toFixed(2), dstEst: est };
        if (!o.synthetic) { const r = { t: ev.t, src: a.src, dst, atk: type, dstEst: est }; pushRecent(a.src, r); if (dst !== a.src) pushRecent(dst, r); }
        broadcast(ev);
      }, delay(a.at));
    }
  }

  // 2) per-second count -> detector (at the same pace as events, to keep UI smooth)
  const groups = new Map();
  for (const a of items) {
    const k = Math.floor(a.at / 1000);
    let g = groups.get(k); if (!g) groups.set(k, g = { first: a.at, items: [], byType: {} });
    g.items.push(a); g.byType[a.type] = (g.byType[a.type] || 0) + 1; if (a.at < g.first) g.first = a.at;
  }
  [...groups.entries()].sort((a, b) => a[0] - b[0]).forEach(([, g]) => setTimeout(() => feedSecond(g, o), delay(g.first)));
}

/* ---------------- demo helpers: spike injection + simulation ---------------- */
function injectSpike(type = 'ddos', target) {
  if (!TYPES.includes(type)) type = 'ddos';
  const dst = target && byCC[target] ? target : pickW(COUNTRIES, c => c.wd).cc;
  const now = Date.now(), secs = 6, perSec = 320, items = [];
  for (let s = 0; s < secs; s++) for (let i = 0; i < perSec; i++)
    items.push({ src: randSrc(dst), dst, type, at: now + s * 1000 + Math.random() * 999 });
  processBatch(items, secs * 1000, { synthetic: true, simulated: true, cap: 220 });
  return { type, target: dst, perSec, secs };
}
function genSim(secs) {
  const now = Date.now(), items = [];
  for (let s = 0; s < secs; s++) {
    const n = Math.round(70 + Math.random() * 50);
    for (let i = 0; i < n; i++) {
      const type = pickW(TYPES, t => ({ web: 40, scanner: 30, ddos: 22, intruder: 3, anon: 5 })[t]);
      const src = pickW(COUNTRIES, c => c.ws).cc;
      items.push({ src, dst: (type === 'web' || type === 'intruder') ? '' : randDst(src), type, at: now - (secs - s) * 1000 + Math.random() * 999 });
    }
  }
  processBatch(items, secs * 950);
}

/* ---------------- Radware upstream ---------------- */
function parseT(s) {                        // "2026-10-16T19:45:53.5466667" (GMT) -> ms
  const m = /^(.*?\.\d{3})\d*$/.exec(s || '');
  return Date.parse((m ? m[1] : s) + 'Z');
}
function normalizeRaw(raw) {                // [[{sourceCountry,destinationCountry,type,attackTime}]] -> items
  const out = [];
  for (const a of (Array.isArray(raw) ? raw : []).flat()) {
    const tn = String(a.type || '').toLowerCase(), type = TYPE_MAP[tn];
    if (!type) { if (!warnedTypes.has(tn)) { warnedTypes.add(tn); console.warn('[radware] unknown attack type:', a.type); } continue; }
    const src = String(a.sourceCountry || '').trim(), dst = String(a.destinationCountry || '').trim(), at = parseT(a.attackTime);
    if (!byCC[src] || isNaN(at)) continue;
    out.push({ src, dst: byCC[dst] ? dst : '', type, at });
  }
  return out;
}
function handleRadwareRaw(raw) {
  const all = normalizeRaw(raw);
  if (!all.length) throw new Error('no usable data');
  // only take COMPLETE seconds (newest second may be incomplete) and prevent duplicates using watermark
  const maxAt = all.reduce((m, a) => Math.max(m, a.at), 0), cutoff = Math.floor(maxAt / 1000) * 1000;
  const items = all.filter(a => a.at >= S.watermark && a.at < cutoff);
  if (!items.length) return 0;
  S.watermark = cutoff;
  processBatch(items, CFG.POLL_MS * 0.9);
  return items.length;
}
function setSource(s) {
  if (S.source === s) return;
  S.source = s; console.log('[source]', s); broadcast({ type: 'status', source: s });
}
let fails = 0;
async function pollRadware() {
  try {
    const r = await fetch(CFG.UPSTREAM, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    handleRadwareRaw(await r.json());
    fails = 0; S.lastOk = Date.now(); setSource('live');
  } catch (e) {
    fails++; console.warn('[radware] poll failed:', e.message, e.cause && e.cause.code ? '(' + e.cause.code + ')' : '', '#' + fails);
    if (fails >= 2) setSource('simulated');
  }
  setTimeout(pollRadware, CFG.POLL_MS);
}

/* ---------------- AbuseIPDB + geolocation ---------------- */
const INTEL_FILE = path.join(__dirname, 'intel-cache.json');
let intel = { enabled: !!CFG.ABUSE_KEY, generatedAt: 0, total: 0, byCountry: {}, top: [], error: CFG.ABUSE_KEY ? 'loading' : 'ABUSEIPDB_KEY not set' };
function buildIntel(list, ts) {
  const byCountry = {};
  for (const x of list) {
    const cc = x.countryCode || 'ZZ';
    const c = byCountry[cc] || (byCountry[cc] = { count: 0, top: [] });
    c.count++; c.top.push({ ip: x.ipAddress, score: x.abuseConfidenceScore, last: x.lastReportedAt });
  }
  for (const c of Object.values(byCountry)) c.top = c.top.sort((a, b) => b.score - a.score).slice(0, 5);
  const top = list.slice().sort((a, b) => b.abuseConfidenceScore - a.abuseConfidenceScore || String(b.lastReportedAt).localeCompare(String(a.lastReportedAt))).slice(0, 10)
    .map(x => ({ ip: x.ipAddress, score: x.abuseConfidenceScore, cc: x.countryCode || '', last: x.lastReportedAt }));
  return { enabled: true, generatedAt: ts, total: list.length, byCountry, top, error: null };
}
async function loadIntel() {
  if (!CFG.ABUSE_KEY) return;
  let cached = null;
  try { cached = JSON.parse(fs.readFileSync(INTEL_FILE, 'utf8')); } catch { /* none */ }
  if (cached && Date.now() - cached.fetchedAt < 6 * 3600e3) { intel = buildIntel(cached.list, cached.fetchedAt); return; }
  try {   // free plan: blacklist only ~5 times/day -> 6 hour cache
    const r = await fetch('https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=500', {
      headers: { Key: CFG.ABUSE_KEY, Accept: 'application/json' }, signal: AbortSignal.timeout(15000)
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((j.errors && j.errors[0] && j.errors[0].detail) || 'HTTP ' + r.status);
    const list = j.data || [], fetchedAt = Date.now();
    fs.writeFileSync(INTEL_FILE, JSON.stringify({ fetchedAt, list }));
    intel = buildIntel(list, fetchedAt); console.log('[abuseipdb] blacklist loaded:', list.length, 'IPs');
  } catch (e) {
    console.warn('[abuseipdb]', e.message);
    if (cached) { intel = buildIntel(cached.list, cached.fetchedAt); intel.error = 'stale cache (' + e.message + ')'; }
    else intel.error = e.message;
  }
}
async function geoIP(ip) {
  try {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org`, { signal: AbortSignal.timeout(6000) });
    const j = await r.json();
    return j.status === 'success' ? { country: j.country, countryCode: j.countryCode, region: j.regionName, city: j.city, lat: j.lat, lon: j.lon, isp: j.isp, org: j.org } : null;
  } catch { return null; }
}
const ipCache = new Map(); let ipStamps = [];
async function lookupIP(ip) {
  if (!net.isIP(ip)) return { code: 400, body: { error: 'Invalid IP address' } };
  const hit = ipCache.get(ip); if (hit && Date.now() - hit.t < 600e3) return { code: 200, body: hit.body };
  const now = Date.now(); ipStamps = ipStamps.filter(t => now - t < 60e3);
  if (ipStamps.length >= 20) return { code: 429, body: { error: 'Too many lookups, wait a minute' } };
  ipStamps.push(now);
  const [geo, abuse] = await Promise.all([geoIP(ip), (async () => {
    if (!CFG.ABUSE_KEY) return { error: 'ABUSEIPDB_KEY not set (add it to .env)' };
    try {
      const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
        headers: { Key: CFG.ABUSE_KEY, Accept: 'application/json' }, signal: AbortSignal.timeout(10000)
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: (j.errors && j.errors[0] && j.errors[0].detail) || 'AbuseIPDB HTTP ' + r.status };
      const d = j.data || {};
      return { data: { score: d.abuseConfidenceScore, totalReports: d.totalReports, distinctUsers: d.numDistinctUsers, lastReportedAt: d.lastReportedAt,
        isp: d.isp, usageType: d.usageType, domain: d.domain, countryCode: d.countryCode, countryName: d.countryName, whitelisted: d.isWhitelisted, isPublic: d.isPublic } };
    } catch (e) { return { error: 'AbuseIPDB unreachable: ' + e.message }; }
  })()]);
  const body = { ip, abuse: abuse.data || null, geo, error: abuse.error || null };
  if (abuse.data) ipCache.set(ip, { t: now, body });
  return { code: 200, body };
}

/* ---------------- Cloudflare Radar (attack trends) ---------------- */
// Radar gives aggregated statistics (top origin / target countries and top
// attack routes), NOT individual live attacks. Data is cached for 1 hour.
const RADAR_FILE = path.join(__dirname, 'radar-cache.json');
const RADAR_TTL = 3600e3;
const RADAR_RANGE = '1d';
const radarEmpty = () => ({ layer7: { origin: [], target: [], routes: [] }, layer3: { origin: [], target: [], routes: [] } });
let radar = Object.assign({
  enabled: !!CFG.CF_TOKEN, generatedAt: 0, dateRange: RADAR_RANGE,
  error: CFG.CF_TOKEN ? 'loading' : 'CLOUDFLARE_API_TOKEN not set'
}, radarEmpty());

async function cfGet(endpoint) {
  const sep = endpoint.includes('?') ? '&' : '?';
  const r = await fetch('https://api.cloudflare.com/client/v4/radar' + endpoint + sep + 'limit=10&dateRange=' + RADAR_RANGE + '&format=json', {
    headers: { Authorization: 'Bearer ' + CFG.CF_TOKEN, Accept: 'application/json' },
    signal: AbortSignal.timeout(15000)
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) throw new Error((j.errors && j.errors[0] && j.errors[0].message) || 'HTTP ' + r.status);
  const res = j.result || {};
  return res.top_0 || res.top || [];
}
// location rows: { originCountryAlpha2 | targetCountryAlpha2, ...Name, value, rank }
function normLocations(rows, kind) {
  return (Array.isArray(rows) ? rows : []).map((x, i) => {
    const cc = String(x[kind + 'CountryAlpha2'] || x.clientCountryAlpha2 || x.alpha2 || '').toUpperCase();
    return { rank: x.rank || i + 1, cc, name: x[kind + 'CountryName'] || (byCC[cc] && byCC[cc].name) || cc, value: parseFloat(x.value) || 0 };
  }).filter(x => x.cc);
}
// route rows: origin country -> target country
function normRoutes(rows) {
  return (Array.isArray(rows) ? rows : []).map((x, i) => ({
    rank: x.rank || i + 1,
    originCC: String(x.originCountryAlpha2 || '').toUpperCase(), originName: x.originCountryName || '',
    targetCC: String(x.targetCountryAlpha2 || '').toUpperCase(), targetName: x.targetCountryName || '',
    value: parseFloat(x.value) || 0
  })).filter(x => x.originCC && x.targetCC);
}
async function fetchRadar() {
  const jobs = [
    ['layer7.origin', '/attacks/layer7/top/locations/origin', r => normLocations(r, 'origin')],
    ['layer7.target', '/attacks/layer7/top/locations/target', r => normLocations(r, 'target')],
    ['layer7.routes', '/attacks/layer7/top/attacks', normRoutes],
    ['layer3.origin', '/attacks/layer3/top/locations/origin', r => normLocations(r, 'origin')],
    ['layer3.target', '/attacks/layer3/top/locations/target', r => normLocations(r, 'target')],
    ['layer3.routes', '/attacks/layer3/top/attacks', normRoutes]
  ];
  const results = await Promise.allSettled(jobs.map(([, ep]) => cfGet(ep)));
  const out = radarEmpty(), errors = []; let okCount = 0;
  results.forEach((r, i) => {
    const [name, , norm] = jobs[i], [layer, key] = name.split('.');
    if (r.status === 'fulfilled') { out[layer][key] = norm(r.value); okCount++; }
    else errors.push(name + ': ' + r.reason.message);
  });
  if (!okCount) throw new Error(errors[0] || 'Cloudflare Radar request failed');
  return { data: out, partialError: errors.length ? errors.join('; ') : null };
}
async function loadRadar() {
  if (!CFG.CF_TOKEN) return;
  let cached = null;
  try { cached = JSON.parse(fs.readFileSync(RADAR_FILE, 'utf8')); } catch { /* none */ }
  if (cached && cached.data && Date.now() - cached.fetchedAt < RADAR_TTL) {
    radar = Object.assign({ enabled: true, generatedAt: cached.fetchedAt, dateRange: RADAR_RANGE, error: null }, cached.data);
    return;
  }
  try {
    const { data, partialError } = await fetchRadar(), fetchedAt = Date.now();
    fs.writeFileSync(RADAR_FILE, JSON.stringify({ fetchedAt, data }));
    radar = Object.assign({ enabled: true, generatedAt: fetchedAt, dateRange: RADAR_RANGE, error: partialError }, data);
    console.log('[radar] Cloudflare Radar data loaded' + (partialError ? ' (partial: ' + partialError + ')' : ''));
  } catch (e) {
    console.warn('[radar]', e.message);
    if (cached && cached.data) radar = Object.assign({ enabled: true, generatedAt: cached.fetchedAt, dateRange: RADAR_RANGE, error: 'stale cache (' + e.message + ')' }, cached.data);
    else radar.error = e.message;
  }
}
// what Radar says about one country (rank + share in the top-10 lists)
function radarFor(cc) {
  if (!radar.enabled) return null;
  const pick = list => (list || []).find(x => x.cc === cc) || null;
  return {
    layer7: { origin: pick(radar.layer7.origin), target: pick(radar.layer7.target) },
    layer3: { origin: pick(radar.layer3.origin), target: pick(radar.layer3.target) },
    dateRange: radar.dateRange, generatedAt: radar.generatedAt
  };
}

/* ---------------- country detail ---------------- */
function countryInfo(cc) {
  const c = byCC[cc]; if (!c) return null;
  const d = db.c[cc] || { sent: {}, recv: {}, tgt: {}, src: {}, min: {} };
  const sum = o => Object.values(o).reduce((a, b) => a + b, 0);
  const top = o => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => ({ cc: k, name: byCC[k] ? byCC[k].name : k, count: v }));
  const nowM = Math.floor(Date.now() / 60000), series = [];
  for (let i = 59; i >= 0; i--) series.push(d.min[nowM - i] || [0, 0]);
  return {
    cc, name: c.name, source: S.source, since: db.since,
    sent: { total: sum(d.sent), byType: d.sent }, recv: { total: sum(d.recv), byType: d.recv },
    topTargets: top(d.tgt), topSources: top(d.src), series,
    recent: (recent[cc] || []).slice(-12).reverse(),
    intelEnabled: intel.enabled, intelError: intel.error, intel: intel.byCountry[cc] || null,
    radarEnabled: radar.enabled, radarError: radar.error, radar: radarFor(cc),
    alerts: S.alerts.filter(a => (a.topSrc && a.topSrc.cc === cc) || (a.topDst && a.topDst.cc === cc)).slice(0, 5)
  };
}

/* ---------------- HTTP ---------------- */
const STATIC = new Map([['/', 'index.html'], ['/index.html', 'index.html'], ['/style.css', 'style.css'], ['/app.js', 'app.js'], ['/countries.js', 'countries.js']]);
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

function sendJSON(req, res, code, obj) {
  const h = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  const o = req.headers.origin;
  if (o && okOrigin(o, req.headers.host)) { h['Access-Control-Allow-Origin'] = o; h['Vary'] = 'Origin'; }
  res.writeHead(code, h); res.end(JSON.stringify(obj));
}
async function api(req, res, p, u) {
  if (req.method === 'OPTIONS') {
    const o = req.headers.origin, h = { 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' };
    if (o && okOrigin(o, req.headers.host)) h['Access-Control-Allow-Origin'] = o;
    res.writeHead(204, h); return res.end();
  }
  let m;
  if (p === '/api/status') return sendJSON(req, res, 200, {
    source: S.source, clients: clients.size, uptimeSec: Math.round((Date.now() - S.startedAt) / 1000), alerts: S.alerts.length,
    intel: { enabled: intel.enabled, total: intel.total, generatedAt: intel.generatedAt, error: intel.error },
    radar: { enabled: radar.enabled, generatedAt: radar.generatedAt, dateRange: radar.dateRange, error: radar.error }
  });
  if (p === '/api/alerts') return sendJSON(req, res, 200, S.alerts);
  if (p === '/api/intel') return sendJSON(req, res, 200, { enabled: intel.enabled, generatedAt: intel.generatedAt, total: intel.total, top: intel.top, error: intel.error });
  if (p === '/api/radar') return sendJSON(req, res, 200, {
    enabled: radar.enabled, generatedAt: radar.generatedAt, dateRange: radar.dateRange, error: radar.error,
    layer7: radar.layer7, layer3: radar.layer3
  });
  if ((m = /^\/api\/country\/([A-Za-z]{2})$/.exec(p))) {
    const info = countryInfo(m[1].toUpperCase());
    return info ? sendJSON(req, res, 200, info) : sendJSON(req, res, 404, { error: 'Unknown country' });
  }
  if ((m = /^\/api\/ip\/([^/]{1,64})$/.exec(p))) {
    const r = await lookupIP(m[1]); return sendJSON(req, res, r.code, r.body);
  }
  if (p === '/api/simulate-spike') {
    if (req.method !== 'POST') return sendJSON(req, res, 405, { error: 'Use POST' });
    if (hist.all.length < 25) return sendJSON(req, res, 409, { error: 'Detector warming up', have: hist.all.length, need: 25 });
    return sendJSON(req, res, 200, injectSpike(u.searchParams.get('type') || 'ddos', (u.searchParams.get('target') || '').toUpperCase()));
  }
  sendJSON(req, res, 404, { error: 'Not found' });
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'), p = u.pathname;
  if (p.startsWith('/api/')) return api(req, res, p, u).catch(e => { console.error('[api]', e); sendJSON(req, res, 500, { error: 'Server error' }); });
  const f = STATIC.get(p);                     // whitelist: .env / history.json / server.js are never served
  if (!f) { res.writeHead(404); return res.end('Not found'); }
  fs.readFile(path.join(__dirname, f), (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
});

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (req.url !== '/ws' || String(req.headers.upgrade).toLowerCase() !== 'websocket' || !key || !okOrigin(req.headers.origin, req.headers.host)) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return socket.destroy();
  }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  clients.add(socket);
  socket.on('data', buf => {                   // client only sends close/ping
    const op = buf[0] & 0x0f;
    if (op === 8) { clients.delete(socket); socket.end(frame('', 8)); }
    else if (op === 9) socket.write(frame('', 10));
  });
  socket.on('close', () => clients.delete(socket));
  socket.on('error', () => { clients.delete(socket); socket.destroy(); });
  socket.write(frame(JSON.stringify({ type: 'hello', serverTime: Date.now(), source: S.source, intelEnabled: intel.enabled, radarEnabled: radar.enabled, alerts: S.alerts.slice(0, 30), rates: S.rates })));
});

/* ---------------- start ---------------- */
function start() {
  server.listen(CFG.PORT, CFG.HOST, () => {
    console.log(`CyberPulse running -> http://${CFG.HOST === '0.0.0.0' ? 'localhost' : CFG.HOST}:${CFG.PORT}`);
    console.log('AbuseIPDB:', CFG.ABUSE_KEY ? 'key found' : 'no key (add ABUSEIPDB_KEY to .env)');
    console.log('Cloudflare Radar:', CFG.CF_TOKEN ? 'token found' : 'no token (add CLOUDFLARE_API_TOKEN to .env)');
  });
  server.on('error', e => { console.error(e.code === 'EADDRINUSE' ? `Port ${CFG.PORT} already in use` : e); process.exit(1); });
  pollRadware();
  loadIntel(); setInterval(loadIntel, 6 * 3600e3);
  loadRadar(); setInterval(loadRadar, RADAR_TTL);
  setInterval(() => { if (S.source === 'simulated') genSim(2); }, 2000);
  setInterval(saveDB, 60e3);
  setInterval(() => { for (const s of clients) if (s.writable) s.write(frame('', 9)); }, 25e3);   // keep-alive ping
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { saveDB(); process.exit(0); });
}
if (require.main === module) start();
else module.exports = { handleRadwareRaw, normalizeRaw, processBatch, injectSpike, analyse, clients, S, countryInfo, server, frame };