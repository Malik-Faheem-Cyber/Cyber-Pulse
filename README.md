# CyberPulse | Live Cyber Threat Map

A real-time cyber threat visualisation and intelligence dashboard built with **Node.js, WebSockets, D3.js, AbuseIPDB and Cloudflare Radar**.

CyberPulse turns a continuous stream of attack telemetry into an interactive picture of the global threat landscape: animated attack arcs on a world map, live statistics, anomaly alerts, per-country history and IP reputation lookups.

![CyberPulse dashboard](docs/dashboard.png)

> **Educational project.** CyberPulse is not affiliated with Radware, AbuseIPDB, Cloudflare or ip-api.com. The live attack feed is a public endpoint used for learning purposes; review its terms of use before any public or commercial deployment.

---

## Features

- **Live attack map:** animated comet-like arcs from source to target country, colour-coded by attack type, with impact ripples.
- **Five attack types:** Web, DDoS, Intruders, Scanners and Anonymizers, each of which can be switched on or off.
- **Real-time push:** events are delivered to the browser over a hand-written WebSocket (RFC 6455) server, with no polling from the browser.
- **Live statistics:** top attackers, top attacked countries, attack rate, activity timeline, and top scanned UDP/TCP ports over a 1, 5 or 15 minute window.
- **Anomaly detection:** rolling 90-second baseline with z-score and severity levels (Medium, High, Critical). Alerts appear as a banner, a screen-edge flash, a pulse on the target country and an optional sound.
- **Country drill-down:** click any country to see attacks sent and received, a 60-minute sparkline, breakdown by type, top targets and sources, recent events, AbuseIPDB data and Cloudflare Radar rankings.
- **IP reputation checker:** enter or click any IP to see its abuse confidence score, report counts, ISP, usage type and location, with a marker placed on the map.
- **Persistent history:** per-country history is saved to disk (24-hour minute buckets) and survives restarts.
- **Graceful fallback:** if the live feed is unreachable, the server switches to simulation automatically and returns to live data when the feed recovers. The browser has its own offline simulator too.
- **Spike demo:** a **Simulate Spike** button injects a synthetic surge (labelled TEST) so the detector can be demonstrated at any time.

## Measured vs. estimated data

The project is deliberately transparent about data quality.

| Field | Status |
| --- | --- |
| Source country, destination country, attack type, timestamp | Measured (from the live feed) |
| Attack vector, application violation, scanned port | **Estimated** from fixed weighted distributions and labelled as such in the UI |
| Destination of web attacks (missing in the feed) | Estimated for animation only. Drawn with a dotted trail, marked with `*`, and excluded from all "received" statistics |
| Cloudflare Radar rankings | Aggregated 24-hour data, shown in a separate section (not individual attacks) |

## Tech stack

| Layer | Technology |
| --- | --- |
| Frontend | HTML5, CSS3, JavaScript (ES2020), HTML5 Canvas |
| Map | D3.js 7.8.5, TopoJSON 3.0.2, world-atlas |
| Backend | Node.js 18+ using only built-in modules (`http`, `fs`, `crypto`, `net`, `fetch`). **No npm dependencies** |
| Real-time | WebSocket (RFC 6455), implemented from scratch |
| Threat intelligence | AbuseIPDB API v2, Cloudflare Radar API v4 |
| Geolocation | ip-api.com |
| Persistence | JSON files |

## Architecture

```
 External sources                 Node.js backend (server.js)               Browser
┌──────────────────┐            ┌───────────────────────────────┐        ┌──────────────────┐
│ Radware live feed│──poll 8s──▶│ Poller + normaliser           │        │ WebSocket client │
│ AbuseIPDB API    │───────────▶│ Batch pipeline (sampling)     │──WS───▶│ D3 world map     │
│ Cloudflare Radar │───────────▶│ Anomaly detector (z-score)    │        │ Dashboard panels │
│ ip-api.com       │───────────▶│ History store + caches        │◀─REST──│ Timeline canvas  │
└──────────────────┘            │ REST API + WebSocket server   │        │ Country panel    │
                                └───────────────────────────────┘        └──────────────────┘
```

The browser never calls third-party APIs directly. All requests are made server-side, which avoids CORS problems and keeps API keys on the server.

## Getting started

### Requirements

- Node.js 18 or newer
- An internet connection (map libraries and world data load from CDNs)
- Optional free API keys for AbuseIPDB and Cloudflare Radar

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Malik-Faheem-Cyber/Cyber-Pulse.git
cd Cyber-Pulse

# 2. Create your environment file
cp .env.example .env        # on Windows: copy .env.example .env

# 3. Add your keys to .env (both are optional)
#    ABUSEIPDB_KEY=your_abuseipdb_key
#    CLOUDFLARE_API_TOKEN=your_cloudflare_radar_token

# 4. Start the server
node server.js
```

Then open **http://localhost:3000** in your browser.

### Configuration

| Variable | Description |
| --- | --- |
| `ABUSEIPDB_KEY` | AbuseIPDB API key. Enables the blacklist panel and IP checker. |
| `CLOUDFLARE_API_TOKEN` | Cloudflare token with **read-only Radar** access. Enables global attack trends. |
| `HOST` | Optional. Set to `0.0.0.0` to make the dashboard reachable from other devices on your network. |

Without the keys, the matching panels show a short "key not set" message and the rest of the dashboard keeps working.

## API reference

### REST endpoints

| Endpoint | Description |
| --- | --- |
| `GET /api/status` | Source, connected clients, uptime, alert count and integration status |
| `GET /api/alerts` | Latest anomaly alerts (up to 50) |
| `GET /api/intel` | Top malicious IPs from the cached AbuseIPDB blacklist |
| `GET /api/radar` | Cached Cloudflare Radar rankings (Layer 3 and Layer 7) |
| `GET /api/country/:cc` | History and intelligence for one country |
| `GET /api/ip/:ip` | AbuseIPDB reputation and geolocation for one IP |
| `POST /api/simulate-spike` | Injects a synthetic traffic surge to test the anomaly detector |

### WebSocket messages (`/ws`)

| Message | Content |
| --- | --- |
| `hello` | Sent on connect: server time, source status, recent alerts and rate history |
| `event` | One sampled attack: source, destination, type, weight and an estimated-target flag |
| `rate` | Per-second attack counts (total and per type) |
| `alert` | Anomaly alert: channel, rate, baseline, z-score, severity, top source and target |
| `status` | Data source changed between live and simulated |

## How anomaly detection works

The detector keeps a rolling baseline of the last 90 one-second samples for total traffic and for each attack type. A spike is reported when all of these hold:

- z-score of at least 3
- rate of at least 1.6 times the mean
- rate above a minimum (30/s for total traffic, 12/s for a single type)

Severity is **Medium** (z ≥ 3), **High** (z ≥ 5) or **Critical** (z ≥ 8). A 25-second cooldown per channel and an 8-second gap between any two alerts make sure one incident produces one alert.

## Security

- API keys are read from `.env` and never reach the browser.
- Only `index.html`, `style.css`, `app.js` and `countries.js` are served, so `.env`, `server.js` and the JSON data files can never be downloaded.
- CORS and WebSocket upgrades accept only localhost or same-origin requests.
- IP addresses are validated, and lookups are cached and rate-limited (20 per minute) to protect API quotas.
- All text inserted into the page is HTML-escaped.

## Project structure

```
├── server.js          # Backend: polling, pipeline, anomaly detection, REST API, WebSocket
├── app.js             # Frontend: data, map and UI layers
├── index.html         # Page structure
├── style.css          # Neon-on-navy theme
├── countries.js       # Country table shared by browser and server
├── .env.example       # Template for required environment variables
└── .gitignore         # Excludes secrets and generated files

# Generated at runtime (git-ignored)
├── .env
├── history.json
├── intel-cache.json
└── radar-cache.json
```

## Limitations

- The live feed is a public endpoint and may change or become unavailable. The simulation fallback keeps the app usable.
- Attack vectors, application violations and scanned ports are estimated, not measured.
- Live events are aggregated at country level. IP-level data comes only from AbuseIPDB.
- Cloudflare Radar provides 24-hour top-10 rankings, refreshed hourly.
- AbuseIPDB and ip-api.com free tiers have usage limits. ip-api.com's free tier is for non-commercial use.
- History is stored in a JSON file in a single process, which suits a demo but not multi-user production.
- The anomaly detector is rule-based and detects volume surges, not attack content. It is not a replacement for an intrusion detection system.

## Future enhancements

- Dedicated panel for Cloudflare Radar top attack routes
- Database storage (SQLite or MongoDB) for long-term history and charts
- More threat-intelligence sources (AlienVault OTX, GreyNoise, abuse.ch)
- Seasonal baselines or machine-learning anomaly detection, with alert export by email or webhook
- City-level IP markers, light theme, mobile layout and PDF/CSV export
- 3D globe view and Docker deployment with HTTPS

## Documentation

A full project report (architecture, design, results and limitations) is available in [`docs/CyberPulse-Report.pdf`](docs/CyberPulse-Report.pdf).

## Acknowledgements

- [D3.js](https://d3js.org) and [world-atlas](https://github.com/topojson/world-atlas)
- [Radware Live Threat Map](https://livethreatmap.radware.com) (inspiration and data source)
- [AbuseIPDB](https://docs.abuseipdb.com), [Cloudflare Radar](https://developers.cloudflare.com/radar/) and [ip-api.com](https://ip-api.com/docs)
- [RFC 6455: The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)





**Malik Faheem**
GitHub: [@Malik-Faheem-Cyber](https://github.com/Malik-Faheem-Cyber)
