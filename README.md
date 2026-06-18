<div align="center">

# 🛡️ APEIRON

### Custom PE/ELF Malware Sandbox with API Tracing

Safely detonate Windows **PE** and Linux **ELF** binaries in a user-mode
emulator, trace every API/syscall, extract IOCs, auto-generate **YARA** &
**Sigma** rules, capture memory dumps on suspicious events, and explore it all
from a real-time analyst dashboard.

[![CI](https://github.com/pasindu-cyber-cloud/APEIRON/actions/workflows/ci.yml/badge.svg)](https://github.com/pasindu-cyber-cloud/APEIRON/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![React 18](https://img.shields.io/badge/react-18-61dafb)

</div>

> ⚠️ **APEIRON executes untrusted, potentially malicious code.** Always run it
> on a dedicated, disposable, network-isolated host. See [SECURITY.md](SECURITY.md).

---

## ✨ Features

| Capability | Description |
|---|---|
| **PE & ELF emulation** | User-mode emulation via the [Qiling Framework](https://qiling.io) (Unicorn engine) — the sample never runs natively on the host. |
| **Full API / syscall tracing** | Every resolved Windows API and Linux syscall is captured, categorized (file / registry / network / process / memory) and streamed live. |
| **IOC extraction** | IPs, domains, URLs, emails, mutexes, registry keys, file paths, hashes and BTC addresses from both static strings and runtime behavior. |
| **Auto rule generation** | Produces **YARA** and **Sigma** rules from observed behavior, written to disk and viewable/downloadable in the GUI. |
| **Memory dumps** | Triggered automatically on suspicious events (process injection, privilege escalation, anti-analysis) and stored for inspection. |
| **Heuristic detections** | MITRE ATT&CK-mapped behavior rules → threat score + verdict (benign → malicious). |
| **Anti-evasion** | Masks virtualization/debugger artifacts and humanizes timing so malware behaves authentically. |
| **Real-time dashboard** | React + Mantine UI: upload, live trace stream (WebSocket), IOC explorer, rule viewer, dump browser, timeline, search & filtering. |
| **Programmatic API** | REST endpoints for submission and result retrieval, with OpenAPI docs. |
| **Reports** | Detailed **JSON** and **PDF** reports per sample. |
| **Built-in YARA** | Ships with packer + anti-VM/anti-debug detection rules. |
| **Production-ready** | Dockerized microservices, Celery queue, SQLite/Postgres storage, structured logging, API-key auth, CI. |

---

## 🏗️ Architecture

```
                              ┌──────────────────────────────────────────┐
                              │            Analyst's Browser               │
                              │   React + Mantine SPA (live dashboard)     │
                              └───────────────┬───────────────┬────────────┘
                                  REST /api    │               │  WebSocket /ws
                                               ▼               ▼
                              ┌──────────────────────────────────────────┐
                              │          frontend (nginx)                  │
                              │   serves SPA + reverse-proxies API/WS      │
                              └───────────────┬────────────────────────────┘
                                              ▼
        ┌──────────────────────────────────────────────────────────────────────┐
        │                          api  (FastAPI / Uvicorn)                      │
        │   • POST /samples (upload)      • GET /samples, /trace, /iocs, /rules  │
        │   • WebSocket trace relay       • JSON/PDF reports   • /health /stats  │
        └───────┬───────────────────────────────────┬──────────────────┬────────┘
                │ enqueue (Celery)                   │ pub/sub          │ read/write
                ▼                                    ▼                  ▼
        ┌───────────────┐   broker / pubsub   ┌─────────────┐   ┌──────────────────┐
        │     redis     │◄───────────────────►│   worker    │   │   database       │
        │ broker+pubsub │   results / events  │  (Celery)   │   │ SQLite / Postgres│
        └───────────────┘                     └──────┬──────┘   └──────────────────┘
                                                      │
                                                      ▼
                          ┌──────────────────────────────────────────────┐
                          │            Analysis Engine                      │
                          │  static → emulation(Qiling) → IOC → detectors   │
                          │  → memory dumps → YARA/Sigma → JSON/PDF report  │
                          └──────────────────────────────────────────────┘
                                                      │
                                                      ▼
                                  ┌──────────────────────────────┐
                                  │  /data volume                 │
                                  │  uploads · dumps · reports ·   │
                                  │  generated_rules · rootfs      │
                                  └──────────────────────────────┘
```

### Analysis pipeline

```
 sample ─► [1] static analysis ─► [2] Qiling emulation + API tracing ─► [3] IOC extraction
        ─► [4] heuristic detectors (MITRE) ─► [5] memory dumps on triggers
        ─► [6] YARA + Sigma generation ─► [7] JSON + PDF report ─► persisted + streamed
```

---

## 🚀 Quick start

### Prerequisites
- Docker + Docker Compose v2
- ~4 GB RAM available to Docker

### Run

```bash
git clone https://github.com/pasindu-cyber-cloud/APEIRON.git
cd APEIRON
cp .env.example .env          # then edit secrets / API key
docker compose up --build
```

Open the dashboard at **http://localhost:8080**.
API docs (Swagger) at **http://localhost:8080/api/docs**.

### Enable full dynamic emulation (optional)

Static analysis + tracing scaffolding works out of the box. For full user-mode
execution, mount a [Qiling rootfs](https://github.com/qilingframework/rootfs)
and point `APEIRON_QILING_ROOTFS` at it:

```bash
git clone https://github.com/qilingframework/rootfs.git ./rootfs
# in .env:  APEIRON_QILING_ROOTFS=/data/rootfs   (mount ./rootfs to /data/rootfs)
```

Add a bind mount to the `worker` and `api` services in `docker-compose.yml`:

```yaml
    volumes:
      - apeiron-data:/data
      - ./rootfs:/data/rootfs:ro
```

> Without a rootfs (or when `APEIRON_ENABLE_EMULATION=false`), APEIRON gracefully
> falls back to static analysis and still extracts IOCs and generates rules.

### Local development (without Docker)

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export DATABASE_URL="sqlite:///./apeiron.sqlite3" APEIRON_DATA_DIR=./data \
       APEIRON_ENABLE_EMULATION=false
uvicorn app.main:app --reload                       # API on :8000
celery -A app.worker.celery_app worker -Q analysis  # worker (needs Redis)

# Frontend
cd ../frontend
npm install
npm run dev                                          # SPA on :5173 (proxies to :8000)
```

---

## 🔌 API reference

Base path: `/api`. If `APEIRON_API_KEY` is set, send it as the `X-API-Key` header.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/samples` | Upload a PE/ELF sample (multipart field `file`). Returns `{id, status, sha256}`. |
| `GET` | `/api/samples` | List samples. Query: `q`, `status`, `tag`, `limit`, `offset`. |
| `GET` | `/api/samples/{id}` | Full sample detail (IOCs, rules, dumps, report). |
| `DELETE` | `/api/samples/{id}` | Delete a sample and all artifacts. |
| `GET` | `/api/samples/{id}/trace` | Trace events. Query: `category`, `suspicious`, `q`, `limit`, `offset`. |
| `GET` | `/api/samples/{id}/report.json` | JSON report. |
| `GET` | `/api/samples/{id}/report.pdf` | PDF report. |
| `GET` | `/api/samples/{id}/dumps/{dump_id}` | Download a memory dump. |
| `GET` | `/api/iocs` | Cross-sample IOC search. Query: `type`, `q`, `sample_id`. |
| `GET` | `/api/iocs/stats` | IOC counts by type. |
| `GET` | `/api/rules` | Generated rules. Query: `kind` (yara/sigma), `sample_id`. |
| `GET` | `/api/rules/{id}/download` | Download a generated rule. |
| `GET` | `/api/rules/builtin` | List built-in YARA rules. |
| `GET` | `/api/health` | Service + component health. |
| `GET` | `/api/stats` | Dashboard statistics. |
| `WS` | `/ws/trace/{id}` | Live trace stream for one sample. |
| `WS` | `/ws/events` | Global analysis event feed. |

### Example: submit and poll

```bash
# Submit
SAMPLE=$(curl -s -F "file=@malware.exe" \
  -H "X-API-Key: $APEIRON_API_KEY" \
  http://localhost:8080/api/samples | jq -r .id)

# Poll status
curl -s -H "X-API-Key: $APEIRON_API_KEY" \
  http://localhost:8080/api/samples/$SAMPLE | jq '{status, verdict, threat_score}'

# Fetch the JSON report
curl -s -H "X-API-Key: $APEIRON_API_KEY" \
  http://localhost:8080/api/samples/$SAMPLE/report.json -o report.json
```

### Example: stream live trace (Python)

```python
import asyncio, websockets, json

async def main(sample_id):
    url = f"ws://localhost:8080/ws/trace/{sample_id}"
    async with websockets.connect(url) as ws:
        async for msg in ws:
            evt = json.loads(msg)
            if evt.get("type") == "trace":
                print(evt["category"], evt["name"], evt.get("args"))

asyncio.run(main("<sample-id>"))
```

---

## 🖥️ Screenshots

> Placeholders — replace with real captures in `docs/`.

| Dashboard | Live API trace | Generated rules |
|---|---|---|
| ![dashboard](docs/screenshot-dashboard.png) | ![trace](docs/screenshot-trace.png) | ![rules](docs/screenshot-rules.png) |

---

## 🗂️ Project layout

```
APEIRON/
├── docker-compose.yml          # redis · api · worker · frontend
├── .env.example                # configuration template
├── backend/
│   ├── Dockerfile
│   ├── requirements*.txt
│   ├── rules/                  # built-in YARA (packers, anti-VM)
│   ├── app/
│   │   ├── main.py             # FastAPI app (REST + WS)
│   │   ├── worker.py           # Celery app
│   │   ├── tasks.py            # analysis task
│   │   ├── queue.py            # lightweight producer for the API
│   │   ├── config.py · database.py · models.py · schemas.py
│   │   ├── events.py · security.py · storage.py · logging_config.py
│   │   ├── api/                # routers: samples, iocs, rules, ws, stats
│   │   └── analyzer/           # engine, static, emulator, ioc_extractor,
│   │                           # detectors, memory, anti_detect, rule_generator, reporting
│   └── tests/                  # pytest suite
├── frontend/                   # React + Vite + Mantine SPA + nginx
└── .github/workflows/ci.yml    # lint · tests · builds
```

---

## ⚙️ Configuration

Key environment variables (see [`.env.example`](.env.example) for the full list):

| Variable | Default | Purpose |
|---|---|---|
| `APEIRON_API_KEY` | _(empty)_ | If set, required via `X-API-Key`. |
| `DATABASE_URL` | sqlite in `/data` | Use Postgres for concurrency: `postgresql+psycopg2://…`. |
| `APEIRON_ENABLE_EMULATION` | `true` | Toggle Qiling emulation. |
| `APEIRON_QILING_ROOTFS` | `/data/rootfs` | Path to the Qiling rootfs. |
| `APEIRON_EMULATION_TIMEOUT` | `60` | Max emulation seconds per sample. |
| `APEIRON_ANTI_EVASION` | `true` | Mask VM/debugger artifacts. |
| `APEIRON_MAX_UPLOAD_BYTES` | `67108864` | Upload size cap (64 MiB). |

---

## 🧪 Testing

```bash
cd backend
pip install -r requirements-dev.txt
ruff check app tests
pytest --cov=app
```

The CI workflow runs backend lint + tests, builds the frontend, and validates
the Docker images on every push and PR.

---

## 🧭 Roadmap

- Network capture (PCAP) + simulated internet (INetSim-style)
- Full-system emulation option for kernel-mode behavior
- ATT&CK Navigator layer export
- Clustering of samples by behavior / ssdeep
- VirusTotal / MISP enrichment connectors

---

## 📜 License

[MIT](LICENSE) © APEIRON contributors.

APEIRON is a defensive security / malware-analysis tool. Use it only on
binaries you are authorized to analyze, and only in isolated environments.
