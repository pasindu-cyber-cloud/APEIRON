<div align="center">

# 🛡️ APEIRON

### Defensive PE/ELF Malware-Analysis Sandbox (Research Prototype)

A Dockerized defensive malware-analysis sandbox prototype for Windows **PE** and
Linux **ELF** files. It combines a production-style microservice architecture
with static analysis, emulation-assisted behavior tracing, IOC extraction,
YARA/Sigma rule generation, and a React analyst dashboard.

[![CI](https://github.com/pasindu-cyber-cloud/APEIRON/actions/workflows/ci.yml/badge.svg)](https://github.com/pasindu-cyber-cloud/APEIRON/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![React 18](https://img.shields.io/badge/react-18-61dafb)

</div>

> ⚠️ **APEIRON analyzes untrusted, potentially malicious files.** Run it only on
> a dedicated, disposable, network-isolated host. See the
> [Security Notice](#-security-notice), [`SECURITY.md`](SECURITY.md), and the
> [threat model](docs/threat-model.md).

---

## 📌 Overview

APEIRON is a defensive malware-analysis sandbox prototype for PE/ELF files. It
combines **FastAPI**, **Celery**, **Redis**, **Qiling-based emulation**, **IOC
extraction**, **YARA/Sigma rule generation**, and a **React analyst dashboard**
to demonstrate modern security-engineering and DevSecOps practices.

It provides static analysis, emulation-assisted behavior tracing, IOC
extraction, and detection-rule generation, surfaced through a real-time
dashboard and a documented REST/WebSocket API.

## 🚦 Project Status

**Research prototype / portfolio project.** It is **not** intended to be exposed
directly to the public internet or used as a replacement for a hardened
enterprise malware sandbox. The emulation and container isolation provide
defense in depth, not a guaranteed containment boundary. Designed for local
research and portfolio demonstration.

---

## ✨ Features

| Capability                          | Description                                                                                                                                                                  |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **PE & ELF emulation**              | Emulation-assisted analysis via the [Qiling Framework](https://qiling.io) (Unicorn engine) — the sample runs in an emulated CPU/OS context rather than natively on the host. |
| **High-signal API/syscall tracing** | Captures high-signal API/syscall activity through Qiling's logging and selected hooks, categorized (file / registry / network / process / memory) and streamed live.         |
| **IOC extraction**                  | IPs, domains, URLs, emails, mutexes, registry keys, file paths, hashes and BTC addresses from static strings and observed behavior.                                          |
| **Rule generation**                 | Generates **YARA** and **Sigma** rules from observed indicators, written to disk and viewable/downloadable in the dashboard.                                                 |
| **Memory dumps**                    | Captured on selected suspicious events (e.g. process-injection APIs) and stored for inspection.                                                                              |
| **Heuristic detections**            | MITRE ATT&CK-mapped behavior heuristics → threat score + verdict (benign → malicious).                                                                                       |
| **Anti-evasion helpers**            | Best-effort masking of common virtualization/debugger artifacts and timing humanization to reduce trivial sandbox evasion (not exhaustive).                                  |
| **Real-time dashboard**             | React + Mantine UI: upload, live trace stream (WebSocket), IOC explorer, rule viewer, dump browser, timeline, search & filtering.                                            |
| **Programmatic API**                | REST endpoints for submission and result retrieval, with OpenAPI docs.                                                                                                       |
| **Reports**                         | Per-sample **JSON** and **PDF** reports.                                                                                                                                     |
| **Built-in YARA**                   | Ships with packer and anti-VM/anti-debug detection rules.                                                                                                                    |
| **Production-style architecture**   | Dockerized microservices, Celery queue, SQLite/Postgres storage, structured logging, API-key auth, strict CORS, and CI.                                                      |

> APEIRON aims to demonstrate the architecture and workflow of a modern malware
> sandbox. Dynamic coverage depends on the emulation environment (see
> [emulation setup](#enable-dynamic-emulation-optional)); without it the system
> still performs static analysis, IOC extraction, and rule generation.

---

## 🔒 Security Notice

- APEIRON is for **defensive research and portfolio demonstration only**.
- **Do not upload or execute real malware** unless you are **legally authorized**
  and working in an **isolated lab** environment.
- **Do not expose this service publicly** without significant additional
  hardening (authentication at the edge, network isolation, resource limits).
- Review the **[threat model](docs/threat-model.md)** for deployment
  assumptions, risks, current mitigations, and recommended hardening.
- In production mode the backend **refuses to start** with a missing/placeholder
  API key or a wildcard CORS configuration (see [Configuration](#️-configuration)).

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

### Requirements

- Docker + Docker Compose v2
- ~4 GB RAM available to Docker

### 1. Configure the environment

```bash
git clone https://github.com/pasindu-cyber-cloud/APEIRON.git
cd APEIRON
cp .env.example .env
```

Then edit `.env`:

- Set a strong **`APEIRON_API_KEY`** (the placeholder value blocks production startup).
- Set **`APEIRON_ALLOWED_ORIGINS`** to the origin(s) your browser will use.
- For relaxed local startup checks, set **`APEIRON_ENV=development`**.

### 2. Start the stack

```bash
docker compose up --build
```

- Dashboard → **http://localhost:8080**
- API docs (Swagger) → **http://localhost:8080/api/docs**
- Health → **http://localhost:8080/api/health**

### 3. Stop the stack

```bash
docker compose down          # stop containers
docker compose down -v       # also remove the data volume (samples, dumps, db)
```

### Enable dynamic emulation (optional)

Static analysis, IOC extraction, and rule generation work out of the box. For
emulation-assisted behavior tracing you need two things: (1) the optional
emulation Python extras, and (2) a
[Qiling rootfs](https://github.com/qilingframework/rootfs).

The Docker image installs the emulation extras (`requirements-emulation.txt`) on
a best-effort basis. For a local checkout:

```bash
cd backend
pip install -r requirements-emulation.txt   # qiling, unicorn, ssdeep
```

Then mount a rootfs and point `APEIRON_QILING_ROOTFS` at it:

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

> Without a rootfs (or when `APEIRON_ENABLE_EMULATION=false`), APEIRON falls back
> to static analysis and still extracts IOCs and generates rules.

### Local development (without Docker)

```bash
# Backend (needs a running Redis for the worker)
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export APEIRON_ENV=development \
       DATABASE_URL="sqlite:///./apeiron.sqlite3" \
       APEIRON_DATA_DIR=./data \
       APEIRON_ENABLE_EMULATION=false
uvicorn app.main:app --reload                       # API on :8000
celery -A app.worker.celery_app worker -Q analysis  # worker (separate shell)

# Frontend
cd ../frontend
npm install
npm run dev                                          # SPA on :5173 (proxies to :8000)
```

---

## 🔌 API reference

Base path: `/api`. When an API key is configured, send it as the `X-API-Key`
header on every request.

| Method   | Endpoint                            | Description                                                                      |
| -------- | ----------------------------------- | -------------------------------------------------------------------------------- |
| `POST`   | `/api/samples`                      | Upload a PE/ELF sample (multipart field `file`). Returns `{id, status, sha256}`. |
| `GET`    | `/api/samples`                      | List samples. Query: `q`, `status`, `tag`, `limit`, `offset`.                    |
| `GET`    | `/api/samples/{id}`                 | Full sample detail (IOCs, rules, dumps, report).                                 |
| `DELETE` | `/api/samples/{id}`                 | Delete a sample and all artifacts.                                               |
| `GET`    | `/api/samples/{id}/trace`           | Trace events. Query: `category`, `suspicious`, `q`, `limit`, `offset`.           |
| `GET`    | `/api/samples/{id}/report.json`     | JSON report.                                                                     |
| `GET`    | `/api/samples/{id}/report.pdf`      | PDF report.                                                                      |
| `GET`    | `/api/samples/{id}/dumps/{dump_id}` | Download a memory dump.                                                          |
| `GET`    | `/api/iocs`                         | Cross-sample IOC search. Query: `type`, `q`, `sample_id`.                        |
| `GET`    | `/api/iocs/stats`                   | IOC counts by type.                                                              |
| `GET`    | `/api/rules`                        | Generated rules. Query: `kind` (yara/sigma), `sample_id`.                        |
| `GET`    | `/api/rules/{id}/download`          | Download a generated rule.                                                       |
| `GET`    | `/api/rules/builtin`                | List built-in YARA rules.                                                        |
| `GET`    | `/api/health`                       | Service + component health.                                                      |
| `GET`    | `/api/stats`                        | Dashboard statistics.                                                            |
| `WS`     | `/ws/trace/{id}`                    | Live trace stream for one sample.                                                |
| `WS`     | `/ws/events`                        | Global analysis event feed.                                                      |

### Using the API key header

```bash
export APEIRON_API_KEY="your-strong-key"   # must match the backend value
curl -H "X-API-Key: $APEIRON_API_KEY" http://localhost:8080/api/stats
```

### Example: submit and poll

```bash
# Submit a (harmless, authorized) sample
SAMPLE=$(curl -s -F "file=@sample.bin" \
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
import asyncio, json, websockets

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

> Screenshots will be added after local demo capture. Planned views: the analyst
> dashboard, the live API trace stream, and the generated YARA/Sigma rules.

---

## 🗂️ Project layout

```
APEIRON/
├── docker-compose.yml          # redis · api · worker · frontend
├── .env.example                # configuration template
├── docs/
│   └── threat-model.md         # risks, mitigations, hardening guidance
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

| Variable                    | Default                                       | Purpose                                                                                                     |
| --------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `APEIRON_ENV`               | `production`                                  | `production` enables strict startup checks; `development` relaxes them.                                     |
| `APEIRON_API_KEY`           | `change-this-before-running`                  | Shared secret for the `X-API-Key` header. **Production startup fails** if empty or left as the placeholder. |
| `APEIRON_ALLOWED_ORIGINS`   | `http://localhost:5173,http://localhost:8080` | Comma-separated CORS allow-list. Wildcards (`*`) are rejected in production.                                |
| `DATABASE_URL`              | sqlite in `/data`                             | Use Postgres for concurrency: `postgresql+psycopg2://…`.                                                    |
| `APEIRON_ENABLE_EMULATION`  | `true`                                        | Toggle Qiling emulation.                                                                                    |
| `APEIRON_QILING_ROOTFS`     | `/data/rootfs`                                | Path to the Qiling rootfs.                                                                                  |
| `APEIRON_EMULATION_TIMEOUT` | `60`                                          | Max emulation seconds per sample.                                                                           |
| `APEIRON_ANTI_EVASION`      | `true`                                        | Enable best-effort masking of VM/debugger artifacts.                                                        |
| `APEIRON_MAX_UPLOAD_BYTES`  | `67108864`                                    | Upload size cap (64 MiB).                                                                                   |

**Startup safety:** in `production` mode the backend refuses to start if the API
key is missing/placeholder or if CORS is wildcard/empty. In `development` mode it
starts but logs clear warnings.

---

## 🧪 Testing & checks

```bash
# Backend: lint + tests
cd backend
pip install -r requirements-dev.txt
ruff format --check app tests
ruff check app tests
pytest --cov=app

# Frontend: lint + build
cd ../frontend
npm install
npm run lint
npm run build
```

CI runs all of the above (backend install/lint/tests, frontend install/lint/build)
plus a Docker Compose build on every push and PR. Frontend lint failures fail CI.

---

## 🧭 Roadmap

- Network capture (PCAP) + simulated internet (INetSim-style)
- Stronger isolation: per-sample ephemeral containers, seccomp/AppArmor, resource limits
- ATT&CK Navigator layer export
- Clustering of samples by behavior / fuzzy hash
- VirusTotal / MISP enrichment connectors

---

## 📜 License

[MIT](LICENSE) © APEIRON contributors.

APEIRON is a defensive security / malware-analysis research tool. Use it only on
files you are authorized to analyze, and only in isolated environments.
