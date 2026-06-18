# APEIRON Threat Model

APEIRON is a **defensive malware-analysis research prototype**. By design it
ingests and emulates files that may be malicious. This document states the
deployment assumptions, the risks involved, the mitigations currently in place,
and recommended hardening before any use beyond a local lab.

This document is intentionally honest: it describes what the project does and
does **not** protect against today.

## Intended use and assumptions

- APEIRON is for **defensive research and portfolio demonstration**.
- Run it **only in an isolated lab environment** on a disposable host or VM.
- **Do not expose the API or dashboard directly to the public internet.**
- Use **harmless / synthetic test samples** unless you are **legally
  authorized** to handle real malware and are working in an appropriately
  contained environment.
- Treat every analyzed file as hostile and every result volume as potentially
  contaminated.

## Assets to protect

- The analysis host and any other systems reachable from it.
- The integrity of analysis results and stored artifacts.
- Availability of the service (it should not be trivially crashable).
- Any credentials/secrets present in the environment.

## Risks

| Risk                       | Description                                                                                                                       |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Sandbox escape**         | Emulation/containment is not a hard security boundary. A crafted sample could attempt to break out of emulation or the container. |
| **Resource exhaustion**    | A sample (or flood of uploads) can consume CPU, memory, disk, or PIDs and cause denial of service.                                |
| **Malicious uploads**      | Uploaded files are untrusted and may target the parser, emulator, or downstream tooling.                                          |
| **API abuse**              | Without authentication/rate limiting, the submission API can be abused to run arbitrary analysis workloads.                       |
| **Unsafe file storage**    | Stored samples, dumps, and reports are derived from malicious input and must be handled carefully.                                |
| **Network abuse**          | If a sample is allowed network access, it could contact C2 infrastructure, scan, or attack other hosts.                           |
| **Information disclosure** | Misconfigured CORS or exposed endpoints could leak analysis data.                                                                 |

## Current mitigations

These are implemented in this repository:

- **Non-root containers** - images run as an unprivileged user.
- **Reduced container privileges** - the analysis `worker` sets
  `no-new-privileges` and drops all Linux capabilities in `docker-compose.yml`.
- **User-mode emulation** - Qiling executes the sample in an emulated CPU/OS
  context rather than natively on the host (defense in depth, not a guarantee).
- **API key authentication** - the `X-API-Key` header is required, and
  production startup is blocked when the key is missing or a placeholder.
- **Strict CORS** - explicit allow-list of origins; wildcards are rejected in
  production.
- **Upload size limits** - configurable via `APEIRON_MAX_UPLOAD_BYTES`.
- **File type validation** - only PE (`MZ`) and ELF (`\x7fELF`) magic bytes are
  accepted for submission.
- **Separated worker model** - submission (API) and execution (Celery worker)
  are separate processes/containers.
- **Configurable emulation timeout** - bounds per-sample emulation time.

## Known limitations

- Emulation and Docker isolation are **not** a guaranteed containment boundary.
- There is **no per-client rate limiting** built in.
- Stored artifacts are not encrypted at rest.
- Network egress from analysis is not sandboxed by the project itself.

## Recommended future hardening

Before using APEIRON for anything beyond a local demo, consider:

- A **dedicated, ephemeral analysis container** per sample.
- **Network isolation** for any actual sample execution (no egress, or a
  controlled fake-internet such as INetSim).
- **Read-only root filesystems** for service containers.
- **seccomp / AppArmor (or SELinux) profiles** on the worker.
- **Resource limits**: memory, CPU, and PID limits (e.g. compose `deploy.
resources` / `--pids-limit`).
- A **separate, quarantined storage volume** for malicious samples and dumps.
- **No public internet exposure**; place behind a VPN/bastion and TLS.
- **Audit logging** of submissions and result access.
- **Stricter file validation** and content scanning prior to analysis.
- **Per-client authentication and rate limiting** at a reverse proxy.

## Reporting

If you discover a security issue in APEIRON itself, please follow the process in
[`SECURITY.md`](../SECURITY.md).
