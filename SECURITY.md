# Security Policy

APEIRON executes **untrusted, potentially malicious binaries**. Treat every
deployment as hostile-by-default.

## Operating guidance

- Run APEIRON on a dedicated, disposable host or VM with no production data.
- The analysis `worker` performs **user-mode emulation** (Qiling) rather than
  native execution, which keeps the sample in an emulated CPU/OS context.
  Even so, never run it on a machine you care about.
- Place the host on an isolated network segment. The `worker` container drops
  all Linux capabilities and sets `no-new-privileges`.
- Keep `APEIRON_ANTI_EVASION=true` so the emulated environment masks common
  virtualization artifacts; this improves behavioral fidelity but is not a
  containment boundary.
- Set `APEIRON_API_KEY` in production to gate submission/retrieval endpoints.
- Do not expose the API directly to the internet without authentication and a
  reverse proxy enforcing TLS.

## Reporting a vulnerability

Open a private security advisory on the repository or email the maintainers.
Please do not file public issues for exploitable vulnerabilities.
