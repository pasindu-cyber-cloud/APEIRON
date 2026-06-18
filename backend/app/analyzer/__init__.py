"""APEIRON analysis engine.

Submodules:
  static_analysis  - format/arch detection, imports, sections, entropy, strings
  emulator         - Qiling user-mode emulation + API/syscall tracing
  ioc_extractor    - regex IOC extraction from strings and trace data
  detectors        - heuristic suspicious-behavior detection
  memory           - memory dump triggering / persistence
  anti_detect      - anti-sandbox-evasion (mask virtualization artifacts)
  rule_generator   - Sigma + YARA generation from observed behavior
  reporting        - JSON + PDF report generation
  engine           - orchestrates the full pipeline
"""
