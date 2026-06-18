"""Top-level analysis orchestrator.

Runs the full pipeline for a single sample and persists every artifact
(trace events, IOCs, rules, dumps, report) to the database while streaming
live trace events to the websocket bus.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..database import session_scope
from ..events import publish_event
from ..logging_config import get_logger
from ..models import (
    IOC,
    GeneratedRule,
    MemoryDump,
    Report,
    Sample,
    SampleStatus,
    TraceEvent,
)
from ..storage import sample_rules_dir
from . import (
    detectors,
    emulator,
    ioc_extractor,
    reporting,
    rule_generator,
    static_analysis,
)
from .types import Recorder

logger = get_logger("apeiron.engine")


def _publish(sample_id: str, kind: str, payload: dict) -> None:
    publish_event(sample_id, {"type": kind, **payload})


def run_analysis(sample_id: str) -> dict:
    """Execute analysis for ``sample_id``. Returns a small status summary."""
    with session_scope() as db:
        sample = db.get(Sample, sample_id)
        if sample is None:
            raise ValueError(f"sample {sample_id} not found")
        sample.status = SampleStatus.RUNNING
        sample.started_at = datetime.now(timezone.utc)
        stored_path = sample.stored_path
        db.flush()
    _publish(sample_id, "status", {"status": SampleStatus.RUNNING})

    recorder = Recorder(on_event=lambda evt: _publish(sample_id, "trace", evt.as_dict()))

    try:
        # 1) Static analysis -------------------------------------------------
        static_info = static_analysis.analyze_static(stored_path)
        recorder.record(
            "api",
            "static.analysis",
            args={"format": static_info["file_format"], "arch": static_info["arch"]},
            detail=f"entropy={static_info['overall_entropy']} "
            f"packed={static_info['likely_packed']}",
        )

        # 2) Dynamic emulation + API tracing --------------------------------
        emulated, dumps = emulator.run_emulation(stored_path, static_info, recorder, sample_id)

        # 3) IOC extraction --------------------------------------------------
        static_iocs = ioc_extractor.extract_from_strings(static_info.get("strings", []))
        runtime_iocs = ioc_extractor.extract_from_trace(recorder.events)
        iocs = ioc_extractor.merge_iocs(static_iocs, runtime_iocs)

        # 4) Heuristic detection --------------------------------------------
        detections, score, tags = detectors.run_detectors(static_info, recorder.events)
        detectors.mark_suspicious_events(recorder.events, detections)
        verdict = detectors.verdict_from_score(score)

        for det in detections:
            recorder.record(
                "api",
                f"detection:{det.name}",
                detail=det.description,
                severity=det.severity,
                suspicious=True,
                args={"mitre": det.mitre, "evidence": det.evidence[:6]},
            )

        # 5) Persist core results + generate rules --------------------------
        with session_scope() as db:
            sample = db.get(Sample, sample_id)
            sample.file_format = static_info["file_format"]
            sample.arch = static_info["arch"]
            sample.bits = int(static_info.get("bits", 0) or 0)
            sample.platform = static_info.get("platform", "unknown")
            sample.threat_score = score
            sample.verdict = verdict
            sample.tags = tags

            for evt in recorder.events:
                db.add(TraceEvent(sample_id=sample_id, **evt.as_dict()))
            for ioc in iocs:
                db.add(
                    IOC(
                        sample_id=sample_id,
                        ioc_type=ioc.ioc_type,
                        value=ioc.value[:2048],
                        context=ioc.context,
                        count=ioc.count,
                    )
                )
            for dump in dumps:
                db.add(
                    MemoryDump(
                        sample_id=sample_id,
                        reason=dump.reason,
                        address=dump.address,
                        size=dump.size,
                        path=dump.path,
                        sha256=dump.sha256,
                    )
                )

            # YARA + Sigma generation
            rules_dir = sample_rules_dir(sample_id)
            yara_name, yara_content = rule_generator.generate_yara(
                sample, static_info, iocs, detections
            )
            sigma_name, sigma_content = rule_generator.generate_sigma(sample, iocs, detections)
            yara_path = rules_dir / f"{yara_name}.yar"
            sigma_path = rules_dir / f"{sigma_name}.yml"
            yara_path.write_text(yara_content)
            sigma_path.write_text(sigma_content)
            db.add(
                GeneratedRule(
                    sample_id=sample_id,
                    kind="yara",
                    name=yara_name,
                    path=str(yara_path),
                    content=yara_content,
                )
            )
            db.add(
                GeneratedRule(
                    sample_id=sample_id,
                    kind="sigma",
                    name=sigma_name,
                    path=str(sigma_path),
                    content=sigma_content,
                )
            )

            sample_summary = {
                "id": sample.id,
                "filename": sample.filename,
                "size": sample.size,
                "md5": sample.md5,
                "sha1": sample.sha1,
                "sha256": sample.sha256,
                "verdict": verdict,
                "threat_score": score,
                "tags": tags,
            }

        # 6) Reports ---------------------------------------------------------
        report_dict = reporting.build_report_dict(
            sample=sample_summary,
            static_info=static_info,
            detections=[det.__dict__ for det in detections],
            iocs=[ioc.__dict__ for ioc in iocs],
            rules=[
                {"kind": "yara", "name": yara_name},
                {"kind": "sigma", "name": sigma_name},
            ],
            dumps=[dump.__dict__ for dump in dumps],
            events=[evt.as_dict() for evt in recorder.events],
        )
        json_path = reporting.write_json_report(sample_id, report_dict)
        pdf_path = reporting.write_pdf_report(sample_id, report_dict)

        with session_scope() as db:
            sample = db.get(Sample, sample_id)
            sample.status = SampleStatus.COMPLETED
            sample.completed_at = datetime.now(timezone.utc)
            db.add(
                Report(
                    sample_id=sample_id,
                    json_path=str(json_path),
                    pdf_path=str(pdf_path) if pdf_path else "",
                )
            )

        _publish(
            sample_id,
            "status",
            {
                "status": SampleStatus.COMPLETED,
                "verdict": verdict,
                "threat_score": score,
                "emulated": emulated,
            },
        )
        logger.info(
            "analysis complete sample=%s verdict=%s score=%d events=%d iocs=%d",
            sample_id,
            verdict,
            score,
            len(recorder.events),
            len(iocs),
        )
        return {
            "sample_id": sample_id,
            "status": SampleStatus.COMPLETED,
            "verdict": verdict,
            "threat_score": score,
            "events": len(recorder.events),
            "iocs": len(iocs),
            "dumps": len(dumps),
            "emulated": emulated,
        }

    except Exception as exc:
        logger.exception("analysis failed for %s", sample_id)
        with session_scope() as db:
            sample = db.get(Sample, sample_id)
            if sample is not None:
                sample.status = SampleStatus.FAILED
                sample.error = str(exc)[:2000]
                sample.completed_at = datetime.now(timezone.utc)
        _publish(sample_id, "status", {"status": SampleStatus.FAILED, "error": str(exc)})
        raise
