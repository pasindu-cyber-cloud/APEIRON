"""Analysis report generation (JSON always, PDF when reportlab is available)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..logging_config import get_logger
from ..storage import sample_report_dir

logger = get_logger("apeiron.reporting")


def build_report_dict(
    sample: dict[str, Any],
    static_info: dict[str, Any],
    detections: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    dumps: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": "apeiron.report/v1",
        "sample": sample,
        "static": {
            "file_format": static_info.get("file_format"),
            "arch": static_info.get("arch"),
            "bits": static_info.get("bits"),
            "platform": static_info.get("platform"),
            "overall_entropy": static_info.get("overall_entropy"),
            "likely_packed": static_info.get("likely_packed"),
            "high_entropy_sections": static_info.get("high_entropy_sections", []),
            "sections": static_info.get("sections", []),
            "imports": static_info.get("imports", {}),
            "imported_api_count": len(static_info.get("imported_api", [])),
        },
        "detections": detections,
        "iocs": iocs,
        "generated_rules": rules,
        "memory_dumps": dumps,
        "trace_event_count": len(events),
        "trace_events": events[:2000],
    }


def write_json_report(sample_id: str, report: dict[str, Any]) -> Path:
    path = sample_report_dir(sample_id) / "report.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    return path


def write_pdf_report(sample_id: str, report: dict[str, Any]) -> Path | None:
    try:
        from reportlab.lib import colors  # type: ignore
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
        from reportlab.lib.units import mm  # type: ignore
        from reportlab.platypus import (  # type: ignore
            ListFlowable,
            ListItem,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except Exception as exc:
        logger.warning("reportlab unavailable, skipping PDF: %s", exc)
        return None

    path = sample_report_dir(sample_id) / "report.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=A4, title="APEIRON Report")
    styles = getSampleStyleSheet()
    story: list = []
    sample = report["sample"]

    story.append(Paragraph("APEIRON Malware Analysis Report", styles["Title"]))
    story.append(Spacer(1, 6 * mm))

    verdict = sample.get("verdict", "unknown")
    story.append(Paragraph(f"<b>Verdict:</b> {verdict} "
                           f"(threat score {sample.get('threat_score', 0)}/100)",
                           styles["Heading2"]))

    meta_rows = [
        ["Filename", sample.get("filename", "")],
        ["SHA256", sample.get("sha256", "")],
        ["MD5", sample.get("md5", "")],
        ["Format", f"{report['static'].get('file_format')} / "
                   f"{report['static'].get('arch')} ({report['static'].get('bits')}-bit)"],
        ["Size", str(sample.get("size", 0)) + " bytes"],
        ["Tags", ", ".join(sample.get("tags", [])) or "-"],
    ]
    table = Table(meta_rows, colWidths=[35 * mm, 140 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1f2933")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Detections", styles["Heading2"]))
    if report["detections"]:
        items = [
            ListItem(Paragraph(
                f"<b>{d['name']}</b> [{d['severity']}] "
                f"({', '.join(d.get('mitre', []))}) - {d['description']}",
                styles["BodyText"]))
            for d in report["detections"]
        ]
        story.append(ListFlowable(items, bulletType="bullet"))
    else:
        story.append(Paragraph("No notable detections.", styles["BodyText"]))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph(f"Indicators of Compromise ({len(report['iocs'])})",
                           styles["Heading2"]))
    if report["iocs"]:
        ioc_rows = [["Type", "Value", "Count"]]
        for ioc in report["iocs"][:60]:
            ioc_rows.append([ioc["ioc_type"], ioc["value"][:90], str(ioc.get("count", 1))])
        ioc_table = Table(ioc_rows, colWidths=[25 * mm, 130 * mm, 15 * mm])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ]))
        story.append(ioc_table)
    else:
        story.append(Paragraph("No IOCs extracted.", styles["BodyText"]))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph(
        f"Memory dumps: {len(report['memory_dumps'])} | "
        f"Generated rules: {len(report['generated_rules'])} | "
        f"Trace events: {report['trace_event_count']}",
        styles["BodyText"]))

    try:
        doc.build(story)
    except Exception as exc:
        logger.warning("PDF build failed: %s", exc)
        return None
    return path
