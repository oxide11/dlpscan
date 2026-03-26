"""Compliance reporting module for dlpscan.

Generates compliance reports from scan results, with framework-specific
pass/fail checks (PCI-DSS, HIPAA, SOC2, GDPR) and multiple output formats
(JSON, HTML, plain text).

Usage::

    from dlpscan.compliance import ComplianceReporter

    reporter = ComplianceReporter(title="Q1 Audit Report")
    reporter.add_scan_result(result, source="uploads/form.txt")
    reporter.add_findings(matches, source="api/endpoint")
    report = reporter.generate()

    print(reporter.to_json())
    print(reporter.to_text())
    with open("report.html", "w") as f:
        f.write(reporter.to_html())
"""

import json
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import escape as html_escape
from typing import Any, Dict, List, Set, Tuple

from .models import Match

# Avoid circular import — ScanResult lives in guard.core, import lazily.
# We accept any object with .findings (List[Match]) and .is_clean (bool).

# ---------------------------------------------------------------------------
# Compliance framework definitions
# ---------------------------------------------------------------------------

_FRAMEWORK_FAILING_CATEGORIES: Dict[str, Set[str]] = {
    "PCI-DSS": {"Credit Card Numbers", "Primary Account Numbers"},
    "HIPAA": {"Medical Identifiers"},
    "SOC2": {"Generic Secrets", "Cloud Provider Secrets", "Code Platform Secrets"},
    "GDPR": {"Contact Information", "Personal Identifiers"},
}


# ---------------------------------------------------------------------------
# ComplianceReport dataclass
# ---------------------------------------------------------------------------

@dataclass
class ComplianceReport:
    """Immutable snapshot of a compliance report.

    Attributes:
        title: Human-readable report title.
        generated_at: ISO 8601 timestamp of report generation.
        scan_summary: Aggregate statistics — total_scans, total_findings,
            categories_breakdown (category -> count), severity_breakdown.
        findings: Per-category/sub_category detail rows, each a dict with
            category, sub_category, count, sample_redacted, confidence_avg.
        compliance_status: Framework name -> bool (True = PASS).
    """

    title: str
    generated_at: str
    scan_summary: Dict[str, Any]
    findings: List[Dict[str, Any]]
    compliance_status: Dict[str, bool]


# ---------------------------------------------------------------------------
# ComplianceReporter
# ---------------------------------------------------------------------------

class ComplianceReporter:
    """Accumulates scan results and generates compliance reports.

    Thread-safe: all mutating methods acquire an internal lock.

    Args:
        title: Title for the generated report.
    """

    def __init__(self, title: str = "DLP Compliance Report") -> None:
        self._title = title
        self._lock = threading.Lock()
        self._matches: List[Tuple[Match, str]] = []  # (match, source)
        self._scan_count: int = 0

    # -- Accumulation API ---------------------------------------------------

    def add_scan_result(self, result: Any, source: str = "") -> None:
        """Accumulate all findings from a ScanResult.

        Args:
            result: A ``ScanResult`` instance (or any object with a
                ``findings`` attribute containing ``Match`` objects).
            source: Optional label describing where the scan was performed.
        """
        with self._lock:
            self._scan_count += 1
            for m in result.findings:
                self._matches.append((m, source))

    def add_findings(self, findings: List[Match], source: str = "") -> None:
        """Accumulate a list of raw Match objects.

        Args:
            findings: List of ``Match`` instances.
            source: Optional label describing the data source.
        """
        with self._lock:
            for m in findings:
                self._matches.append((m, source))

    # -- Report generation --------------------------------------------------

    def generate(self) -> ComplianceReport:
        """Build a ``ComplianceReport`` from all accumulated data.

        Returns:
            A new ``ComplianceReport`` snapshot.
        """
        with self._lock:
            matches = list(self._matches)
            scan_count = self._scan_count

        # Category / sub-category aggregation
        cat_counts: Dict[str, int] = defaultdict(int)
        group_data: Dict[Tuple[str, str], List[Match]] = defaultdict(list)

        for m, _src in matches:
            cat_counts[m.category] += 1
            group_data[(m.category, m.sub_category)].append(m)

        # Severity breakdown (based on confidence ranges)
        severity_counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        for m, _src in matches:
            if m.confidence >= 0.75:
                severity_counts["high"] += 1
            elif m.confidence >= 0.40:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1

        scan_summary: Dict[str, Any] = {
            "total_scans": scan_count,
            "total_findings": len(matches),
            "categories_breakdown": dict(cat_counts),
            "severity_breakdown": severity_counts,
        }

        # Findings detail rows
        findings_rows: List[Dict[str, Any]] = []
        for (cat, sub), group_matches in sorted(group_data.items()):
            count = len(group_matches)
            conf_avg = sum(m.confidence for m in group_matches) / count if count else 0.0
            sample = group_matches[0].redacted_text if group_matches else ""
            findings_rows.append({
                "category": cat,
                "sub_category": sub,
                "count": count,
                "sample_redacted": sample,
                "confidence_avg": round(conf_avg, 4),
            })

        compliance_status = self._check_compliance(cat_counts)

        return ComplianceReport(
            title=self._title,
            generated_at=datetime.now(timezone.utc).isoformat(),
            scan_summary=scan_summary,
            findings=findings_rows,
            compliance_status=compliance_status,
        )

    # -- Output formats -----------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Generate the report as a JSON string.

        Args:
            indent: JSON indentation level.

        Returns:
            JSON-encoded report string.
        """
        report = self.generate()
        return json.dumps(asdict(report), indent=indent)

    def to_text(self) -> str:
        """Generate the report as plain text.

        Returns:
            Human-readable plain text report.
        """
        report = self.generate()
        lines: List[str] = []
        sep = "=" * 72

        lines.append(sep)
        lines.append(f"  {report.title}")
        lines.append(f"  Generated: {report.generated_at}")
        lines.append(sep)
        lines.append("")

        # Summary
        s = report.scan_summary
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Total scans:    {s['total_scans']}")
        lines.append(f"  Total findings: {s['total_findings']}")
        lines.append("")

        lines.append("  Severity breakdown:")
        for sev, cnt in s["severity_breakdown"].items():
            lines.append(f"    {sev:<8s} {cnt}")
        lines.append("")

        lines.append("  Categories breakdown:")
        for cat, cnt in sorted(s["categories_breakdown"].items()):
            lines.append(f"    {cat:<40s} {cnt}")
        lines.append("")

        # Compliance
        lines.append("COMPLIANCE STATUS")
        lines.append("-" * 40)
        for fw, passed in sorted(report.compliance_status.items()):
            status = "PASS" if passed else "FAIL"
            lines.append(f"  {fw:<12s} {status}")
        lines.append("")

        # Findings detail
        if report.findings:
            lines.append("FINDINGS DETAIL")
            lines.append("-" * 40)
            for f in report.findings:
                lines.append(
                    f"  [{f['category']}] {f['sub_category']}  "
                    f"count={f['count']}  avg_conf={f['confidence_avg']:.4f}  "
                    f"sample={f['sample_redacted']}"
                )
            lines.append("")

        lines.append(sep)
        return "\n".join(lines)

    def to_html(self) -> str:
        """Generate the report as a standalone HTML document with inline CSS.

        Returns:
            Complete HTML string (no external dependencies).
        """
        report = self.generate()
        s = report.scan_summary
        e = html_escape  # shorthand

        parts: List[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append("<html lang=\"en\"><head><meta charset=\"utf-8\">")
        parts.append(f"<title>{e(report.title)}</title>")
        parts.append("<style>")
        parts.append(
            "body{font-family:Arial,Helvetica,sans-serif;margin:2em;color:#222;background:#fafafa}"
            "h1{color:#1a1a2e}h2{color:#16213e;border-bottom:2px solid #0f3460;padding-bottom:4px}"
            "table{border-collapse:collapse;width:100%;margin-bottom:1.5em}"
            "th,td{border:1px solid #ccc;padding:8px 12px;text-align:left}"
            "th{background:#0f3460;color:#fff}"
            "tr:nth-child(even){background:#e8e8e8}"
            ".pass{color:#27ae60;font-weight:bold}.fail{color:#c0392b;font-weight:bold}"
            ".badge{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:0.85em}"
            ".badge-high{background:#c0392b}.badge-medium{background:#f39c12}.badge-low{background:#27ae60}"
        )
        parts.append("</style></head><body>")

        # Header
        parts.append(f"<h1>{e(report.title)}</h1>")
        parts.append(f"<p>Generated: {e(report.generated_at)}</p>")

        # Summary table
        parts.append("<h2>Summary</h2>")
        parts.append("<table><tr><th>Metric</th><th>Value</th></tr>")
        parts.append(f"<tr><td>Total Scans</td><td>{s['total_scans']}</td></tr>")
        parts.append(f"<tr><td>Total Findings</td><td>{s['total_findings']}</td></tr>")
        for sev, cnt in s["severity_breakdown"].items():
            badge_cls = f"badge-{sev}"
            parts.append(
                f"<tr><td>Severity: {e(sev)}</td>"
                f"<td><span class=\"badge {badge_cls}\">{cnt}</span></td></tr>"
            )
        parts.append("</table>")

        # Category breakdown table
        parts.append("<h2>Category Breakdown</h2>")
        parts.append("<table><tr><th>Category</th><th>Count</th></tr>")
        for cat, cnt in sorted(s["categories_breakdown"].items()):
            parts.append(f"<tr><td>{e(cat)}</td><td>{cnt}</td></tr>")
        parts.append("</table>")

        # Compliance status table
        parts.append("<h2>Compliance Status</h2>")
        parts.append("<table><tr><th>Framework</th><th>Status</th></tr>")
        for fw, passed in sorted(report.compliance_status.items()):
            cls = "pass" if passed else "fail"
            label = "PASS" if passed else "FAIL"
            parts.append(f"<tr><td>{e(fw)}</td><td class=\"{cls}\">{label}</td></tr>")
        parts.append("</table>")

        # Findings detail table
        if report.findings:
            parts.append("<h2>Findings Detail</h2>")
            parts.append(
                "<table><tr>"
                "<th>Category</th><th>Sub-Category</th><th>Count</th>"
                "<th>Avg Confidence</th><th>Sample (Redacted)</th>"
                "</tr>"
            )
            for f in report.findings:
                parts.append(
                    f"<tr><td>{e(f['category'])}</td>"
                    f"<td>{e(f['sub_category'])}</td>"
                    f"<td>{f['count']}</td>"
                    f"<td>{f['confidence_avg']:.4f}</td>"
                    f"<td><code>{e(f['sample_redacted'])}</code></td></tr>"
                )
            parts.append("</table>")

        parts.append("</body></html>")
        return "\n".join(parts)

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _check_compliance(category_counts: Dict[str, int]) -> Dict[str, bool]:
        """Evaluate each compliance framework against observed categories.

        A framework passes if none of its failing categories have any findings.

        Returns:
            Dict mapping framework name to bool (True = PASS).
        """
        status: Dict[str, bool] = {}
        for framework, failing_cats in sorted(_FRAMEWORK_FAILING_CATEGORIES.items()):
            passed = all(
                category_counts.get(cat, 0) == 0
                for cat in failing_cats
            )
            status[framework] = passed
        return status
