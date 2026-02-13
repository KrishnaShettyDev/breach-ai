"""BREACH.AI Report Generation"""

from breach.report.generator import ReportGenerator, ReportConfig
from breach.report.brutal_report import (
    BrutalReportGenerator,
    AssessmentReportGenerator,
    generate_assessment_report,
)

__all__ = [
    "ReportGenerator",
    "ReportConfig",
    "BrutalReportGenerator",
    "AssessmentReportGenerator",
    "generate_assessment_report",
]
