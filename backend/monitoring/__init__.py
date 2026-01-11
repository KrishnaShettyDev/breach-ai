"""
BREACH.AI - Monitoring Module
==============================
Observability components: metrics, alerts, and health checks.
"""

from backend.monitoring.metrics import (
    SCANS_IN_PROGRESS,
    SCANS_TOTAL,
    FINDINGS_TOTAL,
    increment_scan_counter,
    record_finding,
)
from backend.monitoring.alerts import send_scan_failure_alert

__all__ = [
    "SCANS_IN_PROGRESS",
    "SCANS_TOTAL",
    "FINDINGS_TOTAL",
    "increment_scan_counter",
    "record_finding",
    "send_scan_failure_alert",
]
