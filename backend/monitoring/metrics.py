"""
BREACH.AI - Prometheus Metrics
===============================
Application metrics for monitoring and alerting.
"""

import structlog

logger = structlog.get_logger(__name__)

# Try to import prometheus_client, gracefully handle if not installed
try:
    from prometheus_client import Counter, Histogram, Gauge, Info

    PROMETHEUS_AVAILABLE = True

    # Application info
    APP_INFO = Info("breach_app", "Application information")
    APP_INFO.info({
        "version": "4.0.0",
        "name": "BREACH.AI Enterprise",
    })

    # Scan metrics
    SCANS_IN_PROGRESS = Gauge(
        "breach_scans_in_progress",
        "Number of scans currently running"
    )

    SCANS_TOTAL = Counter(
        "breach_scans_total",
        "Total number of scans",
        ["status", "mode"]
    )

    SCAN_DURATION = Histogram(
        "breach_scan_duration_seconds",
        "Scan duration in seconds",
        ["mode"],
        buckets=[60, 300, 600, 1800, 3600, 7200]
    )

    # Finding metrics
    FINDINGS_TOTAL = Counter(
        "breach_findings_total",
        "Total findings discovered",
        ["severity", "category"]
    )

    # API metrics (if not using middleware)
    API_REQUESTS = Counter(
        "breach_api_requests_total",
        "Total API requests",
        ["method", "endpoint", "status"]
    )

    API_LATENCY = Histogram(
        "breach_api_latency_seconds",
        "API request latency",
        ["method", "endpoint"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )

    # Organization metrics
    ORGANIZATIONS_TOTAL = Gauge(
        "breach_organizations_total",
        "Total number of organizations"
    )

    ACTIVE_SUBSCRIPTIONS = Gauge(
        "breach_active_subscriptions",
        "Number of active paid subscriptions",
        ["tier"]
    )

except ImportError:
    PROMETHEUS_AVAILABLE = False

    # Dummy metrics when prometheus_client is not installed
    class DummyMetric:
        def inc(self, *args, **kwargs): pass
        def dec(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self

    SCANS_IN_PROGRESS = DummyMetric()
    SCANS_TOTAL = DummyMetric()
    SCAN_DURATION = DummyMetric()
    FINDINGS_TOTAL = DummyMetric()
    API_REQUESTS = DummyMetric()
    API_LATENCY = DummyMetric()
    ORGANIZATIONS_TOTAL = DummyMetric()
    ACTIVE_SUBSCRIPTIONS = DummyMetric()

    logger.warning("prometheus_client_not_available")


def increment_scan_counter(status: str, mode: str) -> None:
    """Increment the scan counter."""
    if PROMETHEUS_AVAILABLE:
        SCANS_TOTAL.labels(status=status, mode=mode).inc()


def record_scan_duration(duration_seconds: float, mode: str) -> None:
    """Record scan duration."""
    if PROMETHEUS_AVAILABLE:
        SCAN_DURATION.labels(mode=mode).observe(duration_seconds)


def record_finding(severity: str, category: str) -> None:
    """Record a finding."""
    if PROMETHEUS_AVAILABLE:
        FINDINGS_TOTAL.labels(severity=severity, category=category).inc()


def update_scans_in_progress(count: int) -> None:
    """Update the gauge for scans in progress."""
    if PROMETHEUS_AVAILABLE:
        SCANS_IN_PROGRESS.set(count)


def record_api_request(method: str, endpoint: str, status: int, duration: float) -> None:
    """Record an API request."""
    if PROMETHEUS_AVAILABLE:
        API_REQUESTS.labels(method=method, endpoint=endpoint, status=str(status)).inc()
        API_LATENCY.labels(method=method, endpoint=endpoint).observe(duration)
