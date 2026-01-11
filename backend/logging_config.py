"""
BREACH.AI - Structured Logging Configuration
==============================================
Configure structlog for the backend services.
"""

import logging
import sys
from typing import Any

import structlog

from backend.config import settings


def configure_logging() -> None:
    """Configure structured logging for the application."""

    # Determine if we're in development or production
    is_dev = settings.debug or settings.environment == "development"

    # Common processors
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if is_dev:
        # Development: Pretty console output
        structlog.configure(
            processors=shared_processors + [
                structlog.dev.ConsoleRenderer(colors=True)
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        # Production: JSON output for log aggregation
        structlog.configure(
            processors=shared_processors + [
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

        # Configure stdlib logging to work with structlog
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=logging.INFO,
        )


def get_logger(name: str) -> Any:
    """Get a structlog logger."""
    return structlog.get_logger(name)


# Configure on import
configure_logging()
