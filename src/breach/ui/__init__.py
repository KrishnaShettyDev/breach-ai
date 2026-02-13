"""
BREACH.AI - Terminal UI Components
==================================
Rich-based terminal UI for the CLI scanner.
"""

from .console import console, print_banner, print_error, print_success, print_warning, print_info
from .dashboard import ScanDashboard

__all__ = [
    "console",
    "print_banner",
    "print_error",
    "print_success",
    "print_warning",
    "print_info",
    "ScanDashboard",
]
