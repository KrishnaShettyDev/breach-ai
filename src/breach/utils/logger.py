"""
BREACH.AI - Logging System

Provides structured logging with Rich formatting for terminal output.
"""

import logging
import sys
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for security-focused output
BREACH_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red bold",
    "critical": "red bold reverse",
    "success": "green bold",
    "finding": "magenta bold",
    "attack": "blue",
    "recon": "cyan dim",
})

console = Console(theme=BREACH_THEME)


class BreachFormatter(logging.Formatter):
    """Custom formatter with phase and attack context."""

    def format(self, record: logging.LogRecord) -> str:
        # Add custom attributes if not present
        if not hasattr(record, 'phase'):
            record.phase = ''
        if not hasattr(record, 'attack'):
            record.attack = ''

        return super().format(record)


class BreachLogger(logging.Logger):
    """Extended logger with security-specific methods."""

    def __init__(self, name: str, level: int = logging.DEBUG):
        super().__init__(name, level)
        self._phase = "INIT"
        self._target = ""

    def set_phase(self, phase: str):
        """Set the current scan phase for context."""
        self._phase = phase

    def set_target(self, target: str):
        """Set the current target for context."""
        self._target = target

    def finding(self, severity: str, title: str, details: str = ""):
        """Log a security finding."""
        severity_colors = {
            "critical": "[red bold]CRITICAL[/]",
            "high": "[yellow bold]HIGH[/]",
            "medium": "[blue]MEDIUM[/]",
            "low": "[green]LOW[/]",
            "info": "[dim]INFO[/]",
        }
        sev_display = severity_colors.get(severity.lower(), severity)
        console.print(f"[finding]FINDING[/] {sev_display} {title}")
        if details:
            console.print(f"  [dim]{details}[/]")

    def attack_start(self, attack_type: str, target: str):
        """Log the start of an attack."""
        console.print(f"[attack]ATTACK[/] {attack_type} -> {target}")

    def attack_success(self, attack_type: str, details: str = ""):
        """Log a successful attack."""
        console.print(f"[success]SUCCESS[/] {attack_type} [green]VULNERABLE[/]")
        if details:
            console.print(f"  [dim]{details}[/]")

    def attack_fail(self, attack_type: str):
        """Log a failed attack (not vulnerable)."""
        self.debug(f"FAIL {attack_type} - not vulnerable")

    def recon(self, module: str, message: str):
        """Log reconnaissance activity."""
        console.print(f"[recon]RECON[/] [{module}] {message}")

    def phase_start(self, phase: str):
        """Log the start of a new phase."""
        self._phase = phase
        console.print()
        console.rule(f"[bold]{phase}[/bold]", style="cyan")
        console.print()

    def phase_end(self, phase: str, stats: Optional[dict] = None):
        """Log the end of a phase with optional stats."""
        if stats:
            stat_str = " | ".join(f"{k}: {v}" for k, v in stats.items())
            console.print(f"[dim]{phase} complete: {stat_str}[/]")
        console.print()

    def banner(self):
        """Print the BREACH.AI banner."""
        banner = """
[bold red]
██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗    █████╗ ██╗
██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║   ██╔══██╗██║
██████╔╝██████╔╝█████╗  ███████║██║     ███████║   ███████║██║
██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║   ██╔══██║██║
██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║██╗██║  ██║██║
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝
[/bold red]
[dim]Autonomous Security Assessment Agent[/dim]
[dim]"We hack you before they do."[/dim]
"""
        console.print(banner)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    verbose: bool = False
) -> BreachLogger:
    """
    Set up logging for BREACH.AI.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for log output
        verbose: Enable verbose debug output
    """
    # Set up the custom logger class
    logging.setLoggerClass(BreachLogger)

    # Get or create the breach logger
    breach_logger = logging.getLogger("breach")
    breach_logger.__class__ = BreachLogger

    # Clear existing handlers
    breach_logger.handlers.clear()

    # Set level
    log_level = logging.DEBUG if verbose else getattr(logging, level.upper(), logging.INFO)
    breach_logger.setLevel(log_level)

    # Rich console handler for terminal output
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
    )
    rich_handler.setLevel(log_level)
    rich_handler.setFormatter(BreachFormatter("%(message)s"))
    breach_logger.addHandler(rich_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        ))
        breach_logger.addHandler(file_handler)

    return breach_logger


# Default logger instance
logger: BreachLogger = setup_logging()


def get_logger(name: str = "breach") -> BreachLogger:
    """Get a logger instance."""
    return logging.getLogger(name)
