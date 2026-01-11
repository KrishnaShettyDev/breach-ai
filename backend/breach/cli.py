#!/usr/bin/env python3
"""
BREACH.AI - Command Line Interface

Usage:
    breach-ai scan <target_url> [options]
    breach-ai --help

Examples:
    breach-ai scan https://target.com
    breach-ai scan https://target.com --duration 12 --aggressive
"""

import argparse
import asyncio
import sys

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from backend.breach.core.agent import BreachAgent, ScanConfig
from backend.breach.core.memory import Severity
from backend.breach.utils.logger import logger

console = Console()


def verify_ownership(target: str) -> bool:
    """Verify the user owns the target domain."""
    console.print("\n[yellow]IMPORTANT: Domain Ownership Verification[/yellow]")
    console.print(f"\nYou are about to scan: [bold]{target}[/bold]")
    console.print("\nBy proceeding, you confirm that:")
    console.print("  1. You own this domain/application, OR")
    console.print("  2. You have explicit written permission to test it")
    console.print("\n[red]Unauthorized scanning is illegal and unethical.[/red]")

    response = console.input("\nType 'I CONFIRM' to proceed: ")
    return response.strip() == "I CONFIRM"


def print_results_summary(result):
    """Print a summary of scan results."""
    console.print("\n")
    console.print(Panel.fit(
        f"[bold]Scan Complete[/bold]\n"
        f"Duration: {result.end_time - result.start_time}\n"
        f"Access Achieved: [red]{result.access_achieved.value.upper()}[/red]",
        title="BREACH.AI Results"
    ))

    # Findings table
    if result.findings:
        table = Table(title="Vulnerabilities Found")
        table.add_column("ID", style="cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="green")
        table.add_column("Target")

        severity_colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "green",
            "info": "dim",
        }

        for finding in result.findings:
            color = severity_colors.get(finding.severity.value, "white")
            table.add_row(
                finding.id,
                f"[{color}]{finding.severity.value.upper()}[/{color}]",
                finding.vuln_type,
                finding.endpoint or finding.target[:50]
            )

        console.print(table)
    else:
        console.print("[green]No vulnerabilities found.[/green]")

    # Summary stats
    counts = result.severity_counts()
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Critical: {counts['critical']}")
    console.print(f"  High: {counts['high']}")
    console.print(f"  Medium: {counts['medium']}")
    console.print(f"  Low: {counts['low']}")
    console.print(f"  Info: {counts['info']}")


async def run_scan(args):
    """Run the security scan."""
    logger.banner()

    # Verify ownership
    if not args.skip_verify:
        if not verify_ownership(args.target):
            console.print("[red]Scan cancelled. Ownership not confirmed.[/red]")
            return 1

    console.print(f"\n[bold green]Starting scan of {args.target}[/bold green]")
    console.print(f"Max duration: {args.duration} hours")
    console.print(f"Mode: {'Aggressive' if args.aggressive else 'Normal'}")
    console.print("\n" + "=" * 60 + "\n")

    # Create config
    config = ScanConfig(
        target_url=args.target,
        max_duration_hours=args.duration,
        aggressive_mode=args.aggressive,
        parallel_attacks=args.parallel,
        rate_limit_rps=args.rate_limit,
    )

    # Create and run agent
    agent = BreachAgent(config)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running security assessment...", total=None)
            result = await agent.run()
            progress.update(task, completed=True)

        # Print results
        print_results_summary(result)

        console.print(f"\n[bold]Report saved to:[/bold] ./reports/")

        return 0 if len(result.findings) == 0 else 1

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        agent.stop()
        return 130
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="BREACH.AI - Autonomous Security Assessment Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  breach-ai scan https://target.com
  breach-ai scan https://target.com --duration 12
  breach-ai scan https://target.com --aggressive --parallel 10
        """
    )

    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security assessment")
    scan_parser.add_argument("target", help="Target URL to scan")
    scan_parser.add_argument(
        "--duration", "-d",
        type=int,
        default=24,
        help="Maximum scan duration in hours (default: 24)"
    )
    scan_parser.add_argument(
        "--aggressive", "-a",
        action="store_true",
        help="Enable aggressive scanning mode"
    )
    scan_parser.add_argument(
        "--parallel", "-p",
        type=int,
        default=5,
        help="Number of parallel attack workers (default: 5)"
    )
    scan_parser.add_argument(
        "--rate-limit", "-r",
        type=int,
        default=50,
        help="Requests per second limit (default: 50)"
    )
    scan_parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip ownership verification (use responsibly)"
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    if args.command == "scan":
        exit_code = asyncio.run(run_scan(args))
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
