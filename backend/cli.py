#!/usr/bin/env python3
"""
BREACH.AI CLI
=============

Main command-line interface for the BREACH.AI security assessment engine.

Usage:
    python -m backend.cli <target> [options]
    breach <target> [options]
    breach assess <target> --brutal [options]

Examples:
    breach https://example.com
    breach https://example.com --mode deep
    breach https://example.com --cookie "session=xxx"
    breach assess https://example.com --brutal --output ./reports
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Add parent to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Auto-load .env from project root BEFORE any other imports
def load_env():
    """Load .env file from project root."""
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file)
            return True
        except ImportError:
            # Fallback: parse .env manually if python-dotenv not installed
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        os.environ.setdefault(key, value)
            return True
    return False

# Load environment before importing modules that need it
_env_loaded = load_env()

from backend.breach.engine import BreachEngine


def create_parser():
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='breach',
        description='BREACH.AI - Autonomous Security Assessment Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    breach https://target.com                    # Quick scan
    breach https://target.com --mode deep        # Deep scan
    breach https://target.com --mode chainbreaker # Full exploitation
    breach https://target.com --cookie "session=xxx"  # Authenticated scan
    breach assess https://target.com --brutal    # Run ALL 60+ attack modules

Modes:
    quick       - Fast reconnaissance only
    normal      - Standard vulnerability scan (default)
    deep        - Deep exploitation with chaining
    chainbreaker - Maximum depth, extract everything

Commands:
    assess      - Run brutal one-time assessment with ALL modules
        """
    )

    subparsers = parser.add_subparsers(dest='command')

    # Assess subcommand - Brutal Assessment
    assess_parser = subparsers.add_parser('assess', help='Run brutal one-time assessment')
    assess_parser.add_argument('target', help='Target URL to assess')
    assess_parser.add_argument('--brutal', '-b', action='store_true',
                               help='Run ALL 60+ attack modules (recommended)')
    assess_parser.add_argument('--output', '-o', default='./breach_output',
                               help='Output directory for reports')
    assess_parser.add_argument('--aggressive', '-a', action='store_true',
                               help='Enable aggressive mode')
    assess_parser.add_argument('--timeout', '-t', type=int, default=300,
                               help='Timeout per module in seconds (default: 300)')
    assess_parser.add_argument('--concurrent', type=int, default=5,
                               help='Max concurrent modules (default: 5)')
    assess_parser.add_argument('--scope', action='append',
                               help='Additional scope domains')
    assess_parser.add_argument('--exclude', action='append',
                               help='Paths to exclude')
    assess_parser.add_argument('--skip-verify', action='store_true',
                               help='Skip ownership verification')
    assess_parser.add_argument('--verbose', '-v', action='store_true',
                               help='Verbose output')
    assess_parser.add_argument('--no-banner', action='store_true',
                               help='Skip banner')

    # Default scan command (legacy)
    parser.add_argument('target', nargs='?', help='Target URL to assess')
    parser.add_argument('--mode', '-m',
                       choices=['quick', 'normal', 'deep', 'chainbreaker'],
                       default='normal',
                       help='Scan mode (default: normal)')
    parser.add_argument('--cookie', '-c', help='Session cookie for authenticated testing')
    parser.add_argument('--header', '-H', action='append', help='Additional headers')
    parser.add_argument('--output', '-o', help='Output directory for results')
    parser.add_argument('--format', '-f',
                       choices=['json', 'html', 'markdown'],
                       default='json',
                       help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner')

    return parser


def print_banner():
    """Print the BREACH.AI banner."""
    banner = """
\033[1;31m
 ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗     █████╗ ██╗
 ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║    ██╔══██╗██║
 ██████╔╝██████╔╝█████╗  ███████║██║     ███████║    ███████║██║
 ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║    ██╔══██║██║
 ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║    ██║  ██║██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝
\033[0m
\033[1;37m         Autonomous Security Assessment Engine v4.0\033[0m
\033[90m         Learn. Chain. Break. Prove.\033[0m
    """
    print(banner)


def verify_ownership(target: str) -> bool:
    """Verify ownership before scanning."""
    from urllib.parse import urlparse

    # Check for blocked domains
    try:
        from backend.config import is_blocked_domain
        parsed = urlparse(target if target.startswith('http') else f'https://{target}')
        domain = parsed.netloc

        is_blocked, reason = is_blocked_domain(domain)
        if is_blocked:
            print(f"\n\033[31m[!] BLOCKED: {reason}\033[0m")
            print("\033[33mThis domain cannot be scanned. See documentation for allowed targets.\033[0m")
            return False
    except ImportError:
        pass  # Config module not available in standalone mode

    print("\n\033[33m[!] IMPORTANT: Domain Ownership Verification\033[0m")
    print(f"\nYou are about to assess: \033[1m{target}\033[0m")
    print("\nBy proceeding, you confirm that:")
    print("  1. You own this domain/application, OR")
    print("  2. You have explicit written permission to test it")
    print("\n\033[31mUnauthorized scanning is illegal and unethical.\033[0m")
    print()
    response = input("Type 'I CONFIRM' to proceed: ")
    return response.strip() == "I CONFIRM"


async def run_brutal_assessment(args):
    """Run the brutal one-time assessment."""
    from backend.breach.brutal_assessment import BrutalAssessment
    from backend.breach.report.brutal_report import AssessmentReportGenerator

    print("\n\033[1;35m[BRUTAL ASSESSMENT MODE]\033[0m")
    print(f"Target: {args.target}")
    print(f"Output: {args.output}")
    print(f"Aggressive: {args.aggressive}")
    print(f"Timeout per module: {args.timeout}s")
    print()

    # Verify ownership
    if not args.skip_verify:
        if not verify_ownership(args.target):
            print("\033[31m[!] Assessment cancelled. Ownership not confirmed.\033[0m")
            sys.exit(1)

    # Create and run assessment
    assessment = BrutalAssessment(
        target=args.target,
        scope=args.scope,
        exclude=args.exclude,
        aggressive=args.aggressive,
        timeout_per_module=args.timeout,
        max_concurrent=args.concurrent,
    )

    results = await assessment.run()

    # Generate reports
    print("\n\033[36m[*] Generating reports...\033[0m")
    generator = AssessmentReportGenerator(results, args.output)
    output_files = generator.generate_all()

    print("\n\033[32m[+] Reports generated:\033[0m")
    for report_type, filepath in output_files.items():
        print(f"    - {report_type}: {filepath}")

    # Print final summary
    print(f"\n\033[1mTotal Findings: {results.total_findings}\033[0m")
    print(f"Risk Score: \033[{'31' if results.risk_score >= 50 else '33' if results.risk_score >= 25 else '32'}m{results.risk_score}/100\033[0m")
    print(f"Estimated Breach Cost: \033[1m${results.estimated_breach_cost:,}\033[0m")

    return results


async def run_legacy_scan(args):
    """Run legacy scan mode."""
    deep_mode = args.mode in ['deep', 'chainbreaker']

    async with BreachEngine(deep_mode=deep_mode) as engine:
        await engine.breach(
            target=args.target,
            cookie=args.cookie,
        )

        if args.output:
            import json
            output_path = args.output if args.output.endswith('.json') else f"{args.output}.json"
            with open(output_path, 'w') as f:
                f.write(engine.json_report())
            print(f"\033[32m[+] Report saved: {output_path}\033[0m")


async def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    no_banner = getattr(args, 'no_banner', False)
    if not no_banner:
        print_banner()

    try:
        # Handle assess command
        if args.command == 'assess':
            await run_brutal_assessment(args)
        elif args.target:
            # Legacy scan mode
            await run_legacy_scan(args)
        else:
            parser.print_help()
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\033[33m[!] Interrupted by user\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\n\033[31m[!] Error: {e}\033[0m")
        verbose = getattr(args, 'verbose', False)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
