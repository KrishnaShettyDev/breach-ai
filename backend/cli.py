#!/usr/bin/env python3
"""
BREACH.AI CLI
=============

Main command-line interface for the BREACH.AI security assessment engine.

Usage:
    python -m backend.cli <target> [options]
    breach <target> [options]

Examples:
    breach https://example.com
    breach https://example.com --mode deep
    breach https://example.com --cookie "session=xxx"
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

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

Modes:
    quick       - Fast reconnaissance only
    normal      - Standard vulnerability scan (default)
    deep        - Deep exploitation with chaining
    chainbreaker - Maximum depth, extract everything
        """
    )
    
    parser.add_argument('target', help='Target URL to assess')
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


async def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    # Determine if deep mode
    deep_mode = args.mode in ['deep', 'chainbreaker']

    # Create and run engine
    try:
        async with BreachEngine(deep_mode=deep_mode) as engine:
            await engine.breach(
                target=args.target,
                cookie=args.cookie,
            )

            # Save output if requested
            if args.output:
                import json
                output_path = args.output if args.output.endswith('.json') else f"{args.output}.json"
                with open(output_path, 'w') as f:
                    f.write(engine.json_report())
                print(f"\033[32m[+] Report saved: {output_path}\033[0m")

    except KeyboardInterrupt:
        print("\n\033[33m[!] Interrupted by user\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\n\033[31m[!] Error: {e}\033[0m")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
