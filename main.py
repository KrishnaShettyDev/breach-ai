#!/usr/bin/env python3
"""
BREACH.AI - Main Entry Point
=============================

Usage:
    python main.py <target> [options]
    
Examples:
    python main.py https://example.com
    python main.py https://example.com --mode deep
    python main.py https://example.com --cookie "session=xxx"
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

if __name__ == '__main__':
    from backend.cli import main
    import asyncio
    asyncio.run(main())
