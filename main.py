"""
BREACH.AI - Main Entry Point
=============================
Railway/Render deployment entry point.
"""

from backend.api.server import app

# This is the ASGI app that uvicorn will run
__all__ = ["app"]
