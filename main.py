"""
BREACH.AI - Main Entry Point
=============================
Railway/Render deployment entry point.
"""

import sys
import os

# Ensure the current directory is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Starting BREACH.AI...")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")
print(f"Files in current directory: {os.listdir('.')}")

try:
    print("Importing backend.api.server...")
    from backend.api.server import app
    print("Successfully imported app!")
except Exception as e:
    print(f"ERROR importing app: {e}")
    import traceback
    traceback.print_exc()

    # Create a minimal fallback app for debugging
    from fastapi import FastAPI
    app = FastAPI(title="BREACH.AI - Import Error")

    @app.get("/")
    def root():
        return {"error": str(e), "status": "import_failed"}

    @app.get("/health")
    def health():
        return {"status": "degraded", "error": str(e)}

# This is the ASGI app that uvicorn will run
__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
