"""
Local development and production server launcher for TrustLens AI.
"""

import os
import sys
import uvicorn

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def main():
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("ENV", "development").lower() == "development"

    print(f"Starting TrustLens AI Server on http://{host}:{port} (Reload: {reload})")
    uvicorn.run("app.main:app", host=host, port=port, reload=reload)

if __name__ == "__main__":
    main()
