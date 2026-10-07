"""Shared pytest fixtures / path setup for VulnScan Pro."""
import os
import pathlib
import sys

# Run the test DB in memory and keep SAFE_MODE on by default.
os.environ.setdefault("SAFE_MODE", "1")
os.environ.setdefault("DATABASE_URI", "sqlite://")  # in-memory
os.environ.setdefault("SECRET_KEY", "test-key")

# Make the backend package importable (scanner.*, config, app).
BACKEND = pathlib.Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
