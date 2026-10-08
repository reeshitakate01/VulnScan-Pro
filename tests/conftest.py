"""Shared pytest fixtures / path setup for VulnScan Pro."""
import os
import pathlib
import sys
import uuid

import pytest

# Run the test DB in memory and keep SAFE_MODE on by default.
os.environ.setdefault("SAFE_MODE", "1")
os.environ.setdefault("DATABASE_URI", "sqlite://")  # in-memory
os.environ.setdefault("SECRET_KEY", "test-key")

# Make the backend package importable (scanner.*, config, app).
BACKEND = pathlib.Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def app_module():
    import app as appmod
    appmod.app.config["TESTING"] = True
    return appmod


@pytest.fixture()
def anon_client(app_module):
    """A test client with no logged-in user."""
    return app_module.app.test_client()


@pytest.fixture()
def client(app_module):
    """A test client already registered + logged in as a fresh user."""
    c = app_module.app.test_client()
    email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    # /register logs the new user in and sets the session cookie.
    c.post("/register", data={"email": email, "password": "password123"},
           follow_redirects=True)
    c._email = email  # handy for assertions
    return c
