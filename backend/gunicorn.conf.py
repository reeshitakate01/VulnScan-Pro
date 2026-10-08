"""
Gunicorn configuration for VulnScan Pro (used in Docker / Linux).

IMPORTANT: a single worker is intentional. Scans run in background threads and
are throttled by an in-process semaphore (`scan_semaphore`); progress events
are shared via the database, so one threaded worker keeps that state coherent.
Scale out by raising threads, not workers.
"""
import os

bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"
workers = 1
worker_class = "gthread"
threads = int(os.getenv("GUNICORN_THREADS", "8"))

# SSE progress streams are long-lived; gthread heartbeats keep the worker
# alive, and the stream itself is bounded by SCAN_MAX_DURATION in the app.
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
