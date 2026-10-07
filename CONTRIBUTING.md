# Contributing

Thanks for your interest in improving VulnScan Pro!

## Development setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows (use source venv/bin/activate on *nix)
pip install -r requirements-dev.txt
```

## Before you open a PR

```bash
ruff check .    # lint
pytest          # tests must pass
```

CI runs both automatically on every push and pull request.

## Adding a scanner module

1. Create `backend/scanner/<name>_scanner.py` with a `run_<name>_scan(url)`
   entry point. Route all HTTP through `scanner.safe_requests` so the SSRF
   guard and shared session apply. Keep checks **non-destructive** by default.
2. Return findings in the unified shape
   `{title, severity, description, recommendation, vulnerable, finding_key}`.
3. Wire it into `backend/app.py` (orchestration + flattening),
   `score_engine.py`, `time_estimator.py`, `knowledge_base/owasp_mapping.json`
   (add a `finding_key` entry) and the frontend module list in
   `frontend/static/js/main.js`.
4. Add tests under `tests/`.

## Commit style

Small, focused commits with an imperative subject line.
