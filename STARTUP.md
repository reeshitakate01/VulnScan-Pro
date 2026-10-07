# VulnScan Pro — Startup Guide

For the full documentation see [README.md](README.md). This is the short version.

## Fastest: Docker

```bash
docker compose up --build
# open http://localhost:5000
```

## Manual (Windows PowerShell)

```powershell
# 1. From the project root, create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1
# If PowerShell blocks the script, run once:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# 2. Install dependencies
pip install -r requirements.txt

# 3. (optional) copy and edit configuration
copy .env.example .env

# 4. Start the app
cd backend
python app.py
```

The server starts at **http://127.0.0.1:5000**.

## Manual (macOS / Linux)

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # optional
cd backend && python app.py
```

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Activate the venv, then `pip install -r requirements.txt`. |
| Port 5000 in use | Set `PORT=5001` (env var) before starting. |
| "Target not allowed" error | `SAFE_MODE` is blocking an internal host. Add it to `SAFE_MODE_ALLOW`, or set `SAFE_MODE=0` **only** for hosts you are authorised to test. |
| Port scan shows nothing | Some environments need elevated privileges for raw sockets. |
