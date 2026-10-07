# VulnScan Pro — Manual Startup Guide

## Prerequisites

- **Python 3.10+** installed and on your `PATH`
- **pip** available
- **Git** (optional, only if cloning)

---

## Step 1 — Navigate to the Project Root

```powershell
cd "e:\Projects\Nessus 2.0\vulnscan-pro"
```

---

## Step 2 — Create & Activate a Virtual Environment

> Skip this step if `venv\` already exists and was already activated before.

```powershell
# Create the virtual environment (first time only)
python -m venv venv

# Activate it (Windows PowerShell)
.\venv\Scripts\Activate.ps1
```

> **If you get a script-execution error on PowerShell**, run this once:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

---

## Step 3 — Install Dependencies

```powershell
pip install -r requirements.txt
```

---

## Step 4 — Start the Application

```powershell
cd backend
python app.py
```

The server starts at **http://127.0.0.1:5000**

Open your browser and go to:
```
http://127.0.0.1:5000
```

---

## Step 5 (Optional) — Run the Backtest Suite

In a **separate terminal**, with the venv active:

```powershell
cd "e:\Projects\Nessus 2.0\vulnscan-pro\backend"
python -m tests.backtest_runner
```

Results are written to:
```
e:\Projects\Nessus 2.0\vulnscan-pro\backtest_results.txt
```

---

## Quick-Start (All-in-One)

Copy and paste this entire block into PowerShell from the project root:

```powershell
cd "e:\Projects\Nessus 2.0\vulnscan-pro"
.\venv\Scripts\Activate.ps1
cd backend
python app.py
```

---

## Stopping the App

Press **`Ctrl + C`** in the terminal where `app.py` is running.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` with the venv active |
| `Address already in use` on port 5000 | Kill the process: `netstat -ano \| findstr :5000` then `taskkill /PID <pid> /F` |
| PowerShell won't run `.ps1` scripts | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `python` not found | Use `python3` instead, or add Python to your `PATH` |
| Port scanner shows no results | Run the terminal **as Administrator** for raw socket access |
