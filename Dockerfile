FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    FLASK_DEBUG=0 \
    SAFE_MODE=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# The app imports `config` / `scanner.*` relative to the backend directory.
WORKDIR /app/backend

EXPOSE 5000

CMD ["python", "app.py"]
