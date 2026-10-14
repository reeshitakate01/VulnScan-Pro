FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

RUN pip install flask

COPY . .

EXPOSE 5001

# Seed the DB, then serve HTTP only (TLS isn't needed on the internal network).
# This container is NEVER exposed to the internet — only the scanner reaches it.
CMD ["sh", "-c", "python db.py && python -c \"from app import app; app.run(host='0.0.0.0', port=5001)\""]
