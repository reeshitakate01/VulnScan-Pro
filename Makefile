# VulnScan Pro — common developer tasks
.PHONY: install dev test lint run docker clean

install:
	pip install -r requirements.txt

dev:
	pip install -r requirements-dev.txt

test:
	pytest -q

lint:
	ruff check .

run:
	cd backend && python app.py

docker:
	docker compose up --build

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__ reports/*.pdf
