.PHONY: build run-dev run-staging run-prod test lint format compile-translations update-translations

build:
	docker build -t Cedrina:latest .

run-dev:
	docker-compose up --build

run-local:
	poetry run bash -c "export PYTHONPATH=\$$PWD && uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload"

run-staging:
	docker run -d -p 8000:8000 --env-file .env.staging Cedrina:latest

run-prod:
	docker run -d -p 8000:8000 --env-file .env.production Cedrina:latest

test:
	poetry run bash -c "export PYTHONPATH=\$$PWD && pytest --cov=src --cov-report=html" -v

lint:
	poetry run ruff check src tests
	poetry run mypy src tests

format:
	poetry run black src tests
	poetry run ruff check --fix src tests

compile-translations:
	poetry run pybabel compile -d locales -D messages

update-translations:
	poetry run pybabel extract -F babel.cfg -o locales/messages.pot src/
	poetry run pybabel update -i locales/messages.pot -d locales -D messages