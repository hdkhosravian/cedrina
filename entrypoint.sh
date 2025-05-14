#!/bin/bash

set -e

# Load environment file based on APP_ENV
APP_ENV=${APP_ENV:-development}
ENV_FILE=".env"

if [ "$APP_ENV" != "development" ]; then
  ENV_FILE=".env.$APP_ENV"
fi

if [ -f "$ENV_FILE" ]; then
  echo "Loading environment from $ENV_FILE"
  set -a
  source "$ENV_FILE"
  set +a
else
  echo "Warning: Environment file $ENV_FILE not found"
fi

# Set Gunicorn workers based on environment variable or default
WORKERS=${GUNICORN_WORKERS:-4}
TIMEOUT=${GUNICORN_TIMEOUT:-120}
LOG_LEVEL=${GUNICORN_LOG_LEVEL:-info}

# Run gunicorn with uvicorn workers
exec gunicorn \
  --workers "$WORKERS" \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind "${API_HOST:-0.0.0.0}:${API_PORT:-8000}" \
  --timeout "$TIMEOUT" \
  --log-level "$LOG_LEVEL" \
  --access-logfile - \
  --error-logfile - \
  src.main:app