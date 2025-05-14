# Stage 1: Builder - Install dependencies and compile translations
FROM python:3.12-slim AS builder

# Set working directory
WORKDIR /app

# Install build dependencies (minimal set)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster dependency installation
RUN pip install --no-cache-dir uv==0.4.27

# Copy Poetry files
COPY pyproject.toml poetry.lock ./

# Install dependencies using uv, excluding dev dependencies
RUN uv pip install --system --no-cache-dir -r <(poetry export --without-hashes --without dev)

# Copy locales for translation compilation
COPY locales/ ./locales/

# Compile translations
RUN pybabel compile -d locales -D messages

# Stage 2: Precompiler - Precompile Python bytecode
FROM python:3.12-slim AS precompiler

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy source code
COPY src/ ./src/

# Precompile Python bytecode for faster startup
RUN python -m compileall -b src/

# Stage 3: Runtime - Optimized production image
FROM python:3.12-slim AS runtime

# Metadata
LABEL maintainer="Architecture Team <architecture@example.com>"
LABEL version="0.1.0"
LABEL description="FastAPI Cedrina - Enterprise-grade FastAPI template"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    GUNICORN_WORKERS=4 \
    GUNICORN_TIMEOUT=120 \
    GUNICORN_LOG_LEVEL=info

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app && \
    chown appuser:appuser /app

# Set working directory
WORKDIR /app

# Install runtime dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Copy precompiled dependencies and code
COPY --from=precompiler /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=precompiler /usr/local/bin /usr/local/bin
COPY --from=precompiler /app/src/ /app/src/

# Copy compiled translations
COPY --from=builder /app/locales/ /app/locales/

# Copy environment files
COPY .env* /app/

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && chown appuser:appuser /app/entrypoint.sh

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Entrypoint with tini for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Run gunicorn with uvicorn workers for production
CMD ["sh", "-c", "/app/entrypoint.sh"]