# BREACH.AI - API Server Dockerfile
# ==================================
#
# Build: docker build -t breach-api .
# Run:   docker run -p 8000:8000 --env-file .env breach-api

FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# ==================================
# Builder stage
# ==================================
FROM base as builder

# Install Python dependencies
COPY requirements.txt .
RUN pip install --target=/app/deps -r requirements.txt

# ==================================
# Production stage
# ==================================
FROM base as production

# Copy dependencies from builder
COPY --from=builder /app/deps /usr/local/lib/python3.11/site-packages

# Create non-root user
RUN useradd -m -u 1000 breach && \
    chown -R breach:breach /app

# Copy application code
COPY --chown=breach:breach backend/ ./backend/
COPY --chown=breach:breach alembic/ ./alembic/
COPY --chown=breach:breach alembic.ini .
COPY --chown=breach:breach main.py .

# Switch to non-root user
USER breach

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application (use PORT env var for Railway)
CMD python -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
