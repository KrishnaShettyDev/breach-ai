# BREACH v3.0 - Shannon-Style Autonomous Pentester
# Docker image for containerized execution

FROM python:3.12-slim

LABEL maintainer="Breach Team"
LABEL version="3.0.0"
LABEL description="Autonomous security scanner with proof-by-exploitation"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    build-essential \
    # Git for source analysis
    git \
    # Network tools
    curl \
    wget \
    nmap \
    # Chromium dependencies for Playwright
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml .
COPY src/ ./src/
COPY prompts/ ./prompts/
COPY configs/ ./configs/

# Install Python dependencies
RUN pip install --no-cache-dir -e ".[full]"

# Install Playwright browsers
RUN playwright install chromium
RUN playwright install-deps chromium

# Create directories
RUN mkdir -p /app/audit-logs /app/repos /app/configs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV BREACH_OUTPUT_DIR=/app/audit-logs

# Default command
ENTRYPOINT ["breach"]
CMD ["--help"]
