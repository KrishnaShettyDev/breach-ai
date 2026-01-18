# BREACH.AI - Simple Dockerfile for Railway
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY main.py .

# Expose port
EXPOSE 8000

# Set default port
ENV PORT=8000

# Run the application
CMD python -m uvicorn main:app --host 0.0.0.0 --port $PORT
