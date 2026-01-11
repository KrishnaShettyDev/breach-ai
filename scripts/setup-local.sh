#!/bin/bash
# BREACH.AI - Local Development Setup Script
# Run with: ./scripts/setup-local.sh

set -e

echo "=========================================="
echo "  BREACH.AI - Local Development Setup"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
echo "Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Install Docker Desktop from: https://docker.com/products/docker-desktop"
    exit 1
fi
echo -e "${GREEN}✓ Docker installed${NC}"

# Check Docker Compose
if ! docker compose version &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not available${NC}"
    echo "Docker Compose should be included with Docker Desktop"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose available${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python 3 installed${NC}"

# Check Node.js (for frontend)
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Warning: Node.js not installed (needed for frontend)${NC}"
    echo "Install from: https://nodejs.org"
fi

echo ""
echo "=========================================="
echo "  Step 1: Environment Configuration"
echo "=========================================="

# Create .env from template if it doesn't exist
if [ ! -f .env ]; then
    if [ -f .env.local ]; then
        cp .env.local .env
        echo -e "${GREEN}✓ Created .env from .env.local template${NC}"
        echo -e "${YELLOW}! Please edit .env with your API keys before running${NC}"
    else
        echo -e "${RED}Error: No .env.local template found${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

echo ""
echo "=========================================="
echo "  Step 2: Starting Docker Services"
echo "=========================================="

# Start PostgreSQL and Redis
echo "Starting PostgreSQL and Redis..."
docker compose up -d postgres redis

# Wait for services to be healthy
echo "Waiting for services to be ready..."
sleep 5

# Check PostgreSQL
if docker compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PostgreSQL is ready${NC}"
else
    echo -e "${RED}✗ PostgreSQL failed to start${NC}"
    docker compose logs postgres
    exit 1
fi

# Check Redis
if docker compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Redis is ready${NC}"
else
    echo -e "${RED}✗ Redis failed to start${NC}"
    docker compose logs redis
    exit 1
fi

echo ""
echo "=========================================="
echo "  Step 3: Python Dependencies"
echo "=========================================="

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate and install dependencies
echo "Installing Python dependencies..."
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo -e "${GREEN}✓ Python dependencies installed${NC}"

echo ""
echo "=========================================="
echo "  Step 4: Database Setup"
echo "=========================================="

# Run Alembic migrations
if [ -f alembic.ini ]; then
    echo "Running database migrations..."
    alembic upgrade head
    echo -e "${GREEN}✓ Database migrations complete${NC}"
else
    echo -e "${YELLOW}! Alembic not configured - skipping migrations${NC}"
fi

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "Services running:"
echo "  - PostgreSQL: localhost:5432"
echo "  - Redis:      localhost:6379"
echo ""
echo "Before starting the app, you need to:"
echo ""
echo -e "${YELLOW}1. Get Clerk API keys:${NC}"
echo "   - Go to https://dashboard.clerk.com"
echo "   - Create an application"
echo "   - Copy keys to .env"
echo ""
echo -e "${YELLOW}2. Get Stripe API keys:${NC}"
echo "   - Go to https://dashboard.stripe.com/test/apikeys"
echo "   - Copy TEST keys to .env"
echo ""
echo -e "${YELLOW}3. Get Anthropic API key:${NC}"
echo "   - Go to https://console.anthropic.com"
echo "   - Copy key to .env"
echo ""
echo "Then start the backend:"
echo "  source venv/bin/activate"
echo "  python main.py"
echo ""
echo "Start the frontend (in another terminal):"
echo "  cd frontend && npm install && npm run dev"
echo ""
echo "Optional: Start database admin UIs:"
echo "  docker compose --profile tools up -d"
echo "  - pgAdmin:          http://localhost:5050"
echo "  - Redis Commander:  http://localhost:8081"
echo ""
