# BREACH.AI

<div align="center">

**Autonomous AI-Powered Penetration Testing Platform**

*"We hack you before they do."*

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Next.js 14](https://img.shields.io/badge/Next.js-14-black.svg)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## Overview

BREACH.AI is an enterprise-grade autonomous security assessment platform that uses AI-powered decision making to conduct comprehensive penetration tests. Unlike traditional scanners that check for known vulnerabilities, BREACH.AI thinks like a real attacker—chaining vulnerabilities, escalating privileges, and proving complete compromise.

### Two Ways to Use

| Mode | Description |
|------|-------------|
| **CLI Tool** | Standalone command-line scanner for quick assessments |
| **Web Platform** | Full SaaS with dashboard, team management, and billing |

---

## Key Features

### AI-Powered Intelligence
- **Claude-based Decision Engine** - Makes strategic attack decisions like a human pentester
- **Adaptive Learning** - Learns from failed attempts and adjusts strategy
- **Attack Chaining** - Automatically chains multiple vulnerabilities for deeper exploitation
- **Custom Script Generation** - Generates Python/JavaScript for complex exploitation scenarios

### Comprehensive Scanning
- **40+ Attack Modules** - Covering OWASP Top 10 and beyond
- **Autonomous Reconnaissance** - Subdomain enumeration, port scanning, technology fingerprinting
- **24-Hour Assessments** - Relentless testing with configurable duration
- **Real-time Progress** - WebSocket-based live updates during scans

### Enterprise Ready
- **Multi-Tenant Architecture** - Complete organization isolation
- **Role-Based Access Control** - Owner, Admin, Member, Viewer roles
- **Stripe Billing Integration** - Subscription management with usage quotas
- **Audit Logging** - Full compliance and activity tracking
- **API Access** - Programmatic scanning with API keys

### Brutal Reporting
- **Evidence-Based Reports** - Proof of exploitation with screenshots and data samples
- **Attack Timelines** - Complete progression of the assessment
- **Business Impact Calculation** - GDPR fines, breach costs, risk quantification
- **Remediation Guidance** - Prioritized fix recommendations
- **Multiple Formats** - HTML, JSON, Markdown, PDF

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           BREACH.AI PLATFORM                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
│  │   Frontend      │    │   Backend API   │    │  Scan Engine    │     │
│  │   (Next.js)     │───▶│   (FastAPI)     │───▶│  (Python)       │     │
│  │   Port 3000     │    │   Port 8000     │    │                 │     │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘     │
│          │                      │                      │               │
│          │                      ▼                      │               │
│          │              ┌─────────────────┐            │               │
│          │              │   PostgreSQL    │            │               │
│          └─────────────▶│   (Database)    │◀───────────┘               │
│                         └─────────────────┘                            │
│                                                                         │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
│  │   Clerk Auth    │    │   Stripe        │    │   Claude AI     │     │
│  │   (SSO/OAuth)   │    │   (Billing)     │    │   (Brain)       │     │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Attack Modules

### Reconnaissance
| Module | Capabilities |
|--------|-------------|
| **DNS Recon** | Subdomain enumeration, DNS records, zone transfers |
| **Port Scanner** | Full 65535 port scanning, service fingerprinting |
| **Web Crawler** | Endpoint discovery, sitemap parsing, JS analysis |
| **Tech Fingerprint** | Framework detection, version identification |
| **OSINT** | Employee discovery, leaked credentials, git exposure |
| **Cloud Discovery** | S3 buckets, Azure blobs, GCP storage |

### Injection Attacks
| Module | Capabilities |
|--------|-------------|
| **SQL Injection** | Error-based, Union, Blind, Time-based, OOB |
| **NoSQL Injection** | MongoDB, CouchDB, Redis injection |
| **Command Injection** | OS command execution, shell escape |
| **Template Injection** | SSTI in Jinja2, Twig, Freemarker, etc. |
| **XSS** | Reflected, Stored, DOM-based, mutation XSS |
| **XXE** | XML external entity injection |

### Authentication Attacks
| Module | Capabilities |
|--------|-------------|
| **JWT Obliterator** | Algorithm confusion, key brute force, claim manipulation |
| **OAuth Destroyer** | Token theft, redirect manipulation, scope escalation |
| **Session Annihilator** | Fixation, prediction, hijacking |
| **Password Reset Killer** | Token prediction, email injection |
| **MFA Bypass** | Rate limiting abuse, backup codes, response manipulation |
| **SAML Destroyer** | Signature bypass, XXE, assertion manipulation |
| **API Auth Breaker** | API key leakage, bearer token attacks |

### Access Control
| Module | Capabilities |
|--------|-------------|
| **IDOR Scanner** | Insecure direct object references (BOLA) |
| **Privilege Escalation** | Vertical and horizontal privilege attacks |
| **RBAC Bypass** | Role manipulation, permission confusion |

### API Security
| Module | Capabilities |
|--------|-------------|
| **REST API Attacker** | Mass assignment, parameter pollution, verb tampering |
| **GraphQL Destroyer** | Introspection abuse, injection, batching attacks, DoS |
| **WebSocket Destroyer** | Protocol attacks, injection, hijacking |
| **API Discovery** | Hidden endpoints, version enumeration, documentation leaks |

### Business Logic
| Module | Capabilities |
|--------|-------------|
| **Business Logic Destroyer** | Workflow bypass, race conditions, abuse scenarios |
| **Payment Bypass** | Price manipulation, currency confusion, coupon abuse |
| **Rate Limit Bypass** | Header manipulation, distributed requests |

### Infrastructure
| Module | Capabilities |
|--------|-------------|
| **SSRF Scanner** | Internal service access, cloud metadata, protocol smuggling |
| **Cloud Destroyer** | AWS/Azure/GCP misconfigs, IAM exploitation, serverless attacks |
| **Docker Destroyer** | Container escapes, registry attacks, secrets exposure |
| **File Warfare** | Upload bypass, path traversal, LFI/RFI |

### Modern Stack
| Module | Capabilities |
|--------|-------------|
| **Modern Stack Destroyer** | Next.js, Nuxt, SvelteKit, Vercel, Netlify vulnerabilities |
| **BaaS Attacker** | Supabase RLS bypass, Firebase rules, Clerk misconfig |
| **AI Code Analyzer** | Detects AI-generated code vulnerabilities |

---

## Tech Stack

### Backend
- **Python 3.11+** - Core language
- **FastAPI** - REST API framework
- **SQLAlchemy** - Async ORM with PostgreSQL/SQLite
- **Anthropic Claude** - AI decision engine
- **ARQ** - Background job queue
- **Redis** - Rate limiting and caching
- **Pydantic** - Data validation

### Frontend
- **Next.js 14** - React framework with App Router
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Styling with custom design system
- **Clerk** - Authentication and user management
- **Recharts** - Data visualization
- **Radix UI** - Accessible component primitives

### Infrastructure
- **PostgreSQL** - Production database
- **SQLite** - Development database
- **Redis** - Rate limiting, job queue
- **Docker** - Containerization
- **Prometheus** - Metrics collection
- **Sentry** - Error tracking

---

## Installation

### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL (production) or SQLite (development)
- Redis (optional, for rate limiting)

### Quick Start (Development)

```bash
# Clone the repository
git clone https://github.com/yourusername/breach-ai.git
cd breach-ai

# Backend setup
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Frontend setup
cd frontend
npm install
cd ..

# Configure environment
cp .env.example .env
# Edit .env with your API keys:
# - ANTHROPIC_API_KEY (required)
# - CLERK_SECRET_KEY (required for web platform)
# - STRIPE_SECRET_KEY (optional, for billing)

# Start backend
uvicorn backend.api.server:app --reload --port 8000

# Start frontend (new terminal)
cd frontend
npm run dev
```

### Production Deployment

```bash
# Using Docker Compose
docker-compose up -d

# Or manually:
# 1. Set up PostgreSQL and Redis
# 2. Configure .env.production
# 3. Run with gunicorn:
gunicorn backend.api.server:app -w 4 -k uvicorn.workers.UvicornWorker
```

---

## Usage

### CLI Mode

```bash
# Basic scan
python main.py https://target.com

# Deep scan with AI attack chaining
python main.py https://target.com --mode deep

# Authenticated scan
python main.py https://target.com --cookie "session=xxx"

# Custom headers
python main.py https://target.com --header "Authorization: Bearer token"

# Output to file
python main.py https://target.com --output report.json
```

### Web Platform

1. Navigate to `http://localhost:3000`
2. Sign in with Clerk authentication
3. Add a target domain/URL
4. Configure scan settings
5. Start the scan
6. Monitor progress in real-time
7. Download reports when complete

### API Access

```bash
# Create API key from dashboard, then:

# Start a scan
curl -X POST https://api.breach.ai/api/v1/scans \
  -H "X-API-Key: breach_your_key" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://target.com", "mode": "standard"}'

# Get scan status
curl https://api.breach.ai/api/v1/scans/{scan_id} \
  -H "X-API-Key: breach_your_key"

# List findings
curl https://api.breach.ai/api/v1/scans/{scan_id}/findings \
  -H "X-API-Key: breach_your_key"
```

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/auth/me` | Get current user |
| POST | `/api/v1/auth/api-keys` | Create API key |
| GET | `/api/v1/auth/api-keys` | List API keys |
| DELETE | `/api/v1/auth/api-keys/{id}` | Revoke API key |

### Targets
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/targets` | Add target |
| GET | `/api/v1/targets` | List targets |
| GET | `/api/v1/targets/{id}` | Get target |
| DELETE | `/api/v1/targets/{id}` | Delete target |

### Scans
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scans` | Start scan |
| GET | `/api/v1/scans` | List scans |
| GET | `/api/v1/scans/{id}` | Get scan details |
| POST | `/api/v1/scans/{id}/cancel` | Cancel scan |
| GET | `/api/v1/scans/{id}/findings` | Get findings |
| GET | `/api/v1/scans/{id}/export` | Export report |

### Billing
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/billing/subscription` | Get subscription |
| POST | `/api/v1/billing/checkout` | Create checkout |
| POST | `/api/v1/billing/portal` | Customer portal |

### WebSocket
| Endpoint | Description |
|----------|-------------|
| `WS /ws/scans/{id}` | Real-time scan updates |

---

## Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/breach
# Or for development:
DATABASE_URL=sqlite+aiosqlite:///./breach.db

# Redis (optional)
REDIS_URL=redis://localhost:6379

# Authentication (Clerk)
CLERK_PUBLISHABLE_KEY=pk_xxx
CLERK_SECRET_KEY=sk_xxx

# AI Engine
ANTHROPIC_API_KEY=sk-ant-xxx

# Billing (Stripe)
STRIPE_SECRET_KEY=sk_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false
ENVIRONMENT=production

# Scanning
SCAN_TIMEOUT_SECONDS=3600
MAX_CONCURRENT_SCANS=5

# Rate Limiting
RATE_LIMIT_GLOBAL=100/minute
RATE_LIMIT_SCANS=10/minute

# Monitoring (optional)
SENTRY_DSN=https://xxx@sentry.io/xxx
```

---

## Subscription Plans

| Feature | Free | Starter | Business | Enterprise |
|---------|------|---------|----------|------------|
| Scans/month | 10 | 50 | 200 | 1000 |
| Targets | 3 | 10 | 50 | 200 |
| API Access | - | Yes | Yes | Yes |
| Deep Scan Mode | - | - | Yes | Yes |
| Team Members | 1 | 5 | 20 | Unlimited |
| Priority Support | - | Email | Priority | Dedicated |
| Price | $0 | $49/mo | $199/mo | Custom |

---

## Project Structure

```
breach/
├── backend/                    # Python backend
│   ├── breach/                # Core scanning engine
│   │   ├── core/              # Agent, brain, memory, scheduler
│   │   ├── attacks/           # 40+ attack modules
│   │   ├── recon/             # Reconnaissance modules
│   │   ├── agents/            # AI decision agents
│   │   └── report/            # Report generation
│   ├── api/                   # FastAPI REST API
│   │   ├── routes/            # Auth, scans, billing endpoints
│   │   └── middleware/        # Auth, CORS, rate limiting
│   ├── services/              # Business logic layer
│   ├── db/                    # Database models and setup
│   ├── schemas/               # Pydantic schemas
│   └── config.py              # Settings management
├── frontend/                  # Next.js frontend
│   ├── src/
│   │   ├── app/               # Page routes
│   │   ├── components/        # React components
│   │   ├── lib/               # API client, utilities
│   │   └── hooks/             # Custom React hooks
│   └── package.json
├── scripts/                   # Utility scripts
├── tests/                     # Test suite
├── alembic/                   # Database migrations
├── requirements.txt           # Python dependencies
├── docker-compose.yml         # Container orchestration
└── .env.example               # Environment template
```

---

## Security Considerations

### For Users
- **Only scan targets you own or have explicit written permission to test**
- BREACH.AI requires domain ownership verification
- Scans are logged and auditable
- API keys should be kept secret and rotated regularly

### Platform Security
- No wildcard CORS - explicit origin allowlist
- SSRF protection - blocks private IPs and metadata endpoints
- Rate limiting on all endpoints
- API key scoping system
- Complete audit logging
- Per-organization data isolation

---

## Development

### Running Tests

```bash
# Backend tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=backend --cov-report=html

# Frontend tests
cd frontend && npm test
```

### Code Quality

```bash
# Linting
ruff check backend/
black backend/ --check

# Type checking
mypy backend/
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Legal Disclaimer

BREACH.AI is designed for authorized security testing only. Users are solely responsible for ensuring they have proper authorization before scanning any target. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse of this software.

---

## Support

- **Documentation**: [docs.breach.ai](https://docs.breach.ai)
- **Issues**: [GitHub Issues](https://github.com/yourusername/breach-ai/issues)
- **Email**: support@breach.ai
- **Discord**: [Join our community](https://discord.gg/breach-ai)

---

<div align="center">

**Built with relentless determination to find what others miss.**

*BREACH.AI - Because no one ignores a breach.*

</div>
