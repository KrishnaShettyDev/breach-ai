"""
BREACH.AI - Import Scan Data
=============================
Import historical scan data from breach_output/ and output/ directories.
"""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Add parent to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from dotenv import load_dotenv
import os

# Load .env file from project root
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)

# Use direct connection (not pooler) to avoid cached statement issues
db_url = os.environ.get("DATABASE_URL", "")
if "-pooler" in db_url:
    db_url = db_url.replace("-pooler", "")

print(f"Using database: {db_url[:50]}...")

# Create a fresh engine with prepared_statement_cache_size=0 to avoid cache issues
direct_engine = create_async_engine(
    db_url,
    pool_pre_ping=True,
    connect_args={"prepared_statement_cache_size": 0}
)
AsyncSessionLocal = async_sessionmaker(
    direct_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Import models after engine is created
from backend.db.models import Base
from backend.db.models import (
    Organization, Scan, Finding, ScanStatus, ScanMode, Severity,
    BreachSession, BreachEvidence, BreachPhase, AccessLevel
)


# Default organization for imported data
DEFAULT_ORG_NAME = "BREACH.AI Demo"
DEFAULT_ORG_SLUG = "breach-ai-demo"


async def get_or_create_demo_org(db: AsyncSession) -> Organization:
    """Get or create the demo organization for imported scans."""
    result = await db.execute(
        select(Organization).where(Organization.slug == DEFAULT_ORG_SLUG)
    )
    org = result.scalar_one_or_none()

    if not org:
        org = Organization(
            id=uuid.uuid4(),
            name=DEFAULT_ORG_NAME,
            slug=DEFAULT_ORG_SLUG,
            max_scans_per_month=1000,
            max_targets=100,
            max_team_members=10,
        )
        db.add(org)
        await db.commit()
        await db.refresh(org)
        print(f"Created demo organization: {org.name}")
    else:
        print(f"Using existing organization: {org.name}")

    return org


def parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse datetime from various formats."""
    if not dt_str:
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue

    return None


def map_severity(severity_str: str) -> Severity:
    """Map severity string to enum."""
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
    }
    return severity_map.get(severity_str.lower(), Severity.INFO)


async def import_assessment_file(
    db: AsyncSession,
    org: Organization,
    file_path: Path
) -> Optional[uuid.UUID]:
    """Import a single assessment JSON file."""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  ⚠️  Failed to read {file_path.name}: {e}")
        return None

    # Skip non-assessment files
    if "target" not in data:
        print(f"  ⏭️  Skipping {file_path.name} (not an assessment file)")
        return None

    target_url = data.get("target", "")
    if not target_url:
        print(f"  ⏭️  Skipping {file_path.name} (no target URL)")
        return None

    # Check if scan already exists
    existing = await db.execute(
        select(Scan).where(
            Scan.target_url == target_url,
            Scan.organization_id == org.id
        )
    )
    if existing.scalar_one_or_none():
        print(f"  ⏭️  Scan for {target_url} already exists")
        return None

    # Parse summary
    summary = data.get("summary", {})

    # Create scan
    scan = Scan(
        id=uuid.uuid4(),
        organization_id=org.id,
        target_url=target_url,
        mode=ScanMode.NORMAL,
        status=ScanStatus.COMPLETED,
        progress=100,
        findings_count=summary.get("total_findings", 0),
        critical_count=summary.get("critical", 0),
        high_count=summary.get("high", 0),
        medium_count=summary.get("medium", 0),
        low_count=summary.get("low", 0),
        info_count=summary.get("info", 0),
        total_business_impact=summary.get("estimated_breach_cost", 0.0),
        started_at=parse_datetime(data.get("started_at")),
        completed_at=parse_datetime(data.get("completed_at")),
        duration_seconds=data.get("duration_seconds"),
        config={
            "imported_from": str(file_path),
            "modules_executed": data.get("modules", {}).get("executed", 0),
            "modules_successful": data.get("modules", {}).get("successful", 0),
        }
    )
    db.add(scan)

    # Import findings
    findings_data = data.get("findings", {})
    findings_imported = 0

    for severity_level in ["critical", "high", "medium", "low", "info"]:
        findings_list = findings_data.get(severity_level, [])
        for finding_data in findings_list:
            finding = Finding(
                id=uuid.uuid4(),
                scan_id=scan.id,
                title=finding_data.get("title", "Unknown Finding"),
                severity=map_severity(finding_data.get("severity", severity_level)),
                category=finding_data.get("category", "unknown"),
                endpoint=finding_data.get("affected_component", target_url),
                method="GET",
                description=finding_data.get("description", ""),
                evidence={
                    "attack_module": finding_data.get("attack_module"),
                    "cwe_id": finding_data.get("cwe_id"),
                    "cvss_score": finding_data.get("cvss_score"),
                    "reproduction_steps": finding_data.get("reproduction_steps", []),
                },
                fix_suggestion=finding_data.get("recommendation"),
                discovered_at=parse_datetime(finding_data.get("timestamp")) or datetime.utcnow(),
            )
            db.add(finding)
            findings_imported += 1

    await db.commit()
    print(f"  ✅ Imported {file_path.name}: {target_url} ({findings_imported} findings)")
    return scan.id


async def import_breach_file(
    db: AsyncSession,
    org: Organization,
    file_path: Path
) -> Optional[uuid.UUID]:
    """Import a breach extraction JSON file."""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  ⚠️  Failed to read {file_path.name}: {e}")
        return None

    target_url = data.get("target", "")
    if not target_url:
        print(f"  ⏭️  Skipping {file_path.name} (no target URL)")
        return None

    # Check if already imported
    existing = await db.execute(
        select(BreachSession).where(
            BreachSession.target_url == target_url,
            BreachSession.organization_id == org.id
        )
    )
    if existing.scalar_one_or_none():
        print(f"  ⏭️  Breach session for {target_url} already exists")
        return None

    # Create breach session
    session = BreachSession(
        id=uuid.uuid4(),
        organization_id=org.id,
        target_url=target_url,
        status="completed",
        current_phase=BreachPhase.PROOF,
        breach_achieved=True,
        highest_access=AccessLevel.DATABASE if data.get("users") else AccessLevel.USER,
        systems_compromised=[target_url],
        config={
            "imported_from": str(file_path),
        },
        started_at=parse_datetime(data.get("extraction_time")),
        completed_at=parse_datetime(data.get("extraction_time")),
    )
    db.add(session)

    evidence_count = 0

    # Import discovered data as evidence
    if data.get("endpoints"):
        evidence = BreachEvidence(
            id=uuid.uuid4(),
            session_id=session.id,
            evidence_type="api_endpoints",
            description=f"Discovered {len(data['endpoints'])} API endpoints",
            proves="API attack surface enumeration",
            content={"endpoints": data["endpoints"][:10]},  # First 10 only
            severity=Severity.MEDIUM,
        )
        db.add(evidence)
        evidence_count += 1

    if data.get("api_keys"):
        evidence = BreachEvidence(
            id=uuid.uuid4(),
            session_id=session.id,
            evidence_type="exposed_keys",
            description=f"Discovered {len(data['api_keys'])} exposed API keys",
            proves="Sensitive data exposure in client-side code",
            content={"count": len(data["api_keys"]), "types": list(set(k.get("type") for k in data["api_keys"]))},
            severity=Severity.HIGH,
            is_redacted=True,
            redaction_notes="Full keys redacted for security",
        )
        db.add(evidence)
        evidence_count += 1

    if data.get("users"):
        evidence = BreachEvidence(
            id=uuid.uuid4(),
            session_id=session.id,
            evidence_type="data_breach",
            description=f"Extracted {len(data['users'])} user records",
            proves="Unauthorized access to user data",
            content={"count": len(data["users"]), "sample_fields": list(data["users"][0].keys()) if data["users"] else []},
            severity=Severity.CRITICAL,
            is_redacted=True,
            redaction_notes="PII redacted for security",
        )
        db.add(evidence)
        session.records_exposed = len(data["users"])
        evidence_count += 1

    if data.get("plans"):
        evidence = BreachEvidence(
            id=uuid.uuid4(),
            session_id=session.id,
            evidence_type="business_data",
            description=f"Discovered {len(data['plans'])} subscription plans",
            proves="Access to business configuration data",
            content={"count": len(data["plans"])},
            severity=Severity.MEDIUM,
        )
        db.add(evidence)
        evidence_count += 1

    session.evidence_count = evidence_count
    await db.commit()
    print(f"  ✅ Imported {file_path.name}: {target_url} ({evidence_count} evidence items)")
    return session.id


async def import_evidence_file(
    db: AsyncSession,
    org: Organization,
    file_path: Path
) -> int:
    """Import an evidence JSON file."""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  ⚠️  Failed to read {file_path.name}: {e}")
        return 0

    # Get or find the most recent breach session
    result = await db.execute(
        select(BreachSession)
        .where(BreachSession.organization_id == org.id)
        .order_by(BreachSession.created_at.desc())
        .limit(1)
    )
    session = result.scalar_one_or_none()

    if not session:
        print(f"  ⏭️  No breach session found for evidence file")
        return 0

    evidence_count = 0

    # Handle different evidence file formats
    if isinstance(data, list):
        # Array of evidence items
        for i, item in enumerate(data[:100]):  # Limit to first 100
            evidence = BreachEvidence(
                id=uuid.uuid4(),
                session_id=session.id,
                evidence_type="data_sample",
                description=f"Evidence item {i+1} from {file_path.name}",
                proves="Data extraction capability",
                content={"sample": str(item)[:500]},  # Truncate
                severity=Severity.HIGH,
                is_redacted=True,
            )
            db.add(evidence)
            evidence_count += 1
    elif isinstance(data, dict):
        # Single evidence object
        evidence = BreachEvidence(
            id=uuid.uuid4(),
            session_id=session.id,
            evidence_type="data_extraction",
            description=f"Extracted data from {file_path.name}",
            proves="Data access capability",
            content={"keys": list(data.keys())[:20], "record_count": len(data) if isinstance(data, dict) else 1},
            severity=Severity.HIGH,
            is_redacted=True,
        )
        db.add(evidence)
        evidence_count = 1

    if evidence_count > 0:
        session.evidence_count += evidence_count
        await db.commit()
        print(f"  ✅ Imported {file_path.name}: {evidence_count} evidence items")

    return evidence_count


async def import_all_data():
    """Import all scan data from breach_output/ and output/ directories."""
    print("=" * 60)
    print("BREACH.AI - Data Import")
    print("=" * 60)

    # Initialize database with direct engine
    async with direct_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # Get or create demo organization
        org = await get_or_create_demo_org(db)

        base_path = Path(__file__).parent.parent.parent
        breach_output = base_path / "breach_output"
        output_dir = base_path / "output"

        stats = {
            "scans_imported": 0,
            "breaches_imported": 0,
            "evidence_imported": 0,
            "skipped": 0,
            "errors": 0,
        }

        # Import assessment files first
        print("\n📁 Importing from breach_output/...")
        if breach_output.exists():
            for json_file in sorted(breach_output.glob("*.json")):
                if "assessment" in json_file.name.lower():
                    result = await import_assessment_file(db, org, json_file)
                    if result:
                        stats["scans_imported"] += 1
                    else:
                        stats["skipped"] += 1

        # Import breach extraction files
        print("\n📁 Importing breach extractions...")
        for directory in [breach_output, output_dir]:
            if not directory.exists():
                continue
            for json_file in sorted(directory.glob("*.json")):
                if any(kw in json_file.name.lower() for kw in ["breach", "extraction", "full"]):
                    result = await import_breach_file(db, org, json_file)
                    if result:
                        stats["breaches_imported"] += 1
                    else:
                        stats["skipped"] += 1

        # Import evidence files
        print("\n📁 Importing evidence files...")
        for directory in [breach_output, output_dir]:
            if not directory.exists():
                continue
            for json_file in sorted(directory.glob("**/evidence*.json")):
                count = await import_evidence_file(db, org, json_file)
                stats["evidence_imported"] += count

        # Print summary
        print("\n" + "=" * 60)
        print("Import Summary")
        print("=" * 60)
        print(f"✅ Scans imported:     {stats['scans_imported']}")
        print(f"✅ Breaches imported:  {stats['breaches_imported']}")
        print(f"✅ Evidence imported:  {stats['evidence_imported']}")
        print(f"⏭️  Skipped:           {stats['skipped']}")
        print(f"❌ Errors:             {stats['errors']}")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(import_all_data())
