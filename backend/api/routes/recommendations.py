"""
BREACH.AI - Recommendations API Routes
======================================

API endpoints for accessing remediation recommendations.
"""

from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.database import get_db
from backend.api.deps import get_current_user
from backend.db.models import Finding
from backend.breach.recommendations import (
    ALL_RECOMMENDATIONS,
    get_recommendation,
    get_recommendations_by_category,
)

router = APIRouter(prefix="/recommendations", tags=["Recommendations"])


# ============== Response Models ==============

class RecommendationResponse(BaseModel):
    """Detailed fix recommendation."""
    vuln_type: str
    title: str
    severity: str
    cwe_id: Optional[str] = None
    owasp: Optional[str] = None
    description: str
    impact: Optional[str] = None
    fix: str
    prevention: str
    references: List[str] = []


class RecommendationSummary(BaseModel):
    """Brief recommendation summary."""
    vuln_type: str
    title: str
    severity: str
    owasp: Optional[str] = None


class CategoryRecommendations(BaseModel):
    """All recommendations in a category."""
    category: str
    count: int
    recommendations: List[RecommendationSummary]


class FindingWithRemediation(BaseModel):
    """Finding with attached remediation guidance."""
    finding_id: str
    title: str
    severity: str
    category: str
    affected_endpoint: Optional[str]
    remediation: RecommendationResponse


# ============== Endpoints ==============

@router.get("/categories")
async def list_categories(
    current: tuple = Depends(get_current_user),
):
    """
    List all available recommendation categories.
    """
    categories = {
        "injection": "SQL, NoSQL, Command, SSTI, XXE injections",
        "authentication": "Auth bypass, JWT flaws, session issues",
        "web": "XSS, CSRF, CORS, clickjacking, open redirects",
        "cloud": "AWS, GCP, Azure misconfigurations",
        "api": "BOLA, rate limiting, input validation",
        "infrastructure": "TLS, headers, misconfigurations",
    }

    return {
        "categories": [
            {"id": k, "description": v, "count": len(get_recommendations_by_category(k))}
            for k, v in categories.items()
        ]
    }


@router.get("/category/{category}", response_model=CategoryRecommendations)
async def get_category_recommendations(
    category: str,
    current: tuple = Depends(get_current_user),
):
    """
    Get all recommendations for a specific category.

    Categories:
    - injection: SQL/NoSQL/Command/SSTI injections
    - authentication: Auth bypass, JWT, sessions
    - web: XSS, CSRF, CORS issues
    - cloud: Cloud misconfigurations
    - api: API security issues
    - infrastructure: Server/TLS misconfigurations
    """
    recommendations = get_recommendations_by_category(category)

    if not recommendations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Category '{category}' not found"
        )

    summaries = [
        RecommendationSummary(
            vuln_type=vuln_type,
            title=rec.get("title", vuln_type),
            severity=rec.get("severity", "medium"),
            owasp=rec.get("owasp"),
        )
        for vuln_type, rec in recommendations.items()
    ]

    return CategoryRecommendations(
        category=category,
        count=len(summaries),
        recommendations=summaries,
    )


@router.get("/vuln/{vuln_type}", response_model=RecommendationResponse)
async def get_vuln_recommendation(
    vuln_type: str,
    current: tuple = Depends(get_current_user),
):
    """
    Get detailed remediation guidance for a vulnerability type.

    Examples:
    - sqli - SQL Injection
    - xss - Cross-Site Scripting
    - jwt_none_algorithm - JWT Algorithm Confusion
    - bola - Broken Object Level Authorization
    """
    rec = get_recommendation(vuln_type)

    return RecommendationResponse(
        vuln_type=vuln_type,
        title=rec.get("title", vuln_type),
        severity=rec.get("severity", "medium"),
        cwe_id=rec.get("cwe_id"),
        owasp=rec.get("owasp"),
        description=rec.get("description", ""),
        impact=rec.get("impact"),
        fix=rec.get("fix", ""),
        prevention=rec.get("prevention", ""),
        references=rec.get("references", []),
    )


@router.get("/finding/{finding_id}", response_model=FindingWithRemediation)
async def get_finding_remediation(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: tuple = Depends(get_current_user),
):
    """
    Get remediation guidance for a specific finding.

    Automatically matches the finding's category to the appropriate
    remediation recommendations.
    """
    user, org = current

    # Get the finding
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    # Get recommendation based on category
    # Try to match category to vulnerability type
    vuln_type = finding.category.lower().replace(" ", "_").replace("-", "_")

    # Common mappings
    category_to_vuln = {
        "sql_injection": "sqli",
        "cross_site_scripting": "xss",
        "xss": "xss",
        "csrf": "csrf",
        "ssrf": "ssrf",
        "idor": "bola",
        "broken_authentication": "auth_bypass",
        "jwt": "jwt_none_algorithm",
        "api_key_exposure": "api_key_exposure",
        "sensitive_data_exposure": "data_exposure",
        "security_misconfiguration": "misconfiguration",
        "injection": "sqli",
    }

    vuln_type = category_to_vuln.get(vuln_type, vuln_type)
    rec = get_recommendation(vuln_type)

    return FindingWithRemediation(
        finding_id=str(finding.id),
        title=finding.title,
        severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
        category=finding.category,
        affected_endpoint=finding.affected_endpoint,
        remediation=RecommendationResponse(
            vuln_type=vuln_type,
            title=rec.get("title", finding.category),
            severity=rec.get("severity", "medium"),
            cwe_id=rec.get("cwe_id"),
            owasp=rec.get("owasp"),
            description=rec.get("description", ""),
            impact=rec.get("impact"),
            fix=rec.get("fix", ""),
            prevention=rec.get("prevention", ""),
            references=rec.get("references", []),
        ),
    )


@router.get("/search")
async def search_recommendations(
    q: str = Query(..., min_length=2, description="Search query"),
    current: tuple = Depends(get_current_user),
):
    """
    Search recommendations by keyword.

    Searches titles, descriptions, and fix content.
    """
    results = []
    query = q.lower()

    for vuln_type, rec in ALL_RECOMMENDATIONS.items():
        # Search in title, description, fix
        searchable = " ".join([
            rec.get("title", ""),
            rec.get("description", ""),
            rec.get("fix", ""),
            rec.get("owasp", ""),
            rec.get("cwe_id", ""),
        ]).lower()

        if query in searchable:
            results.append(RecommendationSummary(
                vuln_type=vuln_type,
                title=rec.get("title", vuln_type),
                severity=rec.get("severity", "medium"),
                owasp=rec.get("owasp"),
            ))

    return {
        "query": q,
        "count": len(results),
        "results": results[:20],  # Limit to 20 results
    }


@router.get("/bulk")
async def get_bulk_recommendations(
    vuln_types: str = Query(..., description="Comma-separated vulnerability types"),
    current: tuple = Depends(get_current_user),
):
    """
    Get recommendations for multiple vulnerability types at once.

    Useful for generating a remediation report for multiple findings.
    """
    types = [t.strip() for t in vuln_types.split(",")]

    recommendations = {}
    for vuln_type in types[:20]:  # Limit to 20
        rec = get_recommendation(vuln_type)
        recommendations[vuln_type] = RecommendationResponse(
            vuln_type=vuln_type,
            title=rec.get("title", vuln_type),
            severity=rec.get("severity", "medium"),
            cwe_id=rec.get("cwe_id"),
            owasp=rec.get("owasp"),
            description=rec.get("description", ""),
            impact=rec.get("impact"),
            fix=rec.get("fix", ""),
            prevention=rec.get("prevention", ""),
            references=rec.get("references", []),
        )

    return {
        "count": len(recommendations),
        "recommendations": recommendations,
    }
