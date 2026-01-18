"""
BREACH.AI - Security Fix Recommendations Database

Provides detailed remediation guidance for all vulnerability types.
Each recommendation includes:
- Description of the vulnerability
- Why it's dangerous
- How to fix it (with code examples)
- Prevention best practices
- Compliance mappings (OWASP, CWE, etc.)
"""

from backend.breach.recommendations.injection import INJECTION_RECOMMENDATIONS
from backend.breach.recommendations.authentication import AUTH_RECOMMENDATIONS
from backend.breach.recommendations.web import WEB_RECOMMENDATIONS
from backend.breach.recommendations.cloud import CLOUD_RECOMMENDATIONS
from backend.breach.recommendations.api import API_RECOMMENDATIONS
from backend.breach.recommendations.infrastructure import INFRASTRUCTURE_RECOMMENDATIONS


# Combine all recommendations
ALL_RECOMMENDATIONS = {
    **INJECTION_RECOMMENDATIONS,
    **AUTH_RECOMMENDATIONS,
    **WEB_RECOMMENDATIONS,
    **CLOUD_RECOMMENDATIONS,
    **API_RECOMMENDATIONS,
    **INFRASTRUCTURE_RECOMMENDATIONS,
}


def get_recommendation(vuln_type: str) -> dict:
    """
    Get recommendation for a vulnerability type.

    Args:
        vuln_type: Type of vulnerability (e.g., "sqli", "xss", "jwt_none_algorithm")

    Returns:
        Dictionary with fix recommendation details
    """
    return ALL_RECOMMENDATIONS.get(vuln_type, {
        "title": "Security Vulnerability",
        "severity": "medium",
        "description": "A security vulnerability was identified.",
        "fix": "Review the affected component and apply security best practices.",
        "prevention": "Implement security reviews and testing as part of development.",
    })


def get_recommendations_by_category(category: str) -> dict:
    """Get all recommendations for a category."""
    category_map = {
        "injection": INJECTION_RECOMMENDATIONS,
        "authentication": AUTH_RECOMMENDATIONS,
        "web": WEB_RECOMMENDATIONS,
        "cloud": CLOUD_RECOMMENDATIONS,
        "api": API_RECOMMENDATIONS,
        "infrastructure": INFRASTRUCTURE_RECOMMENDATIONS,
    }
    return category_map.get(category, {})


__all__ = [
    "ALL_RECOMMENDATIONS",
    "get_recommendation",
    "get_recommendations_by_category",
    "INJECTION_RECOMMENDATIONS",
    "AUTH_RECOMMENDATIONS",
    "WEB_RECOMMENDATIONS",
    "CLOUD_RECOMMENDATIONS",
    "API_RECOMMENDATIONS",
    "INFRASTRUCTURE_RECOMMENDATIONS",
]
