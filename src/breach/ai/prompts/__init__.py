"""
BREACH GOD MODE - Attack Prompts

These prompts give the AI UNLIMITED POWER to breach targets.
"""

from breach.ai.prompts.recon import (
    RECON_SYSTEM,
    RECON_PROMPT,
    DEEP_RECON_PROMPT,
)

from breach.ai.prompts.injection import (
    INJECTION_SYSTEM,
    INJECTION_HUNT_PROMPT,
    INJECTION_EXPLOIT_PROMPT,
    INJECTION_BYPASS_PROMPT,
)

from breach.ai.prompts.auth import (
    AUTH_SYSTEM,
    AUTH_HUNT_PROMPT,
    JWT_ATTACK_PROMPT,
    PASSWORD_RESET_ATTACK_PROMPT,
)

from breach.ai.prompts.ssrf import (
    SSRF_SYSTEM,
    SSRF_HUNT_PROMPT,
    SSRF_CLOUD_PROMPT,
)

from breach.ai.prompts.xss import (
    XSS_SYSTEM,
    XSS_HUNT_PROMPT,
    XSS_CONTEXT_PROMPT,
)

__all__ = [
    # Recon
    "RECON_SYSTEM",
    "RECON_PROMPT",
    "DEEP_RECON_PROMPT",
    # Injection
    "INJECTION_SYSTEM",
    "INJECTION_HUNT_PROMPT",
    "INJECTION_EXPLOIT_PROMPT",
    "INJECTION_BYPASS_PROMPT",
    # Auth
    "AUTH_SYSTEM",
    "AUTH_HUNT_PROMPT",
    "JWT_ATTACK_PROMPT",
    "PASSWORD_RESET_ATTACK_PROMPT",
    # SSRF
    "SSRF_SYSTEM",
    "SSRF_HUNT_PROMPT",
    "SSRF_CLOUD_PROMPT",
    # XSS
    "XSS_SYSTEM",
    "XSS_HUNT_PROMPT",
    "XSS_CONTEXT_PROMPT",
]
