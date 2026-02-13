"""
BREACH.AI - AI Code Vulnerability Analyzer

Specifically targets vulnerabilities that AI/LLMs introduce:
- Cursor-generated code
- v0-generated components
- Bolt.new full-stack apps
- ChatGPT-written backends
- Claude-generated APIs
- Copilot suggestions

LLMs make CONSISTENT mistakes. We exploit them.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum

from breach.attacks.base import BaseAttack, AttackResult
from breach.utils.logger import logger


class AIToolSource(Enum):
    """AI tools that generate code."""
    CURSOR = "cursor"
    V0 = "v0"
    BOLT = "bolt"
    CHATGPT = "chatgpt"
    CLAUDE = "claude"
    COPILOT = "copilot"
    REPLIT = "replit"
    LOVABLE = "lovable"
    UNKNOWN = "unknown"


class AIVulnType(Enum):
    """Types of AI-introduced vulnerabilities."""
    NO_INPUT_VALIDATION = "no_input_validation"
    SQL_INJECTION = "sql_injection"
    HARDCODED_SECRET = "hardcoded_secret"
    MISSING_AUTH = "missing_auth"
    IDOR = "idor"
    WEAK_CRYPTO = "weak_crypto"
    EXPOSED_DEBUG = "exposed_debug"
    NO_RATE_LIMIT = "no_rate_limit"
    CORS_WILDCARD = "cors_wildcard"
    UNSAFE_REDIRECT = "unsafe_redirect"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    MASS_ASSIGNMENT = "mass_assignment"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"


@dataclass
class AIVulnerability:
    """A vulnerability introduced by AI-generated code."""
    vuln_type: AIVulnType
    severity: str  # critical, high, medium, low
    confidence: str  # high, medium, low
    location: str  # file path or endpoint
    description: str
    code_snippet: str = ""
    fix_suggestion: str = ""
    common_in: List[AIToolSource] = field(default_factory=list)


@dataclass
class AICodeAnalysisResult:
    """Result of AI code analysis."""
    target: str
    detected_ai_tool: AIToolSource
    vulnerabilities: List[AIVulnerability] = field(default_factory=list)
    patterns_matched: int = 0
    risk_score: int = 0  # 0-100
    ai_indicators: List[str] = field(default_factory=list)


class AICodeAnalyzer(BaseAttack):
    """
    Analyzes code for vulnerabilities commonly introduced by AI/LLMs.

    LLMs have CONSISTENT vulnerability patterns:

    1. THEY DON'T VALIDATE INPUT
       - AI rarely adds Zod/Yup validation
       - Trusts req.body directly
       - No sanitization

    2. THEY USE STRING CONCATENATION FOR SQL
       - Template literals in queries
       - No parameterized queries
       - Dynamic query building

    3. THEY HARDCODE SECRETS
       - API keys inline
       - Database URLs in code
       - Tokens in source files

    4. THEY FORGET AUTHENTICATION
       - API routes without auth checks
       - Server actions without verification
       - No middleware protection

    5. THEY DON'T CHECK OWNERSHIP
       - IDOR everywhere
       - No resource authorization
       - Missing tenant isolation

    6. THEY USE WEAK CRYPTO
       - MD5/SHA1 for passwords
       - Math.random() for tokens
       - No salt in hashing

    7. THEY LEAVE DEBUG CODE
       - console.log with secrets
       - Debug endpoints in production
       - Verbose error messages
    """

    attack_type = "ai_code"

    # Patterns that indicate AI-generated code
    AI_CODE_INDICATORS = [
        # Comments that AI typically adds
        r"// TODO: (add|implement|remove)",
        r"// This (function|component|code) ",
        r"// Example usage:",
        r"/\* eslint-disable \*/",
        r"// @ts-ignore",
        r"// @ts-nocheck",

        # Typical AI variable naming
        r"const (data|result|response|res|err) =",
        r"(handleSubmit|handleClick|handleChange|fetchData)",

        # AI-style function structures
        r"export (default )?async function",
        r"export const \w+ = async \(",

        # AI placeholder comments
        r"// Replace with your",
        r"// Your .* here",
        r"// Add your .* logic",
    ]

    # Vulnerable code patterns AI commonly generates
    VULNERABLE_PATTERNS = {
        AIVulnType.NO_INPUT_VALIDATION: [
            {
                "pattern": r"const \{[^}]+\} = (req\.body|request\.json\(\)|await request\.json\(\))",
                "name": "Direct Request Body Destructuring",
                "description": "Destructuring request body without validation",
                "fix": "Use Zod/Yup schema validation: const data = schema.parse(req.body)",
                "common_in": [AIToolSource.CURSOR, AIToolSource.CHATGPT, AIToolSource.BOLT],
            },
            {
                "pattern": r"formData\.get\(['\"][\w]+['\"]\)",
                "name": "FormData Without Validation",
                "description": "Using FormData values without validation in Server Actions",
                "fix": "Validate with Zod: const { field } = schema.parse(Object.fromEntries(formData))",
                "common_in": [AIToolSource.V0, AIToolSource.CURSOR],
            },
            {
                "pattern": r"JSON\.parse\([^)]+\)",
                "name": "Unvalidated JSON Parse",
                "description": "Parsing JSON without try-catch or schema validation",
                "fix": "Wrap in try-catch and validate parsed data structure",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
        ],
        AIVulnType.SQL_INJECTION: [
            {
                "pattern": r"`SELECT.*\$\{[^}]+\}.*`",
                "name": "SQL via Template Literal",
                "description": "SQL queries using template literal interpolation",
                "fix": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId])",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.CURSOR],
            },
            {
                "pattern": r"(query|execute)\s*\(\s*['\"].*\+.*['\"]",
                "name": "SQL String Concatenation",
                "description": "SQL queries built with string concatenation",
                "fix": "Use prepared statements with placeholders",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
            {
                "pattern": r"\$queryRaw`[^`]*\$\{[^}]+\}",
                "name": "Prisma Raw Query Injection",
                "description": "Prisma $queryRaw with interpolated values",
                "fix": "Use Prisma.sql: prisma.$queryRaw(Prisma.sql`SELECT * WHERE id = ${id}`)",
                "common_in": [AIToolSource.CURSOR, AIToolSource.COPILOT],
            },
        ],
        AIVulnType.HARDCODED_SECRET: [
            {
                "pattern": r"(apiKey|api_key|secret|password|token)\s*[:=]\s*['\"][^'\"]{10,}['\"]",
                "name": "Hardcoded Secret",
                "description": "Secrets hardcoded directly in source code",
                "fix": "Use environment variables: process.env.API_KEY",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.BOLT, AIToolSource.REPLIT],
            },
            {
                "pattern": r"(sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_-]+)",
                "name": "OpenAI Key in Code",
                "description": "OpenAI API key hardcoded in source",
                "fix": "Move to environment variable: process.env.OPENAI_API_KEY",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.BOLT],
            },
            {
                "pattern": r"createClient\([^)]*['\"][^'\"]+['\"]",
                "name": "Database Client with Hardcoded Credentials",
                "description": "Database connection with inline credentials",
                "fix": "Use environment variable: process.env.DATABASE_URL",
                "common_in": [AIToolSource.BOLT, AIToolSource.V0],
            },
        ],
        AIVulnType.MISSING_AUTH: [
            {
                "pattern": r"export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\([^)]*\)\s*\{(?!.*auth)",
                "name": "Unprotected API Route",
                "description": "API route handler without authentication check",
                "fix": "Add auth check: const session = await getServerSession(); if (!session) return unauthorized();",
                "common_in": [AIToolSource.V0, AIToolSource.CURSOR, AIToolSource.BOLT],
            },
            {
                "pattern": r"['\"]use server['\"][\s\S]*?async function \w+\([^)]*\)\s*\{(?![\s\S]*?(getSession|auth|verify))",
                "name": "Unprotected Server Action",
                "description": "Server Action without authentication verification",
                "fix": "Add auth check at the start of the server action",
                "common_in": [AIToolSource.V0, AIToolSource.CURSOR],
            },
            {
                "pattern": r"app\.(get|post|put|delete)\(['\"][^'\"]+['\"],\s*async\s*\([^)]*\)\s*=>",
                "name": "Express Route Without Middleware",
                "description": "Express route without auth middleware",
                "fix": "Add authentication middleware: app.get('/route', authMiddleware, handler)",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
        ],
        AIVulnType.IDOR: [
            {
                "pattern": r"(params|query)\.(id|userId|user_id|orderId|order_id)(?![\s\S]*?(where.*userId|auth|session))",
                "name": "IDOR via URL Parameter",
                "description": "Accessing resources by ID without ownership verification",
                "fix": "Verify the requesting user owns or has access to the resource",
                "common_in": [AIToolSource.CURSOR, AIToolSource.CHATGPT, AIToolSource.V0],
            },
            {
                "pattern": r"findUnique\(\s*\{\s*where:\s*\{\s*id:\s*(params|query)",
                "name": "Prisma FindUnique Without Auth",
                "description": "Database lookup by ID without user verification",
                "fix": "Add user ID to where clause: { where: { id, userId: session.user.id } }",
                "common_in": [AIToolSource.CURSOR, AIToolSource.V0],
            },
            {
                "pattern": r"readFile\s*\([^)]*params\.",
                "name": "File Access via Parameter",
                "description": "Reading files based on user-controlled path",
                "fix": "Validate filename and verify user has access to the file",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
        ],
        AIVulnType.WEAK_CRYPTO: [
            {
                "pattern": r"(createHash\(['\"]md5['\"]\)|createHash\(['\"]sha1['\"]\)).*password",
                "name": "Weak Password Hash",
                "description": "Using MD5/SHA1 for password hashing",
                "fix": "Use bcrypt: const hash = await bcrypt.hash(password, 10);",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
            {
                "pattern": r"Math\.random\(\).*token|token.*Math\.random\(\)",
                "name": "Insecure Token Generation",
                "description": "Using Math.random() for security tokens",
                "fix": "Use crypto: const token = crypto.randomBytes(32).toString('hex');",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.CURSOR],
            },
            {
                "pattern": r"uuid\(\)|uuidv4\(\).*token",
                "name": "UUID as Security Token",
                "description": "Using UUID for security-sensitive tokens",
                "fix": "Use cryptographically secure random: crypto.randomBytes(32)",
                "common_in": [AIToolSource.COPILOT, AIToolSource.CHATGPT],
            },
        ],
        AIVulnType.EXPOSED_DEBUG: [
            {
                "pattern": r"console\.(log|debug|info)\([^)]*\b(password|secret|token|key|credential)",
                "name": "Sensitive Data Logged",
                "description": "Logging sensitive information to console",
                "fix": "Remove console.log statements with sensitive data",
                "common_in": [AIToolSource.CURSOR, AIToolSource.BOLT],
            },
            {
                "pattern": r"['\"]/(api/)?debug['\"]|['\"]/(api/)?test['\"]",
                "name": "Debug Endpoint",
                "description": "Debug/test endpoints in code",
                "fix": "Remove debug endpoints or protect with authentication",
                "common_in": [AIToolSource.CURSOR, AIToolSource.BOLT],
            },
            {
                "pattern": r"catch\s*\([^)]*\)\s*\{[^}]*return.*error\.(message|stack)",
                "name": "Error Details Exposed",
                "description": "Returning error details in response",
                "fix": "Only expose stack traces in development: if (process.env.NODE_ENV === 'development')",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.CURSOR],
            },
        ],
        AIVulnType.NO_RATE_LIMIT: [
            {
                "pattern": r"(api/auth/|/login|/register|/signin|/signup)(?![\s\S]*?rateLimit)",
                "name": "Auth Without Rate Limiting",
                "description": "Authentication endpoints without rate limiting",
                "fix": "Add rate limiting with @upstash/ratelimit or similar",
                "common_in": [AIToolSource.V0, AIToolSource.CURSOR, AIToolSource.BOLT],
            },
            {
                "pattern": r"(sendEmail|send_email|mailer\.send)(?![\s\S]*?rateLimit)",
                "name": "Email Without Rate Limiting",
                "description": "Email sending without rate limits",
                "fix": "Implement rate limiting to prevent abuse",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.V0],
            },
        ],
        AIVulnType.CORS_WILDCARD: [
            {
                "pattern": r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*",
                "name": "CORS Wildcard Origin",
                "description": "CORS allows all origins",
                "fix": "Specify allowed origins explicitly",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.CURSOR],
            },
            {
                "pattern": r"cors\(\s*\{?\s*\}?\s*\)|cors\(\)",
                "name": "Default CORS Configuration",
                "description": "Using default CORS which may be too permissive",
                "fix": "Configure CORS with specific origins: cors({ origin: ['https://yourdomain.com'] })",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
        ],
        AIVulnType.XSS: [
            {
                "pattern": r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:",
                "name": "React Dangerous HTML",
                "description": "Using dangerouslySetInnerHTML with potentially unsafe content",
                "fix": "Sanitize HTML with DOMPurify: DOMPurify.sanitize(content)",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.CURSOR, AIToolSource.V0],
            },
            {
                "pattern": r"innerHTML\s*=|document\.write\(",
                "name": "Direct DOM Manipulation",
                "description": "Setting innerHTML or using document.write",
                "fix": "Use textContent or sanitize input",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
            {
                "pattern": r"v-html\s*=",
                "name": "Vue v-html Directive",
                "description": "Using v-html with potentially unsafe content",
                "fix": "Sanitize content before using v-html",
                "common_in": [AIToolSource.CHATGPT],
            },
        ],
        AIVulnType.MASS_ASSIGNMENT: [
            {
                "pattern": r"\.create\(\s*req\.body\s*\)|\.update\(\s*req\.body\s*\)",
                "name": "Direct Body to Database",
                "description": "Passing entire request body to database operation",
                "fix": "Explicitly select allowed fields: { name: req.body.name, email: req.body.email }",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.CURSOR],
            },
            {
                "pattern": r"Object\.assign\([^,]+,\s*req\.body\)",
                "name": "Object.assign with Body",
                "description": "Merging request body directly into object",
                "fix": "Destructure only needed properties",
                "common_in": [AIToolSource.COPILOT],
            },
            {
                "pattern": r"\.\.\.\s*req\.body|\.\.\.\s*body",
                "name": "Spread Operator on Body",
                "description": "Spreading request body into object",
                "fix": "Explicitly list allowed fields",
                "common_in": [AIToolSource.V0, AIToolSource.CURSOR],
            },
        ],
        AIVulnType.PATH_TRAVERSAL: [
            {
                "pattern": r"(readFile|readFileSync|writeFile)\s*\([^)]*\+[^)]*\)",
                "name": "File Path Concatenation",
                "description": "File operations with concatenated paths",
                "fix": "Use path.join and validate against base directory",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
            {
                "pattern": r"path\.join\([^)]*req\.(params|query|body)",
                "name": "User Input in Path",
                "description": "User input used directly in file path",
                "fix": "Validate and sanitize path components, use allowlist",
                "common_in": [AIToolSource.CHATGPT],
            },
        ],
        AIVulnType.COMMAND_INJECTION: [
            {
                "pattern": r"(exec|execSync|spawn)\s*\([^)]*\$\{",
                "name": "Command with Template Literal",
                "description": "Shell command with interpolated values",
                "fix": "Use argument arrays instead of shell strings",
                "common_in": [AIToolSource.CHATGPT, AIToolSource.COPILOT],
            },
            {
                "pattern": r"(exec|execSync)\s*\([^)]*\+",
                "name": "Command with Concatenation",
                "description": "Shell command with string concatenation",
                "fix": "Use execFile with argument array",
                "common_in": [AIToolSource.CHATGPT],
            },
        ],
    }

    async def run(
        self,
        url: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        **kwargs
    ) -> Optional[AttackResult]:
        """Execute AI code vulnerability analysis."""
        result = await self.analyze(url)

        if result.vulnerabilities:
            return AttackResult(
                success=True,
                attack_type=self.attack_type,
                endpoint=url,
                details=f"AI code vulnerabilities found: {len(result.vulnerabilities)} issues, risk score: {result.risk_score}",
                severity="high" if result.risk_score >= 70 else "medium",
                evidence={
                    "detected_ai_tool": result.detected_ai_tool.value,
                    "risk_score": result.risk_score,
                    "ai_indicators": result.ai_indicators,
                    "vulnerabilities": [
                        {
                            "type": v.vuln_type.value,
                            "severity": v.severity,
                            "confidence": v.confidence,
                            "location": v.location,
                            "description": v.description,
                            "fix": v.fix_suggestion,
                        }
                        for v in result.vulnerabilities
                    ],
                },
            )

        return None

    async def analyze(
        self,
        target: str,
        source_code: str = None,
    ) -> AICodeAnalysisResult:
        """Analyze target for AI-introduced vulnerabilities."""
        logger.info(f"Analyzing for AI-generated code vulnerabilities: {target}")

        result = AICodeAnalysisResult(
            target=target,
            detected_ai_tool=AIToolSource.UNKNOWN,
        )

        # Fetch code if not provided
        if source_code is None:
            source_code = await self._fetch_source_code(target)

        # Detect AI tool indicators
        result.ai_indicators = self._detect_ai_indicators(source_code)
        result.detected_ai_tool = self._guess_ai_tool(result.ai_indicators)

        # Run all vulnerability checks
        vulns = []

        for vuln_type, patterns in self.VULNERABLE_PATTERNS.items():
            type_vulns = self._check_patterns(source_code, vuln_type, patterns)
            vulns.extend(type_vulns)

        # Also run endpoint-based checks
        endpoint_vulns = await self._check_endpoints(target)
        vulns.extend(endpoint_vulns)

        result.vulnerabilities = vulns
        result.patterns_matched = len(vulns)
        result.risk_score = self._calculate_risk_score(vulns)

        return result

    async def _fetch_source_code(self, target: str) -> str:
        """Fetch source code from target (HTML + JS bundles)."""
        all_code = ""

        try:
            # Fetch main page
            response = await self.http.get(target, timeout=10)
            body = response.text if hasattr(response, 'text') else ""
            all_code += body

            # Find and fetch JS files
            js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)

            for js_url in set(js_urls[:15]):
                try:
                    if js_url.startswith("/"):
                        js_url = f"{target.rstrip('/')}{js_url}"
                    elif not js_url.startswith("http"):
                        js_url = f"{target.rstrip('/')}/{js_url}"

                    js_response = await self.http.get(js_url, timeout=5)
                    js_body = js_response.text if hasattr(js_response, 'text') else ""
                    all_code += "\n" + js_body
                except Exception:
                    pass

            # Try common Next.js paths
            nextjs_paths = [
                "/_next/static/chunks/main.js",
                "/_next/static/chunks/pages/_app.js",
                "/_next/static/chunks/webpack.js",
            ]

            for path in nextjs_paths:
                try:
                    url = f"{target.rstrip('/')}{path}"
                    resp = await self.http.get(url, timeout=5)
                    all_code += "\n" + (resp.text if hasattr(resp, 'text') else "")
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Error fetching source: {e}")

        return all_code

    def _detect_ai_indicators(self, code: str) -> List[str]:
        """Detect indicators of AI-generated code."""
        indicators = []

        for pattern in self.AI_CODE_INDICATORS:
            if re.search(pattern, code, re.IGNORECASE):
                indicators.append(pattern)

        # Additional heuristics
        if code.count("// TODO:") > 5:
            indicators.append("Many TODO comments")

        if code.count("console.log") > 10:
            indicators.append("Excessive console.log")

        if re.search(r"\/\/ (This|The) (function|component|code|method)", code):
            indicators.append("AI-style explanatory comments")

        return indicators

    def _guess_ai_tool(self, indicators: List[str]) -> AIToolSource:
        """Guess which AI tool generated the code."""
        # This is heuristic-based
        indicator_text = " ".join(indicators).lower()

        if "v0" in indicator_text or "shadcn" in indicator_text:
            return AIToolSource.V0
        elif "cursor" in indicator_text:
            return AIToolSource.CURSOR
        elif "bolt" in indicator_text:
            return AIToolSource.BOLT
        elif len(indicators) > 3:
            return AIToolSource.CHATGPT  # Default for AI-looking code

        return AIToolSource.UNKNOWN

    def _check_patterns(
        self,
        code: str,
        vuln_type: AIVulnType,
        patterns: List[dict],
    ) -> List[AIVulnerability]:
        """Check code against vulnerability patterns."""
        vulns = []

        for pattern_info in patterns:
            pattern = pattern_info["pattern"]
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)

            for match in matches:
                # Get surrounding context
                start = max(0, match.start() - 50)
                end = min(len(code), match.end() + 50)
                snippet = code[start:end].strip()

                vulns.append(AIVulnerability(
                    vuln_type=vuln_type,
                    severity=self._get_severity(vuln_type),
                    confidence="high" if len(match.group(0)) > 20 else "medium",
                    location="Source code",
                    description=pattern_info["description"],
                    code_snippet=snippet[:200],
                    fix_suggestion=pattern_info["fix"],
                    common_in=pattern_info.get("common_in", []),
                ))

        return vulns

    async def _check_endpoints(self, target: str) -> List[AIVulnerability]:
        """Check for vulnerabilities via endpoint testing."""
        vulns = []

        # Check for unprotected API routes
        common_routes = [
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/debug",
            "/api/settings",
            "/api/data",
            "/api/export",
        ]

        for route in common_routes:
            try:
                url = f"{target.rstrip('/')}{route}"
                response = await self.http.get(url, timeout=5)

                if response.status_code == 200:
                    vulns.append(AIVulnerability(
                        vuln_type=AIVulnType.MISSING_AUTH,
                        severity="high",
                        confidence="high",
                        location=route,
                        description=f"API endpoint {route} accessible without authentication",
                        fix_suggestion="Add authentication middleware to protect this endpoint",
                        common_in=[AIToolSource.V0, AIToolSource.BOLT],
                    ))
            except Exception:
                pass

        # Check for verbose errors
        try:
            response = await self.http.get(f"{target}/api/nonexistent_12345", timeout=5)
            body = response.text if hasattr(response, 'text') else ""

            if any(x in body.lower() for x in ["stack", "trace", "error at", "exception"]):
                vulns.append(AIVulnerability(
                    vuln_type=AIVulnType.EXPOSED_DEBUG,
                    severity="medium",
                    confidence="high",
                    location="Error handling",
                    description="Stack traces exposed in error responses",
                    fix_suggestion="Implement proper error handling that hides internal details in production",
                ))
        except Exception:
            pass

        # Check for CORS issues
        try:
            response = await self.http.options(f"{target}/api/users", timeout=5)
            headers = response.headers if hasattr(response, 'headers') else {}

            cors_header = headers.get("access-control-allow-origin", "")
            if cors_header == "*":
                vulns.append(AIVulnerability(
                    vuln_type=AIVulnType.CORS_WILDCARD,
                    severity="medium",
                    confidence="high",
                    location="CORS configuration",
                    description="CORS allows all origins (*)",
                    fix_suggestion="Configure CORS to only allow specific trusted origins",
                ))
        except Exception:
            pass

        return vulns

    def _get_severity(self, vuln_type: AIVulnType) -> str:
        """Get severity for vulnerability type."""
        critical = [
            AIVulnType.SQL_INJECTION,
            AIVulnType.COMMAND_INJECTION,
            AIVulnType.HARDCODED_SECRET,
        ]
        high = [
            AIVulnType.MISSING_AUTH,
            AIVulnType.IDOR,
            AIVulnType.PATH_TRAVERSAL,
            AIVulnType.SSRF,
            AIVulnType.XSS,
            AIVulnType.INSECURE_DESERIALIZATION,
            AIVulnType.BROKEN_ACCESS_CONTROL,
        ]
        medium = [
            AIVulnType.NO_INPUT_VALIDATION,
            AIVulnType.WEAK_CRYPTO,
            AIVulnType.EXPOSED_DEBUG,
            AIVulnType.NO_RATE_LIMIT,
            AIVulnType.CORS_WILDCARD,
            AIVulnType.MASS_ASSIGNMENT,
        ]

        if vuln_type in critical:
            return "critical"
        elif vuln_type in high:
            return "high"
        elif vuln_type in medium:
            return "medium"
        return "low"

    def _calculate_risk_score(self, vulns: List[AIVulnerability]) -> int:
        """Calculate overall risk score."""
        score = 0

        severity_scores = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
        }

        for vuln in vulns:
            score += severity_scores.get(vuln.severity, 5)

        return min(score, 100)  # Cap at 100

    def get_recommendations(self, result: AICodeAnalysisResult) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []

        vuln_types = {v.vuln_type for v in result.vulnerabilities}

        if AIVulnType.NO_INPUT_VALIDATION in vuln_types:
            recommendations.append(
                "Add input validation using Zod or Yup on ALL API endpoints and Server Actions"
            )

        if AIVulnType.SQL_INJECTION in vuln_types:
            recommendations.append(
                "Replace string interpolation with parameterized queries or ORM methods"
            )

        if AIVulnType.HARDCODED_SECRET in vuln_types:
            recommendations.append(
                "Move all secrets to environment variables and use .env.local for development"
            )

        if AIVulnType.MISSING_AUTH in vuln_types:
            recommendations.append(
                "Implement authentication checks on all sensitive API routes using middleware"
            )

        if AIVulnType.IDOR in vuln_types:
            recommendations.append(
                "Add resource ownership verification before returning or modifying data"
            )

        if AIVulnType.WEAK_CRYPTO in vuln_types:
            recommendations.append(
                "Use bcrypt for password hashing and crypto.randomBytes for token generation"
            )

        if AIVulnType.NO_RATE_LIMIT in vuln_types:
            recommendations.append(
                "Implement rate limiting using @upstash/ratelimit on authentication and sensitive endpoints"
            )

        if AIVulnType.XSS in vuln_types:
            recommendations.append(
                "Sanitize all user-generated HTML with DOMPurify before rendering"
            )

        if AIVulnType.MASS_ASSIGNMENT in vuln_types:
            recommendations.append(
                "Explicitly list allowed fields when creating/updating database records"
            )

        if not recommendations:
            recommendations.append("No critical issues found. Continue following security best practices.")

        return recommendations


# Convenience functions
async def analyze_ai_code(target: str, http_client=None) -> AICodeAnalysisResult:
    """Analyze target for AI-generated code vulnerabilities."""
    from breach.utils.http import HTTPClient

    client = http_client or HTTPClient(base_url=target)
    own_client = http_client is None

    try:
        analyzer = AICodeAnalyzer(client)
        return await analyzer.analyze(target)
    finally:
        if own_client:
            await client.close()


def analyze_source_code(source_code: str) -> List[AIVulnerability]:
    """Analyze source code string for vulnerabilities."""
    analyzer = AICodeAnalyzer(None)
    vulns = []

    for vuln_type, patterns in analyzer.VULNERABLE_PATTERNS.items():
        type_vulns = analyzer._check_patterns(source_code, vuln_type, patterns)
        vulns.extend(type_vulns)

    return vulns
