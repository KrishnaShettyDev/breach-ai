"""
BREACH - Language-Specific Analyzers
=====================================

Pattern-based taint analysis for multiple programming languages.
Each analyzer knows the sources, sinks, and idioms of its language.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from breach.source.dataflow import (
    TaintSource,
    TaintSink,
    TaintedFlow,
    VulnType,
)


class LanguageAnalyzer(ABC):
    """Base class for language-specific analyzers."""

    # Override in subclasses
    SOURCES: Dict[str, str] = {}  # pattern -> source_type
    SINKS: Dict[str, VulnType] = {}  # pattern -> vuln_type
    SANITIZERS: List[str] = []  # patterns that indicate sanitization

    def analyze(
        self,
        code: str,
        file_path: str,
    ) -> Tuple[List[TaintSource], List[TaintSink], List[TaintedFlow]]:
        """
        Analyze code for tainted data flows.

        Returns:
            Tuple of (sources, sinks, flows)
        """
        lines = code.split("\n")
        sources: List[TaintSource] = []
        sinks: List[TaintSink] = []
        flows: List[TaintedFlow] = []

        # Find all sources
        for line_num, line in enumerate(lines, 1):
            for pattern, source_type in self.SOURCES.items():
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract variable name if possible
                    var_name = self._extract_variable(line, pattern)
                    sources.append(TaintSource(
                        name=pattern,
                        type=source_type,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip()[:200],
                        variable_name=var_name,
                    ))

        # Find all sinks
        for line_num, line in enumerate(lines, 1):
            for pattern, vuln_type in self.SINKS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    func_name = self._extract_function(line)
                    sinks.append(TaintSink(
                        name=pattern,
                        vuln_type=vuln_type,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip()[:200],
                        function_name=func_name,
                    ))

        # Find flows (sources and sinks in proximity with data connection)
        flows = self._find_flows(code, lines, sources, sinks, file_path)

        return sources, sinks, flows

    def _find_flows(
        self,
        code: str,
        lines: List[str],
        sources: List[TaintSource],
        sinks: List[TaintSink],
        file_path: str,
    ) -> List[TaintedFlow]:
        """Find data flows from sources to sinks."""
        flows = []

        for source in sources:
            # Get variable name from source
            tainted_var = source.variable_name
            if not tainted_var:
                continue

            # Look for this variable flowing to sinks
            for sink in sinks:
                # Check if sink is after source
                if sink.line_number < source.line_number:
                    continue

                # Check if tainted variable appears in sink context
                context_start = max(0, source.line_number - 1)
                context_end = min(len(lines), sink.line_number + 5)
                context = "\n".join(lines[context_start:context_end])

                # Check for variable in sink line
                sink_line = lines[sink.line_number - 1]
                if tainted_var in sink_line:
                    confidence = self._calculate_confidence(
                        source, sink, context, tainted_var
                    )

                    # Check for sanitization
                    is_sanitized = False
                    sanitizer = None
                    for san_pattern in self.SANITIZERS:
                        if re.search(san_pattern, context, re.IGNORECASE):
                            is_sanitized = True
                            sanitizer = san_pattern
                            confidence *= 0.2  # Significantly reduce confidence
                            break

                    if confidence > 0.2:  # Minimum threshold
                        flows.append(TaintedFlow(
                            source=source,
                            sink=sink,
                            path=[source.variable_name or source.name, "...", sink.name],
                            vuln_type=sink.vuln_type,
                            confidence=confidence,
                            file_path=file_path,
                            start_line=source.line_number,
                            end_line=sink.line_number,
                            code_context=context[:500],
                            is_sanitized=is_sanitized,
                            sanitizer=sanitizer,
                        ))

        return flows

    def _calculate_confidence(
        self,
        source: TaintSource,
        sink: TaintSink,
        context: str,
        tainted_var: str,
    ) -> float:
        """Calculate confidence score for a flow."""
        confidence = 0.5

        # Direct flow (same line) = higher confidence
        if source.line_number == sink.line_number:
            confidence += 0.3

        # Close proximity = higher confidence
        line_diff = abs(sink.line_number - source.line_number)
        if line_diff < 5:
            confidence += 0.2
        elif line_diff < 10:
            confidence += 0.1

        # String concatenation with user input = higher confidence
        concat_patterns = [
            rf'{tainted_var}\s*\+',  # var +
            rf'\+\s*{tainted_var}',  # + var
            rf'f["\'].*\{{{tainted_var}\}}',  # f-string
            rf'`\$\{{{tainted_var}\}}`',  # template literal
            rf'%s.*{tainted_var}',  # printf style
            rf'{tainted_var}.*%',  # Ruby style
        ]
        for pattern in concat_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                confidence += 0.2
                break

        # Cap at 1.0
        return min(1.0, confidence)

    def _extract_variable(self, line: str, pattern: str) -> Optional[str]:
        """Extract variable name being assigned from source."""
        # First check if the pattern is in this line
        if not re.search(pattern, line, re.IGNORECASE):
            return None

        # Common assignment patterns across languages
        assignment_patterns = [
            # Python/Ruby/PHP: var = source
            r'^[\s]*(\w+)\s*=\s*.*' + pattern.replace('\\', '').replace('.', r'\.'),
            # Generic: anything = source
            r'(\w+)\s*=\s*.*' + pattern.replace('\\', '').replace('.', r'\.'),
            # JavaScript: const/let/var x = source
            r'(?:const|let|var)\s+(\w+)\s*=',
            # Go: x := source
            r'(\w+)\s*:=',
            # PHP: $var = source
            r'(\$\w+)\s*=',
        ]

        for p in assignment_patterns:
            try:
                match = re.search(p, line, re.IGNORECASE)
                if match:
                    var = match.group(1)
                    # Filter out keywords
                    if var.lower() not in {'const', 'let', 'var', 'if', 'for', 'while', 'return'}:
                        return var
            except re.error:
                continue

        # Fallback: look for any variable on left side of =
        simple_match = re.match(r'[\s]*(\w+)\s*=', line)
        if simple_match:
            var = simple_match.group(1)
            if var.lower() not in {'const', 'let', 'var', 'if', 'for', 'while', 'return'}:
                return var

        return None

    def _extract_function(self, line: str) -> Optional[str]:
        """Extract function name from line."""
        # Match function calls
        match = re.search(r'(\w+)\s*\(', line)
        if match:
            return match.group(1)
        return None

    @abstractmethod
    def detect_technologies(self, code: str) -> Dict[str, str]:
        """Detect technologies/frameworks used."""
        pass


class PythonAnalyzer(LanguageAnalyzer):
    """Python-specific taint analyzer."""

    SOURCES = {
        # Flask
        r'request\.args': 'query_param',
        r'request\.form': 'body',
        r'request\.json': 'body',
        r'request\.data': 'body',
        r'request\.values': 'param',
        r'request\.headers': 'header',
        r'request\.cookies': 'cookie',
        r'request\.files': 'file',
        # Django
        r'request\.GET': 'query_param',
        r'request\.POST': 'body',
        r'request\.FILES': 'file',
        r'request\.META': 'header',
        r'request\.COOKIES': 'cookie',
        # FastAPI
        r'Query\(': 'query_param',
        r'Body\(': 'body',
        r'Header\(': 'header',
        r'Cookie\(': 'cookie',
        r'Path\(': 'path_param',
        r'Form\(': 'body',
        # Generic
        r'input\(': 'stdin',
        r'sys\.argv': 'argv',
        r'os\.environ': 'env',
    }

    SINKS = {
        # SQL Injection
        r'\.execute\(': VulnType.SQLI,
        r'\.executemany\(': VulnType.SQLI,
        r'cursor\.execute': VulnType.SQLI,
        r'\.raw\(': VulnType.SQLI,
        r'RawSQL\(': VulnType.SQLI,
        r'\.extra\(': VulnType.SQLI,
        # Command Injection
        r'os\.system\(': VulnType.CMDI,
        r'os\.popen\(': VulnType.CMDI,
        r'subprocess\.call\(': VulnType.CMDI,
        r'subprocess\.run\(': VulnType.CMDI,
        r'subprocess\.Popen\(': VulnType.CMDI,
        r'commands\.getoutput\(': VulnType.CMDI,
        r'eval\(': VulnType.CMDI,
        r'exec\(': VulnType.CMDI,
        # SSRF
        r'requests\.get\(': VulnType.SSRF,
        r'requests\.post\(': VulnType.SSRF,
        r'urllib\.request\.urlopen\(': VulnType.SSRF,
        r'httpx\.(get|post)\(': VulnType.SSRF,
        r'aiohttp\.ClientSession': VulnType.SSRF,
        # LFI/Path Traversal
        r'open\(': VulnType.LFI,
        r'\.read_text\(': VulnType.LFI,
        r'send_file\(': VulnType.LFI,
        r'send_from_directory\(': VulnType.LFI,
        r'shutil\.copy': VulnType.PATH_TRAVERSAL,
        # SSTI
        r'render_template_string\(': VulnType.SSTI,
        r'Template\(': VulnType.SSTI,
        r'\.format\(': VulnType.SSTI,  # Less confident
        r'Jinja2\.from_string': VulnType.SSTI,
        # Deserialization
        r'pickle\.loads?\(': VulnType.DESERIALIZATION,
        r'yaml\.load\(': VulnType.DESERIALIZATION,
        r'yaml\.unsafe_load\(': VulnType.DESERIALIZATION,
        r'marshal\.loads?\(': VulnType.DESERIALIZATION,
        r'shelve\.open\(': VulnType.DESERIALIZATION,
        # XXE
        r'etree\.parse\(': VulnType.XXE,
        r'etree\.fromstring\(': VulnType.XXE,
        r'xml\.dom\.minidom': VulnType.XXE,
        r'xml\.sax\.parse': VulnType.XXE,
        # Open Redirect
        r'redirect\(': VulnType.OPEN_REDIRECT,
        r'HttpResponseRedirect\(': VulnType.OPEN_REDIRECT,
    }

    SANITIZERS = [
        r'escape\(',
        r'quote\(',
        r'sanitize',
        r'clean\(',
        r'strip\(',
        r'bleach\.',
        r'markupsafe\.',
        r'int\(',
        r'float\(',
        r'\.isdigit\(',
        r'\.isalnum\(',
        r'parameterized',
        r'%s.*cursor\.execute',  # Parameterized query
        r'cursor\.execute\([^,]+,\s*\[',  # List parameters
        r'cursor\.execute\([^,]+,\s*\{',  # Dict parameters
    ]

    def detect_technologies(self, code: str) -> Dict[str, str]:
        """Detect Python technologies."""
        techs = {}
        patterns = {
            'flask': r'from flask import|Flask\(',
            'django': r'from django|django\.conf',
            'fastapi': r'from fastapi|FastAPI\(',
            'sqlalchemy': r'from sqlalchemy|SQLAlchemy\(',
            'pymongo': r'from pymongo|MongoClient\(',
            'redis': r'import redis|Redis\(',
            'celery': r'from celery|Celery\(',
            'boto3': r'import boto3',
            'requests': r'import requests',
            'aiohttp': r'import aiohttp',
        }
        for tech, pattern in patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                techs[tech] = 'detected'
        return techs


class JavaScriptAnalyzer(LanguageAnalyzer):
    """JavaScript/TypeScript taint analyzer."""

    SOURCES = {
        # Express.js
        r'req\.query': 'query_param',
        r'req\.params': 'path_param',
        r'req\.body': 'body',
        r'req\.headers': 'header',
        r'req\.cookies': 'cookie',
        r'request\.query': 'query_param',
        r'request\.body': 'body',
        # Browser DOM
        r'location\.search': 'dom',
        r'location\.hash': 'dom',
        r'location\.href': 'dom',
        r'document\.URL': 'dom',
        r'document\.referrer': 'dom',
        r'document\.cookie': 'cookie',
        r'window\.name': 'dom',
        r'localStorage\.getItem': 'storage',
        r'sessionStorage\.getItem': 'storage',
        # React
        r'useSearchParams': 'query_param',
        r'useParams': 'path_param',
        r'this\.props': 'props',
        # Next.js
        r'router\.query': 'query_param',
        r'params\.': 'path_param',
        # Vue
        r'this\.\$route\.query': 'query_param',
        r'this\.\$route\.params': 'path_param',
    }

    SINKS = {
        # SQL Injection
        r'\.query\(': VulnType.SQLI,
        r'\.execute\(': VulnType.SQLI,
        r'\.raw\(': VulnType.SQLI,
        r'sequelize\.query': VulnType.SQLI,
        r'knex\.raw': VulnType.SQLI,
        r'pool\.query': VulnType.SQLI,
        r'\$where': VulnType.NOSQL,
        r'\.find\(\{': VulnType.NOSQL,
        # XSS
        r'innerHTML': VulnType.XSS,
        r'outerHTML': VulnType.XSS,
        r'document\.write': VulnType.XSS,
        r'\.html\(': VulnType.XSS,
        r'dangerouslySetInnerHTML': VulnType.XSS,
        r'v-html': VulnType.XSS,
        # Command Injection
        r'exec\(': VulnType.CMDI,
        r'execSync\(': VulnType.CMDI,
        r'spawn\(': VulnType.CMDI,
        r'spawnSync\(': VulnType.CMDI,
        r'child_process': VulnType.CMDI,
        r'eval\(': VulnType.CMDI,
        r'new Function\(': VulnType.CMDI,
        # SSRF
        r'fetch\(': VulnType.SSRF,
        r'axios\(': VulnType.SSRF,
        r'axios\.(get|post|put|delete)\(': VulnType.SSRF,
        r'http\.request\(': VulnType.SSRF,
        r'https\.request\(': VulnType.SSRF,
        r'request\(': VulnType.SSRF,
        # LFI
        r'fs\.readFile': VulnType.LFI,
        r'fs\.readFileSync': VulnType.LFI,
        r'createReadStream': VulnType.LFI,
        r'path\.join': VulnType.PATH_TRAVERSAL,
        r'path\.resolve': VulnType.PATH_TRAVERSAL,
        # SSTI
        r'render\(': VulnType.SSTI,
        r'ejs\.render': VulnType.SSTI,
        r'pug\.render': VulnType.SSTI,
        r'handlebars\.compile': VulnType.SSTI,
        # Open Redirect
        r'res\.redirect\(': VulnType.OPEN_REDIRECT,
        r'window\.location\s*=': VulnType.OPEN_REDIRECT,
        r'location\.href\s*=': VulnType.OPEN_REDIRECT,
    }

    SANITIZERS = [
        r'escape\(',
        r'encodeURI',
        r'encodeURIComponent',
        r'sanitize',
        r'DOMPurify',
        r'\.textContent',
        r'\.innerText',
        r'parseInt\(',
        r'parseFloat\(',
        r'Number\(',
        r'prepared statement',
        r'\?\s*,',  # Parameterized query
        r'\$\d+',  # PostgreSQL parameters
    ]

    def detect_technologies(self, code: str) -> Dict[str, str]:
        """Detect JavaScript technologies."""
        techs = {}
        patterns = {
            'react': r'import.*from\s*[\'"]react[\'"]|React\.',
            'vue': r'import.*from\s*[\'"]vue[\'"]|Vue\.',
            'angular': r'@angular/|@Component',
            'express': r'express\(\)|app\.listen|require\([\'"]express[\'"]\)',
            'nextjs': r'next/router|getServerSideProps|next/link',
            'nestjs': r'@nestjs/|@Controller|@Injectable',
            'mongodb': r'mongoose|MongoClient',
            'graphql': r'graphql|gql`|@Query|@Mutation',
            'prisma': r'@prisma/|PrismaClient',
            'typeorm': r'typeorm|@Entity|Repository',
        }
        for tech, pattern in patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                techs[tech] = 'detected'
        return techs


class GoAnalyzer(LanguageAnalyzer):
    """Go-specific taint analyzer."""

    SOURCES = {
        r'r\.URL\.Query\(\)': 'query_param',
        r'r\.FormValue\(': 'body',
        r'r\.PostFormValue\(': 'body',
        r'r\.Header\.Get\(': 'header',
        r'r\.Cookie\(': 'cookie',
        r'mux\.Vars\(': 'path_param',
        r'c\.Query\(': 'query_param',  # Gin
        r'c\.Param\(': 'path_param',  # Gin
        r'c\.PostForm\(': 'body',  # Gin
        r'ctx\.Query\(': 'query_param',  # Fiber
        r'ctx\.Params\(': 'path_param',  # Fiber
        r'os\.Args': 'argv',
        r'os\.Getenv\(': 'env',
    }

    SINKS = {
        # SQL Injection
        r'db\.Query\(': VulnType.SQLI,
        r'db\.Exec\(': VulnType.SQLI,
        r'db\.QueryRow\(': VulnType.SQLI,
        r'\.Raw\(': VulnType.SQLI,
        # Command Injection
        r'exec\.Command\(': VulnType.CMDI,
        r'exec\.CommandContext\(': VulnType.CMDI,
        r'os\.StartProcess\(': VulnType.CMDI,
        # SSRF
        r'http\.Get\(': VulnType.SSRF,
        r'http\.Post\(': VulnType.SSRF,
        r'http\.NewRequest\(': VulnType.SSRF,
        r'client\.Do\(': VulnType.SSRF,
        # LFI
        r'os\.Open\(': VulnType.LFI,
        r'os\.ReadFile\(': VulnType.LFI,
        r'ioutil\.ReadFile\(': VulnType.LFI,
        r'filepath\.Join\(': VulnType.PATH_TRAVERSAL,
        # SSTI
        r'template\.HTML\(': VulnType.SSTI,
        r'\.Execute\(': VulnType.SSTI,
        # XXE
        r'xml\.Unmarshal\(': VulnType.XXE,
        r'xml\.NewDecoder\(': VulnType.XXE,
        # Open Redirect
        r'http\.Redirect\(': VulnType.OPEN_REDIRECT,
        r'c\.Redirect\(': VulnType.OPEN_REDIRECT,
    }

    SANITIZERS = [
        r'html\.EscapeString',
        r'template\.HTMLEscapeString',
        r'url\.QueryEscape',
        r'strconv\.Atoi',
        r'strconv\.ParseInt',
        r'filepath\.Clean',
        r'prepared statement',
        r'\$\d+',  # PostgreSQL parameters
    ]

    def detect_technologies(self, code: str) -> Dict[str, str]:
        """Detect Go technologies."""
        techs = {}
        patterns = {
            'gin': r'"github\.com/gin-gonic/gin"',
            'fiber': r'"github\.com/gofiber/fiber"',
            'echo': r'"github\.com/labstack/echo"',
            'chi': r'"github\.com/go-chi/chi"',
            'gorm': r'"gorm\.io/gorm"',
            'sqlx': r'"github\.com/jmoiron/sqlx"',
            'grpc': r'"google\.golang\.org/grpc"',
            'aws': r'"github\.com/aws/aws-sdk-go"',
        }
        for tech, pattern in patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                techs[tech] = 'detected'
        return techs


class JavaAnalyzer(LanguageAnalyzer):
    """Java-specific taint analyzer."""

    SOURCES = {
        r'request\.getParameter\(': 'query_param',
        r'request\.getParameterValues\(': 'query_param',
        r'request\.getHeader\(': 'header',
        r'request\.getCookies\(': 'cookie',
        r'request\.getInputStream\(': 'body',
        r'request\.getReader\(': 'body',
        r'@RequestParam': 'query_param',
        r'@PathVariable': 'path_param',
        r'@RequestBody': 'body',
        r'@RequestHeader': 'header',
        r'@CookieValue': 'cookie',
        r'System\.getenv\(': 'env',
        r'System\.getProperty\(': 'property',
    }

    SINKS = {
        # SQL Injection
        r'createStatement\(': VulnType.SQLI,
        r'executeQuery\(': VulnType.SQLI,
        r'executeUpdate\(': VulnType.SQLI,
        r'execute\(': VulnType.SQLI,
        r'createNativeQuery\(': VulnType.SQLI,
        r'createQuery\(': VulnType.SQLI,
        # Command Injection
        r'Runtime\.getRuntime\(\)\.exec\(': VulnType.CMDI,
        r'ProcessBuilder\(': VulnType.CMDI,
        r'ScriptEngine\.eval\(': VulnType.CMDI,
        # SSRF
        r'new URL\(': VulnType.SSRF,
        r'HttpURLConnection': VulnType.SSRF,
        r'HttpClient': VulnType.SSRF,
        r'RestTemplate': VulnType.SSRF,
        r'WebClient': VulnType.SSRF,
        # LFI
        r'new FileInputStream\(': VulnType.LFI,
        r'new FileReader\(': VulnType.LFI,
        r'Files\.readAllBytes\(': VulnType.LFI,
        r'Paths\.get\(': VulnType.PATH_TRAVERSAL,
        # XXE
        r'DocumentBuilderFactory': VulnType.XXE,
        r'SAXParserFactory': VulnType.XXE,
        r'XMLInputFactory': VulnType.XXE,
        r'TransformerFactory': VulnType.XXE,
        # Deserialization
        r'ObjectInputStream': VulnType.DESERIALIZATION,
        r'readObject\(': VulnType.DESERIALIZATION,
        r'XMLDecoder': VulnType.DESERIALIZATION,
        r'XStream': VulnType.DESERIALIZATION,
        # LDAP
        r'search\(.*SearchControls': VulnType.LDAP,
        r'InitialDirContext': VulnType.LDAP,
        # XSS
        r'PrintWriter\.print': VulnType.XSS,
        r'response\.getWriter\(\)\.write': VulnType.XSS,
        # Open Redirect
        r'sendRedirect\(': VulnType.OPEN_REDIRECT,
    }

    SANITIZERS = [
        r'PreparedStatement',
        r'setString\(',
        r'setInt\(',
        r'StringEscapeUtils\.escape',
        r'HtmlUtils\.htmlEscape',
        r'OWASP\.encoder',
        r'Jsoup\.clean',
        r'Integer\.parseInt',
        r'Long\.parseLong',
        r'\.matches\(',
        r'validator\.',
    ]

    def detect_technologies(self, code: str) -> Dict[str, str]:
        """Detect Java technologies."""
        techs = {}
        patterns = {
            'spring': r'@SpringBootApplication|springframework',
            'springboot': r'spring-boot|@RestController',
            'hibernate': r'org\.hibernate|@Entity',
            'jpa': r'javax\.persistence|jakarta\.persistence',
            'struts': r'org\.apache\.struts',
            'jsf': r'javax\.faces|jakarta\.faces',
            'jdbc': r'java\.sql\.|DriverManager',
            'log4j': r'org\.apache\.logging\.log4j|log4j',
            'jackson': r'com\.fasterxml\.jackson',
        }
        for tech, pattern in patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                techs[tech] = 'detected'
        return techs


class PHPAnalyzer(LanguageAnalyzer):
    """PHP-specific taint analyzer."""

    SOURCES = {
        r'\$_GET': 'query_param',
        r'\$_POST': 'body',
        r'\$_REQUEST': 'param',
        r'\$_COOKIE': 'cookie',
        r'\$_FILES': 'file',
        r'\$_SERVER\[.HTTP_': 'header',
        r'\$_SESSION': 'session',
        r'file_get_contents\([\'"]php://input[\'"]\)': 'body',
        r'\$request->input\(': 'param',  # Laravel
        r'\$request->query\(': 'query_param',  # Laravel
        r'\$request->post\(': 'body',  # Laravel
        r'Request::get\(': 'query_param',
    }

    SINKS = {
        # SQL Injection
        r'mysql_query\(': VulnType.SQLI,
        r'mysqli_query\(': VulnType.SQLI,
        r'->query\(': VulnType.SQLI,
        r'->exec\(': VulnType.SQLI,
        r'pg_query\(': VulnType.SQLI,
        r'DB::raw\(': VulnType.SQLI,
        r'DB::select\(': VulnType.SQLI,
        # Command Injection
        r'exec\(': VulnType.CMDI,
        r'shell_exec\(': VulnType.CMDI,
        r'system\(': VulnType.CMDI,
        r'passthru\(': VulnType.CMDI,
        r'popen\(': VulnType.CMDI,
        r'proc_open\(': VulnType.CMDI,
        r'pcntl_exec\(': VulnType.CMDI,
        r'eval\(': VulnType.CMDI,
        r'assert\(': VulnType.CMDI,
        r'preg_replace\([\'"]/.*/e': VulnType.CMDI,
        # XSS
        r'echo\s+\$': VulnType.XSS,
        r'print\s+\$': VulnType.XSS,
        # SSRF
        r'file_get_contents\(': VulnType.SSRF,
        r'curl_exec\(': VulnType.SSRF,
        r'fopen\(': VulnType.SSRF,
        r'readfile\(': VulnType.SSRF,
        # LFI
        r'include\s*\(': VulnType.LFI,
        r'include_once\s*\(': VulnType.LFI,
        r'require\s*\(': VulnType.LFI,
        r'require_once\s*\(': VulnType.LFI,
        r'file\(': VulnType.LFI,
        # XXE
        r'simplexml_load_string\(': VulnType.XXE,
        r'simplexml_load_file\(': VulnType.XXE,
        r'DOMDocument::loadXML': VulnType.XXE,
        # Deserialization
        r'unserialize\(': VulnType.DESERIALIZATION,
        # Open Redirect
        r'header\([\'"]Location:': VulnType.OPEN_REDIRECT,
    }

    SANITIZERS = [
        r'htmlspecialchars\(',
        r'htmlentities\(',
        r'strip_tags\(',
        r'addslashes\(',
        r'mysqli_real_escape_string\(',
        r'mysql_real_escape_string\(',
        r'PDO::prepare\(',
        r'->prepare\(',
        r'intval\(',
        r'floatval\(',
        r'filter_var\(',
        r'escapeshellarg\(',
        r'escapeshellcmd\(',
    ]

    def detect_technologies(self, code: str) -> Dict[str, str]:
        """Detect PHP technologies."""
        techs = {}
        patterns = {
            'laravel': r'Illuminate\\|Laravel|artisan',
            'symfony': r'Symfony\\|symfony\.yaml',
            'wordpress': r'wp_|WP_|wordpress',
            'drupal': r'drupal_|Drupal\\',
            'codeigniter': r'CI_Controller|codeigniter',
            'yii': r'Yii::|yii\\',
            'pdo': r'PDO|PDOStatement',
            'composer': r'vendor/autoload',
        }
        for tech, pattern in patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                techs[tech] = 'detected'
        return techs


class RubyAnalyzer(LanguageAnalyzer):
    """Ruby-specific taint analyzer."""

    SOURCES = {
        r'params\[': 'param',
        r'params\.': 'param',
        r'request\.params': 'param',
        r'request\.query_string': 'query_param',
        r'request\.body': 'body',
        r'request\.headers': 'header',
        r'cookies\[': 'cookie',
        r'session\[': 'session',
        r'ENV\[': 'env',
        r'ARGV': 'argv',
    }

    SINKS = {
        # SQL Injection
        r'\.where\(': VulnType.SQLI,
        r'\.find_by_sql\(': VulnType.SQLI,
        r'\.execute\(': VulnType.SQLI,
        r'ActiveRecord::Base\.connection\.execute': VulnType.SQLI,
        r'\.order\(': VulnType.SQLI,
        r'\.pluck\(': VulnType.SQLI,
        # Command Injection
        r'system\(': VulnType.CMDI,
        r'exec\(': VulnType.CMDI,
        r'`': VulnType.CMDI,  # Backticks
        r'%x\[': VulnType.CMDI,
        r'IO\.popen\(': VulnType.CMDI,
        r'Open3\.': VulnType.CMDI,
        r'Kernel\.system': VulnType.CMDI,
        r'eval\(': VulnType.CMDI,
        # XSS
        r'\.html_safe': VulnType.XSS,
        r'raw\(': VulnType.XSS,
        # SSRF
        r'Net::HTTP': VulnType.SSRF,
        r'open-uri': VulnType.SSRF,
        r'URI\.open\(': VulnType.SSRF,
        r'RestClient': VulnType.SSRF,
        r'HTTParty': VulnType.SSRF,
        r'Faraday': VulnType.SSRF,
        # LFI
        r'File\.read\(': VulnType.LFI,
        r'File\.open\(': VulnType.LFI,
        r'IO\.read\(': VulnType.LFI,
        r'send_file\(': VulnType.LFI,
        # SSTI
        r'ERB\.new\(': VulnType.SSTI,
        r'render\s+inline:': VulnType.SSTI,
        # Deserialization
        r'Marshal\.load\(': VulnType.DESERIALIZATION,
        r'YAML\.load\(': VulnType.DESERIALIZATION,
        r'JSON\.parse\(': VulnType.DESERIALIZATION,
        # Open Redirect
        r'redirect_to\(': VulnType.OPEN_REDIRECT,
    }

    SANITIZERS = [
        r'sanitize\(',
        r'h\(',
        r'html_escape\(',
        r'CGI\.escape',
        r'ERB::Util\.html_escape',
        r'\.to_i',
        r'\.to_f',
        r'Integer\(',
        r'Float\(',
        r'Shellwords\.escape',
        r'\.where\([^,]+,\s*\[',  # Parameterized query
    ]

    def detect_technologies(self, code: str) -> Dict[str, str]:
        """Detect Ruby technologies."""
        techs = {}
        patterns = {
            'rails': r'Rails\.|ActiveRecord|ActionController',
            'sinatra': r"require ['\"]sinatra['\"]|Sinatra::",
            'grape': r'Grape::API',
            'devise': r'Devise|devise',
            'activerecord': r'ActiveRecord::Base',
            'sidekiq': r'Sidekiq',
            'redis': r'Redis\.new',
            'aws': r'Aws::',
        }
        for tech, pattern in patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                techs[tech] = 'detected'
        return techs
