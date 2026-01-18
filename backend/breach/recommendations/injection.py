"""
BREACH.AI - Injection Vulnerability Recommendations

Fix recommendations for:
- SQL Injection
- NoSQL Injection
- Command Injection
- SSTI (Server-Side Template Injection)
- XXE (XML External Entity)
- LDAP Injection
- XPath Injection
"""

INJECTION_RECOMMENDATIONS = {
    # SQL Injection
    "sqli": {
        "title": "SQL Injection",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021-Injection",
        "description": "SQL injection allows attackers to manipulate database queries by injecting malicious SQL code through user input.",
        "impact": """
- Complete database compromise
- Data theft (credentials, PII, financial data)
- Data modification or deletion
- Authentication bypass
- Potential server takeover via xp_cmdshell or similar
""",
        "fix": """
1. **Use Parameterized Queries (Prepared Statements)**

   Python (SQLAlchemy):
   ```python
   # VULNERABLE
   query = f"SELECT * FROM users WHERE id = {user_id}"

   # SECURE
   query = text("SELECT * FROM users WHERE id = :id")
   result = db.execute(query, {"id": user_id})
   ```

   Node.js (pg):
   ```javascript
   // VULNERABLE
   const query = `SELECT * FROM users WHERE id = ${userId}`;

   // SECURE
   const query = 'SELECT * FROM users WHERE id = $1';
   const result = await client.query(query, [userId]);
   ```

2. **Use ORM methods that escape automatically**
   ```python
   # SQLAlchemy ORM
   user = session.query(User).filter(User.id == user_id).first()
   ```

3. **Input validation with allowlists**
   ```python
   ALLOWED_SORT_COLUMNS = ['name', 'date', 'id']
   if sort_column not in ALLOWED_SORT_COLUMNS:
       raise ValueError("Invalid sort column")
   ```
""",
        "prevention": """
- Never concatenate user input into SQL queries
- Use parameterized queries for ALL database operations
- Apply least privilege principle to database accounts
- Enable database query logging for detection
- Use Web Application Firewall (WAF) as defense in depth
- Regular security testing and code review
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },

    # NoSQL Injection
    "nosqli": {
        "title": "NoSQL Injection",
        "severity": "critical",
        "cwe_id": "CWE-943",
        "owasp": "A03:2021-Injection",
        "description": "NoSQL injection allows attackers to manipulate NoSQL queries using operator injection or JavaScript injection in databases like MongoDB.",
        "impact": """
- Authentication bypass
- Data extraction
- Denial of service
- In some cases, remote code execution via $where operator
""",
        "fix": """
1. **Sanitize and validate input types**

   ```python
   # VULNERABLE - Direct JSON input to query
   user = db.users.find_one({"username": request.json['username']})

   # SECURE - Ensure string type
   username = str(request.json.get('username', ''))
   user = db.users.find_one({"username": username})
   ```

2. **Block MongoDB operators in input**
   ```python
   def sanitize_mongo_input(data):
       if isinstance(data, dict):
           for key in list(data.keys()):
               if key.startswith('$'):
                   raise ValueError(f"Operator not allowed: {key}")
               data[key] = sanitize_mongo_input(data[key])
       elif isinstance(data, list):
           return [sanitize_mongo_input(item) for item in data]
       return data
   ```

3. **Use schema validation**
   ```python
   from pydantic import BaseModel, validator

   class LoginRequest(BaseModel):
       username: str
       password: str

       @validator('username', 'password')
       def must_be_string(cls, v):
           if not isinstance(v, str):
               raise ValueError('Must be a string')
           return v
   ```

4. **Disable JavaScript execution if not needed**
   ```javascript
   // MongoDB config
   mongod --noscripting
   ```
""",
        "prevention": """
- Always validate input types (ensure strings are strings)
- Block all $ prefixed keys in user input
- Disable server-side JavaScript when not required
- Use schema validation libraries
- Apply least privilege to database users
""",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
        ],
    },

    # Command Injection
    "command_injection": {
        "title": "OS Command Injection",
        "severity": "critical",
        "cwe_id": "CWE-78",
        "owasp": "A03:2021-Injection",
        "description": "Command injection allows attackers to execute arbitrary operating system commands on the server by injecting commands through user input.",
        "impact": """
- Complete server compromise
- Data theft and exfiltration
- Malware installation
- Lateral movement in the network
- Ransomware deployment
""",
        "fix": """
1. **Avoid shell commands entirely - use language libraries**

   ```python
   # VULNERABLE
   import os
   os.system(f"ping -c 1 {hostname}")

   # SECURE - Use Python library
   import socket
   socket.gethostbyname(hostname)
   ```

2. **If shell is necessary, use parameterized execution**

   ```python
   # VULNERABLE
   subprocess.call(f"convert {input_file} {output_file}", shell=True)

   # SECURE - Array arguments, no shell
   subprocess.call(["convert", input_file, output_file], shell=False)
   ```

3. **Strict input validation with allowlist**
   ```python
   import re

   def validate_hostname(hostname):
       pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\\-\\.]{0,252}[a-zA-Z0-9]$'
       if not re.match(pattern, hostname):
           raise ValueError("Invalid hostname")
       return hostname
   ```

4. **Use shlex for escaping when shell is required**
   ```python
   import shlex
   safe_input = shlex.quote(user_input)
   ```
""",
        "prevention": """
- Never pass user input to shell commands
- Use language-native libraries instead of system commands
- If commands are required, use array-based execution without shell
- Implement strict allowlist validation on inputs
- Run services with minimal privileges
- Use containerization to limit blast radius
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },

    # Server-Side Template Injection
    "ssti": {
        "title": "Server-Side Template Injection (SSTI)",
        "severity": "critical",
        "cwe_id": "CWE-1336",
        "owasp": "A03:2021-Injection",
        "description": "SSTI occurs when user input is embedded into a template engine without proper sanitization, allowing attackers to inject template directives.",
        "impact": """
- Remote code execution on the server
- Sensitive data disclosure
- Server takeover
- Access to internal systems and files
""",
        "fix": """
1. **Never pass user input as template content**

   ```python
   # VULNERABLE - User input in template
   template = Template(user_input)

   # SECURE - User input as variable
   template = Template("Hello {{ name }}")
   result = template.render(name=user_input)
   ```

2. **Use a sandbox/restricted template environment**
   ```python
   from jinja2 import Environment, select_autoescape
   from jinja2.sandbox import SandboxedEnvironment

   env = SandboxedEnvironment(
       autoescape=select_autoescape(['html', 'xml'])
   )
   ```

3. **Use logic-less templates when possible**
   - Mustache templates are logic-less and safer
   - Avoid Jinja2, Mako, Freemarker for user content

4. **Input validation**
   ```python
   # Block common SSTI payloads
   BLOCKED_PATTERNS = ['{{', '{%', '${', '#{', '<#', '[#']

   def validate_input(user_input):
       for pattern in BLOCKED_PATTERNS:
           if pattern in user_input:
               raise ValueError("Invalid characters in input")
       return user_input
   ```
""",
        "prevention": """
- Separate user data from template code
- Use sandboxed template environments
- Prefer logic-less template engines
- Block template syntax characters in user input
- Apply Content Security Policy headers
""",
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
        ],
    },

    # XXE (XML External Entity)
    "xxe": {
        "title": "XML External Entity (XXE) Injection",
        "severity": "high",
        "cwe_id": "CWE-611",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "XXE vulnerabilities occur when XML parsers process external entity references in user-supplied XML, allowing file disclosure, SSRF, and denial of service.",
        "impact": """
- Local file disclosure (/etc/passwd, application configs)
- Server-side request forgery (SSRF)
- Denial of service via entity expansion
- Port scanning of internal networks
- In some cases, remote code execution
""",
        "fix": """
1. **Disable DTD and external entities in XML parsers**

   Python (lxml):
   ```python
   from lxml import etree

   parser = etree.XMLParser(
       resolve_entities=False,
       no_network=True,
       dtd_validation=False,
       load_dtd=False
   )
   doc = etree.fromstring(xml_content, parser=parser)
   ```

   Python (defusedxml - RECOMMENDED):
   ```python
   import defusedxml.ElementTree as ET

   doc = ET.fromstring(xml_content)
   ```

   Java:
   ```java
   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
   dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   ```

2. **Use JSON instead of XML where possible**
   - JSON does not have entity features
   - Simpler and often more efficient

3. **Validate XML against a schema**
   ```python
   from lxml import etree

   schema = etree.XMLSchema(etree.parse('schema.xsd'))
   schema.assertValid(doc)
   ```
""",
        "prevention": """
- Use defusedxml or equivalent safe parsers
- Disable DTD processing entirely
- Disable external entity resolution
- Use JSON instead of XML when possible
- Validate XML structure against strict schemas
- Apply network-level egress filtering
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    },

    # LDAP Injection
    "ldap_injection": {
        "title": "LDAP Injection",
        "severity": "high",
        "cwe_id": "CWE-90",
        "owasp": "A03:2021-Injection",
        "description": "LDAP injection occurs when user input is incorporated into LDAP queries without proper sanitization, allowing attackers to modify query logic.",
        "impact": """
- Authentication bypass
- Access to sensitive directory information
- Privilege escalation
- Data modification in directory services
""",
        "fix": """
1. **Escape special LDAP characters**

   ```python
   def escape_ldap(value):
       escape_chars = {
           '\\\\': '\\\\5c',
           '*': '\\\\2a',
           '(': '\\\\28',
           ')': '\\\\29',
           '\\x00': '\\\\00',
       }
       for char, escape in escape_chars.items():
           value = value.replace(char, escape)
       return value

   # Usage
   safe_username = escape_ldap(user_input)
   filter_str = f"(uid={safe_username})"
   ```

2. **Use parameterized LDAP queries where available**

3. **Validate input strictly**
   ```python
   import re

   def validate_username(username):
       if not re.match(r'^[a-zA-Z0-9._-]+$', username):
           raise ValueError("Invalid username format")
       return username
   ```
""",
        "prevention": """
- Escape all special LDAP characters in user input
- Use strict input validation with allowlists
- Apply least privilege to LDAP bind accounts
- Log and monitor LDAP queries for anomalies
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
}
