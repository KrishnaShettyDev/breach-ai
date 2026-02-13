"""
BREACH.AI - Web Vulnerability Recommendations

Fix recommendations for:
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object Reference (IDOR)
- File Upload Vulnerabilities
- Path Traversal
- CSRF
- Open Redirect
"""

WEB_RECOMMENDATIONS = {
    # Reflected XSS
    "xss_reflected": {
        "title": "Reflected Cross-Site Scripting (XSS)",
        "severity": "high",
        "cwe_id": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": "User input is reflected in the response without proper encoding, allowing attackers to inject malicious scripts that execute in victims' browsers.",
        "impact": """
- Session hijacking
- Cookie theft
- Keylogging
- Phishing attacks
- Malware distribution
- Account takeover
""",
        "fix": """
1. **Output encoding based on context**

   HTML context:
   ```python
   from markupsafe import escape

   # Template
   <div>{{ user_input | e }}</div>  # Jinja2 auto-escaping

   # Manual
   safe_output = escape(user_input)
   ```

   JavaScript context:
   ```python
   import json

   # SECURE - JSON encode for JS context
   script_data = json.dumps(user_input)
   ```
   ```html
   <script>
     var data = {{ user_input | tojson }};
   </script>
   ```

   URL context:
   ```python
   from urllib.parse import quote

   safe_url = quote(user_input, safe='')
   ```

2. **Use Content Security Policy**
   ```python
   @app.after_request
   def add_csp(response):
       response.headers['Content-Security-Policy'] = (
           "default-src 'self'; "
           "script-src 'self'; "
           "style-src 'self' 'unsafe-inline'"
       )
       return response
   ```

3. **Use HttpOnly cookies**
   ```python
   response.set_cookie(
       'session',
       value=session_id,
       httponly=True,
       secure=True,
       samesite='Lax'
   )
   ```
""",
        "prevention": """
- Enable automatic output encoding in templates
- Implement strict Content Security Policy
- Use HttpOnly flag on sensitive cookies
- Validate and sanitize all input
- Use modern frameworks with built-in XSS protection
- Regular security testing with XSS payloads
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },

    # Stored XSS
    "xss_stored": {
        "title": "Stored Cross-Site Scripting (XSS)",
        "severity": "critical",
        "cwe_id": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": "Malicious scripts are permanently stored on the server (in database, files, etc.) and served to users, affecting all visitors who view the infected content.",
        "impact": """
- Mass user compromise
- Persistent attack vector
- Worm-like propagation
- Cryptocurrency mining
- Data theft at scale
""",
        "fix": """
1. **Sanitize input before storage**

   ```python
   import bleach

   ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br']
   ALLOWED_ATTRS = {'a': ['href', 'title']}

   def sanitize_html(user_input):
       return bleach.clean(
           user_input,
           tags=ALLOWED_TAGS,
           attributes=ALLOWED_ATTRS,
           strip=True
       )

   # Store sanitized content
   post.content = sanitize_html(request.form['content'])
   ```

2. **Output encoding (defense in depth)**
   ```html
   <!-- Even with sanitized storage, encode on output -->
   <div>{{ post.content | safe }}</div>  <!-- Only if sanitized -->
   ```

3. **Content Security Policy with nonces**
   ```python
   import secrets

   @app.before_request
   def set_csp_nonce():
       g.csp_nonce = secrets.token_hex(16)

   @app.after_request
   def add_csp(response):
       response.headers['Content-Security-Policy'] = (
           f"script-src 'nonce-{g.csp_nonce}'"
       )
       return response
   ```
""",
        "prevention": """
- Sanitize user-generated content before storage
- Use allowlist-based HTML sanitizers (bleach, DOMPurify)
- Implement Content Security Policy
- Regular database audits for malicious content
- Consider sandboxed iframes for user content
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },

    # DOM XSS
    "xss_dom": {
        "title": "DOM-based Cross-Site Scripting",
        "severity": "high",
        "cwe_id": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": "Client-side JavaScript processes untrusted data and writes it to the DOM in an unsafe way, allowing script injection without server interaction.",
        "impact": """
- Client-side attack (harder to detect)
- Session hijacking
- Keylogging
- Bypasses some server-side protections
""",
        "fix": """
1. **Use safe DOM APIs**

   ```javascript
   // VULNERABLE
   element.innerHTML = userInput;
   document.write(userInput);

   // SECURE
   element.textContent = userInput;
   element.innerText = userInput;
   ```

2. **Sanitize before DOM insertion**
   ```javascript
   // Using DOMPurify
   import DOMPurify from 'dompurify';

   const clean = DOMPurify.sanitize(userInput);
   element.innerHTML = clean;
   ```

3. **Avoid dangerous sinks**
   ```javascript
   // AVOID these sinks with untrusted data:
   element.innerHTML = x;
   element.outerHTML = x;
   document.write(x);
   document.writeln(x);
   eval(x);
   setTimeout(x, 0);
   setInterval(x, 0);
   new Function(x);
   element.setAttribute('onclick', x);
   ```

4. **Use frameworks that auto-escape**
   ```jsx
   // React auto-escapes by default
   function SafeComponent({ userInput }) {
     return <div>{userInput}</div>;  // Safe
   }

   // DANGEROUS - explicit bypass
   function UnsafeComponent({ userInput }) {
     return <div dangerouslySetInnerHTML={{__html: userInput}} />;
   }
   ```
""",
        "prevention": """
- Use textContent instead of innerHTML
- Use DOMPurify for HTML sanitization
- Avoid eval() and similar functions
- Use modern frameworks with auto-escaping
- Implement Trusted Types CSP directive
- Code review JavaScript for DOM XSS patterns
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
        ],
    },

    # SSRF
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF)",
        "severity": "critical",
        "cwe_id": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "description": "The application makes HTTP requests to user-controlled URLs, allowing attackers to access internal services, cloud metadata, and bypass network controls.",
        "impact": """
- Access to internal services (Redis, databases, admin panels)
- Cloud metadata access (AWS keys, Azure tokens)
- Port scanning of internal network
- Reading local files via file:// protocol
- Remote code execution in some cases
""",
        "fix": """
1. **URL validation with allowlist**

   ```python
   from urllib.parse import urlparse
   import ipaddress

   ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']
   BLOCKED_RANGES = [
       ipaddress.ip_network('10.0.0.0/8'),
       ipaddress.ip_network('172.16.0.0/12'),
       ipaddress.ip_network('192.168.0.0/16'),
       ipaddress.ip_network('127.0.0.0/8'),
       ipaddress.ip_network('169.254.169.254/32'),  # Cloud metadata
   ]

   def validate_url(url):
       parsed = urlparse(url)

       # Only allow HTTPS
       if parsed.scheme not in ['https']:
           raise ValueError("Only HTTPS allowed")

       # Check allowlist
       if parsed.hostname not in ALLOWED_HOSTS:
           raise ValueError("Host not in allowlist")

       # Resolve and check IP
       ip = socket.gethostbyname(parsed.hostname)
       ip_obj = ipaddress.ip_address(ip)

       for blocked in BLOCKED_RANGES:
           if ip_obj in blocked:
               raise ValueError("Access to internal networks blocked")

       return url
   ```

2. **Disable redirects or validate redirect targets**
   ```python
   import requests

   response = requests.get(
       url,
       allow_redirects=False,  # Disable redirects
       timeout=5
   )

   # Or validate redirects manually
   if response.is_redirect:
       redirect_url = response.headers['Location']
       validate_url(redirect_url)  # Validate redirect target
   ```

3. **Use network segmentation**
   - Run request-making services in isolated network
   - Block access to metadata endpoints at firewall level
   - Use egress filtering
""",
        "prevention": """
- Implement strict URL allowlists
- Block access to private IP ranges
- Disable URL redirects or validate all hops
- Use network-level egress controls
- Block cloud metadata endpoints (169.254.169.254)
- Use DNS rebinding protections
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    },

    # IDOR
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR)",
        "severity": "high",
        "cwe_id": "CWE-639",
        "owasp": "A01:2021-Broken Access Control",
        "description": "The application exposes internal object references (IDs, filenames) that can be manipulated by users to access unauthorized resources.",
        "impact": """
- Unauthorized data access
- Data modification
- Account information disclosure
- Privacy violations
- Data breach
""",
        "fix": """
1. **Implement authorization checks**

   ```python
   @app.route('/api/documents/<int:doc_id>')
   @login_required
   def get_document(doc_id):
       document = Document.query.get_or_404(doc_id)

       # VULNERABLE - No authorization check
       return jsonify(document.to_dict())

       # SECURE - Check ownership/permissions
       if document.owner_id != current_user.id:
           if not current_user.has_permission('view_all_documents'):
               abort(403)

       return jsonify(document.to_dict())
   ```

2. **Use indirect references (UUIDs)**
   ```python
   import uuid

   class Document(db.Model):
       id = db.Column(db.Integer, primary_key=True)
       public_id = db.Column(db.String(36), default=lambda: str(uuid.uuid4()))

   # Use public_id in URLs instead of sequential id
   @app.route('/api/documents/<public_id>')
   def get_document(public_id):
       document = Document.query.filter_by(public_id=public_id).first_or_404()
       # Still verify authorization!
   ```

3. **Scope queries to user**
   ```python
   # VULNERABLE
   document = Document.query.get(doc_id)

   # SECURE - Query scoped to user
   document = Document.query.filter_by(
       id=doc_id,
       owner_id=current_user.id
   ).first_or_404()
   ```

4. **Centralized authorization middleware**
   ```python
   def authorize_resource(resource_type, resource_id, action='read'):
       policy = get_policy(resource_type)
       if not policy.allows(current_user, resource_id, action):
           abort(403)
   ```
""",
        "prevention": """
- Always verify authorization for every resource access
- Use UUIDs instead of sequential IDs
- Scope all queries to the authenticated user
- Implement centralized authorization checks
- Log all access attempts for audit
- Regular authorization testing
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
        ],
    },

    # File Upload
    "file_upload": {
        "title": "Unrestricted File Upload",
        "severity": "critical",
        "cwe_id": "CWE-434",
        "owasp": "A04:2021-Insecure Design",
        "description": "The application allows uploading files without proper validation, potentially allowing execution of malicious code or overwriting critical files.",
        "impact": """
- Remote code execution
- Web shell upload
- Server compromise
- Denial of service
- Malware distribution
""",
        "fix": """
1. **Validate file type by content, not extension**

   ```python
   import magic

   ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf']

   def validate_file(file):
       # Check magic bytes, not extension
       mime = magic.from_buffer(file.read(2048), mime=True)
       file.seek(0)

       if mime not in ALLOWED_TYPES:
           raise ValueError(f"File type {mime} not allowed")

       # Also check extension
       ext = os.path.splitext(file.filename)[1].lower()
       if ext not in ['.jpg', '.jpeg', '.png', '.gif', '.pdf']:
           raise ValueError("Invalid file extension")

       return True
   ```

2. **Store files outside webroot**
   ```python
   UPLOAD_DIR = '/var/app/uploads'  # Outside webroot

   def save_file(file):
       # Generate random filename
       filename = f"{uuid.uuid4()}{os.path.splitext(file.filename)[1]}"
       filepath = os.path.join(UPLOAD_DIR, filename)

       file.save(filepath)
       return filename

   # Serve files through application
   @app.route('/files/<filename>')
   def serve_file(filename):
       return send_from_directory(UPLOAD_DIR, filename)
   ```

3. **Disable execution in upload directory**
   ```nginx
   # Nginx config
   location /uploads {
       location ~ \\.(php|py|pl|cgi|asp|aspx|jsp)$ {
           deny all;
       }
   }
   ```

4. **Limit file size and scan for malware**
   ```python
   MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

   def validate_file_size(file):
       file.seek(0, 2)  # Seek to end
       size = file.tell()
       file.seek(0)

       if size > MAX_FILE_SIZE:
           raise ValueError("File too large")
   ```
""",
        "prevention": """
- Validate file type by magic bytes, not extension
- Store uploads outside the webroot
- Use random filenames, not user-provided names
- Disable script execution in upload directories
- Implement file size limits
- Scan uploads for malware
- Serve files through the application with proper headers
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ],
    },

    # Path Traversal
    "path_traversal": {
        "title": "Path Traversal / Directory Traversal",
        "severity": "high",
        "cwe_id": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "description": "The application uses user input to construct file paths without proper sanitization, allowing attackers to access files outside the intended directory.",
        "impact": """
- Sensitive file disclosure (/etc/passwd, config files)
- Source code theft
- Credential extraction
- System information disclosure
""",
        "fix": """
1. **Use basename and join safely**

   ```python
   import os

   UPLOAD_DIR = '/var/app/uploads'

   def get_file(filename):
       # VULNERABLE
       filepath = f"{UPLOAD_DIR}/{filename}"

       # SECURE - Use basename to strip path
       safe_filename = os.path.basename(filename)
       filepath = os.path.join(UPLOAD_DIR, safe_filename)

       # Additional check - ensure file is within allowed directory
       filepath = os.path.realpath(filepath)
       if not filepath.startswith(os.path.realpath(UPLOAD_DIR)):
           raise ValueError("Access denied")

       return filepath
   ```

2. **Use allowlist for file access**
   ```python
   ALLOWED_FILES = {
       'terms': '/var/app/static/terms.pdf',
       'privacy': '/var/app/static/privacy.pdf',
   }

   def get_document(doc_name):
       if doc_name not in ALLOWED_FILES:
           raise ValueError("Document not found")
       return ALLOWED_FILES[doc_name]
   ```

3. **Use framework's safe file sending**
   ```python
   from flask import send_from_directory

   @app.route('/files/<filename>')
   def serve_file(filename):
       # send_from_directory safely restricts to directory
       return send_from_directory('/var/app/files', filename)
   ```
""",
        "prevention": """
- Use os.path.basename() to strip directory components
- Validate resolved path is within allowed directory
- Use allowlists for accessible files
- Use framework's safe file serving functions
- Avoid passing user input to file operations
- Run application with minimal file permissions
""",
        "references": [
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },

    # Open Redirect
    "open_redirect": {
        "title": "Open Redirect",
        "severity": "medium",
        "cwe_id": "CWE-601",
        "owasp": "A01:2021-Broken Access Control",
        "description": "The application redirects users to URLs specified in user input without validation, enabling phishing attacks.",
        "impact": """
- Phishing attacks using trusted domain
- OAuth token theft
- Credential harvesting
- Malware distribution
""",
        "fix": """
1. **Allowlist of redirect destinations**

   ```python
   from urllib.parse import urlparse

   ALLOWED_REDIRECT_DOMAINS = ['example.com', 'app.example.com']

   def safe_redirect(url):
       parsed = urlparse(url)

       # Allow relative URLs
       if not parsed.netloc:
           return redirect(url)

       # Check domain allowlist
       if parsed.netloc in ALLOWED_REDIRECT_DOMAINS:
           return redirect(url)

       # Default to home page
       return redirect('/')
   ```

2. **Use indirect references**
   ```python
   REDIRECT_MAP = {
       'home': '/',
       'dashboard': '/dashboard',
       'profile': '/profile',
   }

   @app.route('/redirect')
   def safe_redirect():
       dest = request.args.get('dest', 'home')
       return redirect(REDIRECT_MAP.get(dest, '/'))
   ```

3. **Only allow relative URLs**
   ```python
   def is_safe_url(url):
       parsed = urlparse(url)
       # Only allow relative URLs (no scheme or netloc)
       return not parsed.scheme and not parsed.netloc
   ```
""",
        "prevention": """
- Use allowlist of redirect destinations
- Only allow relative URLs
- Use indirect references (keys) instead of URLs
- Don't pass URLs in parameters
- Log redirect requests for monitoring
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
    },
}
