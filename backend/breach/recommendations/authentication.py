"""
BREACH.AI - Authentication Vulnerability Recommendations

Fix recommendations for:
- Authentication Bypass
- JWT Attacks
- OAuth/OIDC Vulnerabilities
- MFA Bypass
- Session Management
- SAML Attacks
- Password Reset Vulnerabilities
- API Authentication Issues
"""

AUTH_RECOMMENDATIONS = {
    # JWT None Algorithm
    "jwt_none_algorithm": {
        "title": "JWT None Algorithm Attack",
        "severity": "critical",
        "cwe_id": "CWE-327",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "The application accepts JWTs with 'none' algorithm, allowing attackers to forge valid tokens without knowing the secret key.",
        "impact": """
- Complete authentication bypass
- Privilege escalation to any user
- Full account takeover
""",
        "fix": """
1. **Explicitly reject 'none' algorithm**

   Python (PyJWT):
   ```python
   import jwt

   # VULNERABLE
   data = jwt.decode(token, options={"verify_signature": False})

   # SECURE - Specify allowed algorithms
   data = jwt.decode(
       token,
       key=SECRET_KEY,
       algorithms=["HS256"]  # Explicit algorithm allowlist
   )
   ```

   Node.js (jsonwebtoken):
   ```javascript
   // VULNERABLE
   jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });

   // SECURE
   jwt.verify(token, secret, { algorithms: ['HS256'] });
   ```

2. **Use asymmetric algorithms (RS256) when possible**
   ```python
   data = jwt.decode(
       token,
       key=PUBLIC_KEY,
       algorithms=["RS256"]
   )
   ```
""",
        "prevention": """
- Always specify an explicit algorithm allowlist
- Never accept 'none' as a valid algorithm
- Consider using asymmetric algorithms (RS256/ES256)
- Validate all JWT claims (exp, iss, aud)
- Use short expiration times
""",
        "references": [
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
    },

    # JWT Algorithm Confusion
    "jwt_algorithm_confusion": {
        "title": "JWT Algorithm Confusion Attack",
        "severity": "critical",
        "cwe_id": "CWE-327",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "The application can be tricked into using HMAC verification with a public RSA key, allowing attackers to forge tokens.",
        "impact": """
- Authentication bypass
- Token forgery
- Full account takeover
""",
        "fix": """
1. **Explicitly specify the expected algorithm**

   ```python
   # VULNERABLE - Algorithm from token header
   algorithm = jwt.get_unverified_header(token)['alg']
   data = jwt.decode(token, key, algorithms=[algorithm])

   # SECURE - Fixed algorithm
   data = jwt.decode(
       token,
       key=RSA_PUBLIC_KEY,
       algorithms=["RS256"]  # Only allow RS256
   )
   ```

2. **Use separate keys for different algorithms**
   ```python
   if algorithm == "HS256":
       key = HMAC_SECRET
   elif algorithm == "RS256":
       key = RSA_PUBLIC_KEY
   else:
       raise ValueError("Unsupported algorithm")
   ```

3. **Use libraries that prevent confusion attacks**
   - PyJWT 2.x+ is safe by default when algorithms specified
""",
        "prevention": """
- Never derive algorithm from the token itself
- Use a fixed, server-configured algorithm
- Prefer asymmetric algorithms (RS256, ES256)
- Use separate key storage for different algorithms
""",
        "references": [
            "https://portswigger.net/web-security/jwt/algorithm-confusion",
        ],
    },

    # JWT Weak Secret
    "jwt_weak_secret": {
        "title": "JWT Weak Secret Key",
        "severity": "critical",
        "cwe_id": "CWE-521",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "The JWT is signed with a weak or predictable secret key that can be brute-forced.",
        "impact": """
- Token forgery
- Authentication bypass
- Privilege escalation
""",
        "fix": """
1. **Use a strong, random secret key**

   ```python
   import secrets

   # Generate a 256-bit secret
   SECRET_KEY = secrets.token_hex(32)

   # Store securely in environment variable
   SECRET_KEY = os.environ['JWT_SECRET']
   ```

2. **Use asymmetric keys (RS256) for production**
   ```bash
   # Generate RSA key pair
   openssl genrsa -out private.pem 2048
   openssl rsa -in private.pem -pubout -out public.pem
   ```

3. **Key rotation**
   - Implement key rotation with kid (key ID) claim
   - Support multiple keys during rotation period
""",
        "prevention": """
- Use secrets.token_bytes(32) or equivalent for HMAC secrets
- Use RSA-2048 or better for asymmetric algorithms
- Store secrets in secure vaults (HashiCorp Vault, AWS Secrets Manager)
- Implement key rotation
- Never commit secrets to source control
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ],
    },

    # OAuth Redirect URI Bypass
    "oauth_redirect_bypass": {
        "title": "OAuth Redirect URI Bypass",
        "severity": "high",
        "cwe_id": "CWE-601",
        "owasp": "A01:2021-Broken Access Control",
        "description": "The OAuth implementation does not properly validate redirect URIs, allowing attackers to steal authorization codes or tokens.",
        "impact": """
- Authorization code theft
- Access token theft
- Account takeover
- Phishing amplification
""",
        "fix": """
1. **Exact string matching for redirect URIs**

   ```python
   REGISTERED_REDIRECT_URIS = [
       "https://app.example.com/callback",
       "https://app.example.com/oauth/callback"
   ]

   def validate_redirect_uri(redirect_uri):
       if redirect_uri not in REGISTERED_REDIRECT_URIS:
           raise ValueError("Invalid redirect_uri")
       return redirect_uri
   ```

2. **Never use substring or regex matching**
   ```python
   # VULNERABLE
   if redirect_uri.startswith("https://app.example.com"):
       pass  # This allows https://app.example.com.evil.com

   # SECURE
   if redirect_uri in REGISTERED_REDIRECT_URIS:
       pass
   ```

3. **Require HTTPS for all redirect URIs**
   ```python
   from urllib.parse import urlparse

   def validate_redirect_uri(uri):
       parsed = urlparse(uri)
       if parsed.scheme != 'https':
           raise ValueError("HTTPS required for redirect URI")
   ```
""",
        "prevention": """
- Use exact string matching for redirect URI validation
- Never allow open redirects in callback URLs
- Always require HTTPS
- Implement state parameter to prevent CSRF
- Use PKCE for public clients
""",
        "references": [
            "https://oauth.net/2/redirect-uri-validation/",
        ],
    },

    # MFA Bypass
    "mfa_bypass": {
        "title": "Multi-Factor Authentication Bypass",
        "severity": "critical",
        "cwe_id": "CWE-287",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "The MFA implementation can be bypassed through various techniques such as response manipulation, direct endpoint access, or code reuse.",
        "impact": """
- Complete MFA bypass
- Account takeover despite MFA enabled
- Credential stuffing attacks become effective
""",
        "fix": """
1. **Server-side MFA state verification**

   ```python
   def verify_mfa(user_id, code, session):
       # VULNERABLE - Client-controlled state
       if request.json.get('mfa_verified'):
           return True

       # SECURE - Server-side state
       if not session.get('mfa_pending'):
           raise ValueError("MFA not initiated")

       user = get_user(user_id)
       if not verify_totp(user.mfa_secret, code):
           raise ValueError("Invalid MFA code")

       session['mfa_verified'] = True
       session.pop('mfa_pending')
       return True
   ```

2. **Single-use MFA codes**
   ```python
   def verify_and_invalidate_code(user_id, code):
       if code in get_used_codes(user_id):
           raise ValueError("Code already used")

       if verify_totp(user.mfa_secret, code):
           mark_code_used(user_id, code)
           return True
       return False
   ```

3. **Rate limiting on MFA attempts**
   ```python
   @rate_limit(max_attempts=5, window=300)
   def verify_mfa_code(user_id, code):
       pass
   ```

4. **Enforce MFA on all sensitive operations**
   ```python
   @require_mfa
   def change_password(user_id, new_password):
       pass
   ```
""",
        "prevention": """
- Maintain MFA state server-side only
- Implement single-use codes
- Rate limit MFA verification attempts
- Lock accounts after excessive failures
- Require MFA re-verification for sensitive operations
- Audit log all MFA events
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
        ],
    },

    # Session Fixation
    "session_fixation": {
        "title": "Session Fixation",
        "severity": "high",
        "cwe_id": "CWE-384",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "The application does not regenerate session IDs after authentication, allowing attackers to fixate a known session ID and hijack the session after the victim logs in.",
        "impact": """
- Session hijacking
- Account takeover
- Unauthorized access to user data
""",
        "fix": """
1. **Regenerate session ID after authentication**

   Python (Flask):
   ```python
   from flask import session

   @app.route('/login', methods=['POST'])
   def login():
       if authenticate(username, password):
           # Regenerate session
           session.clear()
           session['user_id'] = user.id
           session.regenerate()  # If using Flask-Session
           return redirect('/dashboard')
   ```

   Django:
   ```python
   from django.contrib.auth import login

   def login_view(request):
       if authenticate(request, username=username, password=password):
           # Django's login() regenerates session automatically
           login(request, user)
   ```

2. **Invalidate old sessions on login**
   ```python
   def login_user(user):
       # Delete all existing sessions for user
       Session.objects.filter(user=user).delete()
       # Create new session
       create_session(user)
   ```

3. **Use secure session configuration**
   ```python
   SESSION_COOKIE_SECURE = True
   SESSION_COOKIE_HTTPONLY = True
   SESSION_COOKIE_SAMESITE = 'Lax'
   ```
""",
        "prevention": """
- Always regenerate session ID after login
- Regenerate session ID after privilege changes
- Use secure, random session ID generation
- Implement session timeout
- Don't accept session IDs from URLs
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },

    # Default Credentials
    "default_credentials": {
        "title": "Default Credentials",
        "severity": "critical",
        "cwe_id": "CWE-1392",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "The application or service uses default, commonly known credentials that have not been changed.",
        "impact": """
- Immediate unauthorized access
- Full administrative control
- Data breach
- Service compromise
""",
        "fix": """
1. **Force password change on first login**

   ```python
   def first_login(user_id, current_password, new_password):
       user = get_user(user_id)

       if user.must_change_password:
           if current_password == user.password:
               user.password = hash_password(new_password)
               user.must_change_password = False
               save_user(user)
           else:
               raise ValueError("Invalid current password")
   ```

2. **Generate unique initial passwords**
   ```python
   import secrets

   def create_user(username, email):
       initial_password = secrets.token_urlsafe(16)
       user = User(
           username=username,
           email=email,
           password=hash_password(initial_password),
           must_change_password=True
       )
       send_welcome_email(email, initial_password)
       return user
   ```

3. **Remove or disable default accounts**
   ```sql
   -- Remove default admin accounts
   DELETE FROM users WHERE username IN ('admin', 'administrator', 'root', 'test');
   ```

4. **Automated credential scanning**
   - Include default credential checks in CI/CD
   - Scan for hardcoded credentials in code
""",
        "prevention": """
- Never ship products with default credentials
- Force password changes on first use
- Generate unique passwords for each installation
- Implement account lockout for failed attempts
- Audit for default credentials regularly
""",
        "references": [
            "https://cwe.mitre.org/data/definitions/1392.html",
        ],
    },

    # SAML Signature Bypass
    "saml_signature_bypass": {
        "title": "SAML Signature Bypass",
        "severity": "critical",
        "cwe_id": "CWE-347",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "The SAML implementation does not properly verify signatures, allowing attackers to forge SAML assertions.",
        "impact": """
- Authentication bypass
- Identity spoofing
- Unauthorized access as any user
- Privilege escalation
""",
        "fix": """
1. **Always verify SAML signatures**

   Python (python-saml):
   ```python
   from onelogin.saml2.auth import OneLogin_Saml2_Auth

   auth = OneLogin_Saml2_Auth(req, settings)
   auth.process_response()

   if not auth.is_authenticated():
       raise ValueError("SAML authentication failed")

   errors = auth.get_errors()
   if errors:
       raise ValueError(f"SAML errors: {errors}")
   ```

2. **Validate the entire assertion is signed**
   ```python
   settings = {
       'security': {
           'wantAssertionsSigned': True,
           'wantMessagesSigned': True,
           'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
       }
   }
   ```

3. **Validate certificate chain**
   ```python
   def validate_saml_cert(cert):
       # Verify certificate is from trusted IdP
       # Check certificate expiration
       # Validate certificate chain
       pass
   ```
""",
        "prevention": """
- Always require signed assertions
- Validate complete signature (not just presence)
- Use strong signature algorithms (RSA-SHA256+)
- Validate IdP certificates
- Check assertion expiration and audience
- Log all SAML authentication events
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html",
        ],
    },

    # Password Reset Token Issues
    "password_reset_token": {
        "title": "Insecure Password Reset Token",
        "severity": "high",
        "cwe_id": "CWE-640",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "Password reset tokens are predictable, reusable, or do not expire properly, allowing attackers to take over accounts.",
        "impact": """
- Account takeover
- Unauthorized password changes
- Mass account compromise if tokens are predictable
""",
        "fix": """
1. **Generate cryptographically secure tokens**

   ```python
   import secrets
   from datetime import datetime, timedelta

   def create_reset_token(user_id):
       token = secrets.token_urlsafe(32)  # 256 bits
       expiry = datetime.utcnow() + timedelta(hours=1)

       store_reset_token(
           user_id=user_id,
           token_hash=hash_token(token),  # Store hashed
           expires_at=expiry
       )
       return token  # Send unhashed to user
   ```

2. **Single-use tokens**
   ```python
   def use_reset_token(token, new_password):
       token_record = get_token_by_hash(hash_token(token))

       if not token_record:
           raise ValueError("Invalid token")

       if token_record.expires_at < datetime.utcnow():
           raise ValueError("Token expired")

       if token_record.used:
           raise ValueError("Token already used")

       # Reset password
       update_password(token_record.user_id, new_password)

       # Invalidate token
       token_record.used = True
       save_token(token_record)

       # Invalidate all sessions
       invalidate_user_sessions(token_record.user_id)
   ```

3. **Invalidate token after password change**
   - Delete all reset tokens for user after successful reset
   - Log out all active sessions
""",
        "prevention": """
- Use cryptographically random tokens (32+ bytes)
- Store token hashes, not plaintext
- Implement short expiration (1 hour max)
- Single-use tokens only
- Rate limit reset requests
- Notify user of password reset via alternate channel
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
        ],
    },
}
