"""
BREACH.AI - API Security Vulnerability Recommendations

Fix recommendations for:
- REST API Vulnerabilities
- GraphQL Vulnerabilities
- WebSocket Security
- API Authentication Issues
- Rate Limiting
- API Versioning
"""

API_RECOMMENDATIONS = {
    # BOLA (Broken Object Level Authorization)
    "bola": {
        "title": "Broken Object Level Authorization (BOLA)",
        "severity": "critical",
        "cwe_id": "CWE-639",
        "owasp": "API1:2023-Broken Object Level Authorization",
        "description": "API endpoints expose object references (IDs) that can be manipulated to access unauthorized resources without proper authorization checks.",
        "impact": """
- Unauthorized data access
- Data theft
- Privacy violations
- Horizontal privilege escalation
""",
        "fix": """
1. **Implement authorization checks on every endpoint**

   ```python
   @app.route('/api/v1/orders/<int:order_id>')
   @login_required
   def get_order(order_id):
       order = Order.query.get_or_404(order_id)

       # VULNERABLE - No authorization check
       return jsonify(order.to_dict())

       # SECURE - Verify ownership
       if order.user_id != current_user.id:
           abort(403)
       return jsonify(order.to_dict())
   ```

2. **Use policy-based authorization**
   ```python
   from functools import wraps

   def authorize(resource_type):
       def decorator(f):
           @wraps(f)
           def wrapper(*args, **kwargs):
               resource_id = kwargs.get('id') or kwargs.get(f'{resource_type}_id')
               if not can_access(current_user, resource_type, resource_id):
                   abort(403)
               return f(*args, **kwargs)
           return wrapper
       return decorator

   @app.route('/api/v1/orders/<int:order_id>')
   @login_required
   @authorize('order')
   def get_order(order_id):
       return jsonify(Order.query.get(order_id).to_dict())
   ```

3. **Scope queries to user context**
   ```python
   # VULNERABLE
   order = Order.query.get(order_id)

   # SECURE
   order = Order.query.filter_by(
       id=order_id,
       user_id=current_user.id
   ).first_or_404()
   ```

4. **Use unpredictable identifiers**
   ```python
   import uuid

   class Order(db.Model):
       id = db.Column(db.Integer, primary_key=True)
       public_id = db.Column(db.String(36), default=lambda: str(uuid.uuid4()))
   ```
""",
        "prevention": """
- Implement authorization checks on every endpoint
- Use centralized authorization middleware
- Scope all database queries to the user context
- Use UUIDs instead of sequential IDs
- Log all access attempts
- Regular security testing for BOLA
""",
        "references": [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
    },

    # Mass Assignment
    "mass_assignment": {
        "title": "Mass Assignment Vulnerability",
        "severity": "high",
        "cwe_id": "CWE-915",
        "owasp": "API3:2023-Broken Object Property Level Authorization",
        "description": "The API accepts and processes more properties than intended, allowing attackers to modify protected fields like roles, permissions, or account status.",
        "impact": """
- Privilege escalation (changing role to admin)
- Bypassing payment (setting price to 0)
- Account manipulation
- Data corruption
""",
        "fix": """
1. **Use explicit allowlists for input**

   ```python
   # VULNERABLE - Accepts all fields
   @app.route('/api/v1/users/<int:id>', methods=['PUT'])
   def update_user(id):
       user = User.query.get(id)
       user.update(**request.json)  # Dangerous!
       db.session.commit()

   # SECURE - Explicit allowlist
   ALLOWED_FIELDS = ['name', 'email', 'bio']

   @app.route('/api/v1/users/<int:id>', methods=['PUT'])
   def update_user(id):
       user = User.query.get(id)
       data = request.json

       for field in ALLOWED_FIELDS:
           if field in data:
               setattr(user, field, data[field])

       db.session.commit()
   ```

2. **Use DTOs/Schemas for input validation**
   ```python
   from pydantic import BaseModel

   class UserUpdateSchema(BaseModel):
       name: str = None
       email: str = None
       bio: str = None
       # Note: role, is_admin NOT included

       class Config:
           extra = 'forbid'  # Reject unknown fields

   @app.route('/api/v1/users/<int:id>', methods=['PUT'])
   def update_user(id):
       data = UserUpdateSchema(**request.json)
       user = User.query.get(id)
       user.update(**data.dict(exclude_unset=True))
       db.session.commit()
   ```

3. **Use read-only properties in ORM**
   ```python
   class User(db.Model):
       role = db.Column(db.String(50), default='user')

       def update(self, **kwargs):
           # Remove protected fields
           protected = ['role', 'is_admin', 'password_hash']
           for field in protected:
               kwargs.pop(field, None)
           for key, value in kwargs.items():
               setattr(self, key, value)
   ```
""",
        "prevention": """
- Use explicit allowlists for updateable fields
- Use DTOs/schemas with validation
- Never pass raw request data to ORM updates
- Document which fields are user-modifiable
- Log all field modifications
- Security test for mass assignment
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        ],
    },

    # GraphQL Introspection
    "graphql_introspection": {
        "title": "GraphQL Introspection Enabled in Production",
        "severity": "medium",
        "cwe_id": "CWE-200",
        "owasp": "API8:2023-Security Misconfiguration",
        "description": "GraphQL introspection is enabled, exposing the entire API schema including internal fields, deprecated endpoints, and hidden functionality.",
        "impact": """
- Schema exposure
- Internal field discovery
- Attack surface enumeration
- Sensitive field identification
""",
        "fix": """
1. **Disable introspection in production**

   Python (Graphene):
   ```python
   from graphene import Schema
   from graphql import validate, parse
   from graphql.validation import NoSchemaIntrospectionCustomRule

   schema = Schema(query=Query, mutation=Mutation)

   # Add validation rule
   if not settings.DEBUG:
       schema.validation_rules = [NoSchemaIntrospectionCustomRule]
   ```

   Python (Ariadne):
   ```python
   from ariadne import make_executable_schema
   from ariadne.validation import IntrospectionDisabledRule

   schema = make_executable_schema(type_defs, resolvers)

   app = GraphQL(
       schema,
       validation_rules=[IntrospectionDisabledRule] if not DEBUG else []
   )
   ```

   Node.js (Apollo):
   ```javascript
   const server = new ApolloServer({
     schema,
     introspection: process.env.NODE_ENV !== 'production',
   });
   ```

2. **Use persisted queries**
   ```javascript
   // Only allow pre-registered queries
   const server = new ApolloServer({
     schema,
     persistedQueries: {
       cache: new InMemoryLRUCache()
     },
     // Reject non-persisted queries in production
     allowBatchedHttpRequests: false,
   });
   ```
""",
        "prevention": """
- Disable introspection in production
- Use persisted queries where possible
- Implement query depth limiting
- Use query cost analysis
- Monitor GraphQL query patterns
- Regular schema security review
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        ],
    },

    # GraphQL Query Depth Attack
    "graphql_depth_attack": {
        "title": "GraphQL Query Depth Attack",
        "severity": "high",
        "cwe_id": "CWE-400",
        "owasp": "API4:2023-Unrestricted Resource Consumption",
        "description": "GraphQL allows deeply nested queries that can cause denial of service by exhausting server resources.",
        "impact": """
- Denial of service
- Server resource exhaustion
- Database overload
- Service unavailability
""",
        "fix": """
1. **Implement query depth limiting**

   Python (Graphene):
   ```python
   from graphql import validate
   from graphql.validation import DepthLimitRule

   def execute_query(schema, query):
       # Limit depth to 10 levels
       validation_errors = validate(
           schema,
           parse(query),
           [DepthLimitRule(10)]
       )
       if validation_errors:
           raise Exception("Query too deep")
   ```

   Node.js:
   ```javascript
   import depthLimit from 'graphql-depth-limit';

   const server = new ApolloServer({
     schema,
     validationRules: [depthLimit(10)]
   });
   ```

2. **Implement query complexity/cost analysis**
   ```python
   from graphql import GraphQLError

   def calculate_query_cost(query_ast, schema):
       # Calculate cost based on fields and arguments
       cost = 0
       for field in query_ast.definitions:
           cost += calculate_field_cost(field)
       return cost

   MAX_COST = 1000

   def validate_query_cost(query):
       cost = calculate_query_cost(query)
       if cost > MAX_COST:
           raise GraphQLError(f"Query cost {cost} exceeds maximum {MAX_COST}")
   ```

3. **Limit query aliases and fragments**
   ```javascript
   const server = new ApolloServer({
     schema,
     validationRules: [
       depthLimit(10),
       queryComplexity({
         maximumComplexity: 1000,
         estimators: [fieldExtensionsEstimator(), simpleEstimator()]
       })
     ]
   });
   ```
""",
        "prevention": """
- Implement query depth limiting (max 10-15)
- Use query complexity analysis
- Set timeout limits on queries
- Implement rate limiting
- Monitor query performance
- Use DataLoader for batching
""",
        "references": [
            "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
        ],
    },

    # API Rate Limiting Missing
    "api_rate_limiting": {
        "title": "Missing API Rate Limiting",
        "severity": "medium",
        "cwe_id": "CWE-770",
        "owasp": "API4:2023-Unrestricted Resource Consumption",
        "description": "API endpoints lack rate limiting, allowing attackers to perform brute force attacks, denial of service, or resource exhaustion.",
        "impact": """
- Brute force attacks
- Credential stuffing
- Denial of service
- Resource exhaustion
- Cost inflation (pay-per-use APIs)
""",
        "fix": """
1. **Implement rate limiting middleware**

   Python (Flask-Limiter):
   ```python
   from flask_limiter import Limiter
   from flask_limiter.util import get_remote_address

   limiter = Limiter(
       app,
       key_func=get_remote_address,
       default_limits=["100 per minute", "1000 per hour"]
   )

   @app.route('/api/v1/login', methods=['POST'])
   @limiter.limit("5 per minute")  # Strict limit on auth
   def login():
       pass

   @app.route('/api/v1/search')
   @limiter.limit("30 per minute")
   def search():
       pass
   ```

   Node.js (express-rate-limit):
   ```javascript
   const rateLimit = require('express-rate-limit');

   const apiLimiter = rateLimit({
     windowMs: 15 * 60 * 1000, // 15 minutes
     max: 100,
     message: 'Too many requests'
   });

   const authLimiter = rateLimit({
     windowMs: 60 * 1000, // 1 minute
     max: 5,
     message: 'Too many login attempts'
   });

   app.use('/api/', apiLimiter);
   app.use('/api/auth/', authLimiter);
   ```

2. **Use token bucket or sliding window**
   ```python
   import redis

   class RateLimiter:
       def __init__(self, redis_client, max_requests, window_seconds):
           self.redis = redis_client
           self.max_requests = max_requests
           self.window = window_seconds

       def is_allowed(self, key):
           current = self.redis.incr(key)
           if current == 1:
               self.redis.expire(key, self.window)
           return current <= self.max_requests
   ```

3. **Return rate limit headers**
   ```python
   @app.after_request
   def add_rate_limit_headers(response):
       response.headers['X-RateLimit-Limit'] = '100'
       response.headers['X-RateLimit-Remaining'] = str(remaining)
       response.headers['X-RateLimit-Reset'] = str(reset_time)
       return response
   ```
""",
        "prevention": """
- Implement rate limiting on all endpoints
- Use stricter limits on authentication endpoints
- Return rate limit headers for transparency
- Monitor rate limit violations
- Use distributed rate limiting for scale
- Consider per-user and per-IP limits
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
        ],
    },

    # WebSocket Security
    "websocket_security": {
        "title": "WebSocket Security Vulnerabilities",
        "severity": "high",
        "cwe_id": "CWE-1385",
        "owasp": "API8:2023-Security Misconfiguration",
        "description": "WebSocket connections lack proper authentication, authorization, or input validation, allowing unauthorized access or injection attacks.",
        "impact": """
- Unauthorized data access
- Cross-Site WebSocket Hijacking (CSWSH)
- Message injection
- Session hijacking
""",
        "fix": """
1. **Authenticate WebSocket connections**

   ```python
   from flask_socketio import SocketIO, disconnect
   from functools import wraps

   socketio = SocketIO(app)

   def authenticated_only(f):
       @wraps(f)
       def wrapper(*args, **kwargs):
           if not current_user.is_authenticated:
               disconnect()
               return
           return f(*args, **kwargs)
       return wrapper

   @socketio.on('connect')
   def handle_connect():
       if not current_user.is_authenticated:
           return False  # Reject connection
   ```

2. **Validate message input**
   ```python
   from pydantic import BaseModel, ValidationError

   class ChatMessage(BaseModel):
       room: str
       content: str
       type: str = 'text'

   @socketio.on('message')
   @authenticated_only
   def handle_message(data):
       try:
           message = ChatMessage(**data)
           # Process validated message
       except ValidationError:
           emit('error', {'message': 'Invalid message format'})
   ```

3. **Implement origin checking**
   ```python
   ALLOWED_ORIGINS = ['https://app.example.com']

   @socketio.on('connect')
   def handle_connect():
       origin = request.headers.get('Origin')
       if origin not in ALLOWED_ORIGINS:
           return False

   # Or in SocketIO config
   socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS)
   ```

4. **Use secure WebSocket (WSS)**
   ```javascript
   // Client-side
   const socket = new WebSocket('wss://api.example.com/ws');

   // Server-side (nginx)
   server {
       listen 443 ssl;
       location /ws {
           proxy_pass http://backend;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
       }
   }
   ```
""",
        "prevention": """
- Authenticate all WebSocket connections
- Validate all message input
- Implement origin checking
- Use WSS (WebSocket Secure) only
- Rate limit messages
- Implement message size limits
- Log WebSocket events
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets",
        ],
    },

    # API Key Exposure
    "api_key_exposure": {
        "title": "API Key Exposure",
        "severity": "critical",
        "cwe_id": "CWE-798",
        "owasp": "API2:2023-Broken Authentication",
        "description": "API keys are exposed in client-side code, URLs, logs, or version control, allowing unauthorized API access.",
        "impact": """
- Unauthorized API access
- Data theft
- Service abuse
- Cost inflation
- Account compromise
""",
        "fix": """
1. **Never expose API keys in client-side code**

   ```javascript
   // VULNERABLE - Key in frontend
   const API_KEY = 'sk_live_abc123';
   fetch(`/api/data?key=${API_KEY}`);

   // SECURE - Proxy through backend
   // Frontend
   fetch('/api/proxy/data');

   // Backend
   @app.route('/api/proxy/data')
   def proxy_data():
       response = requests.get(
           'https://external-api.com/data',
           headers={'Authorization': f'Bearer {os.environ["API_KEY"]}'}
       )
       return response.json()
   ```

2. **Use environment variables**
   ```python
   import os

   # VULNERABLE
   API_KEY = 'sk_live_abc123'

   # SECURE
   API_KEY = os.environ.get('API_KEY')
   if not API_KEY:
       raise ValueError("API_KEY not configured")
   ```

3. **Rotate exposed keys immediately**
   ```bash
   # 1. Generate new key
   # 2. Update all services
   # 3. Revoke old key
   # 4. Monitor for unauthorized usage
   ```

4. **Use secrets scanning in CI/CD**
   ```yaml
   # GitHub Actions
   - name: Scan for secrets
     uses: trufflesecurity/trufflehog@main
     with:
       path: ./
       base: main
   ```

5. **Implement key scoping**
   ```python
   # Create keys with minimal permissions
   api_key = create_api_key(
       user_id=user.id,
       scopes=['read:data'],  # Limited scope
       expires_in=30*24*60*60  # 30 days
   )
   ```
""",
        "prevention": """
- Never commit API keys to version control
- Use environment variables or secrets managers
- Implement key rotation policies
- Use scoped keys with minimal permissions
- Enable secrets scanning in CI/CD
- Monitor API key usage
- Use short-lived tokens where possible
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
    },
}
