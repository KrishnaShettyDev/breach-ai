"""
BREACH.AI - Cloud Security Vulnerability Recommendations

Fix recommendations for:
- AWS Security Issues
- Azure Security Issues
- GCP Security Issues
- Cloud Storage Misconfigurations
- Container Security
- Kubernetes Security
"""

CLOUD_RECOMMENDATIONS = {
    # AWS IAM Privilege Escalation
    "aws_iam_escalation": {
        "title": "AWS IAM Privilege Escalation",
        "severity": "critical",
        "cwe_id": "CWE-269",
        "owasp": "A01:2021-Broken Access Control",
        "description": "IAM policies allow privilege escalation through overly permissive permissions such as iam:CreateRole, iam:AttachRolePolicy, or sts:AssumeRole.",
        "impact": """
- Escalation to administrator privileges
- Full AWS account compromise
- Access to all resources and data
- Ability to create backdoor access
""",
        "fix": """
1. **Apply least privilege IAM policies**

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "LimitedS3Access",
         "Effect": "Allow",
         "Action": [
           "s3:GetObject",
           "s3:PutObject"
         ],
         "Resource": "arn:aws:s3:::my-bucket/uploads/*"
       }
     ]
   }
   ```

2. **Restrict dangerous IAM permissions**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "DenyIAMEscalation",
         "Effect": "Deny",
         "Action": [
           "iam:CreateUser",
           "iam:CreateRole",
           "iam:AttachUserPolicy",
           "iam:AttachRolePolicy",
           "iam:PutUserPolicy",
           "iam:PutRolePolicy",
           "iam:CreateAccessKey"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. **Use Permission Boundaries**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "*",
         "Resource": "*",
         "Condition": {
           "StringEquals": {
             "aws:RequestedRegion": "us-east-1"
           }
         }
       },
       {
         "Effect": "Deny",
         "Action": "iam:*",
         "Resource": "*"
       }
     ]
   }
   ```

4. **Enable AWS Organizations SCPs**
   - Restrict sensitive actions at organization level
   - Prevent privilege escalation across accounts
""",
        "prevention": """
- Regular IAM policy audits with AWS Access Analyzer
- Use permission boundaries for all roles
- Implement SCPs for organization-wide restrictions
- Use AWS Config rules for IAM compliance
- Enable CloudTrail for IAM action monitoring
- Use IAM Access Advisor to identify unused permissions
""",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
        ],
    },

    # AWS S3 Bucket Misconfiguration
    "s3_public_bucket": {
        "title": "Public S3 Bucket",
        "severity": "critical",
        "cwe_id": "CWE-732",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "S3 bucket is publicly accessible, exposing sensitive data to the internet.",
        "impact": """
- Data breach
- Sensitive file exposure
- Regulatory compliance violations
- Reputational damage
""",
        "fix": """
1. **Block public access at account level**

   ```bash
   aws s3control put-public-access-block \\
     --account-id 123456789012 \\
     --public-access-block-configuration \\
       BlockPublicAcls=true,\\
       IgnorePublicAcls=true,\\
       BlockPublicPolicy=true,\\
       RestrictPublicBuckets=true
   ```

2. **Block public access on bucket**
   ```bash
   aws s3api put-public-access-block \\
     --bucket my-bucket \\
     --public-access-block-configuration \\
       BlockPublicAcls=true,\\
       IgnorePublicAcls=true,\\
       BlockPublicPolicy=true,\\
       RestrictPublicBuckets=true
   ```

3. **Remove public ACLs**
   ```bash
   aws s3api put-bucket-acl --bucket my-bucket --acl private
   ```

4. **Use bucket policies to restrict access**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "DenyPublicAccess",
         "Effect": "Deny",
         "Principal": "*",
         "Action": "s3:*",
         "Resource": [
           "arn:aws:s3:::my-bucket",
           "arn:aws:s3:::my-bucket/*"
         ],
         "Condition": {
           "Bool": {
             "aws:SecureTransport": "false"
           }
         }
       }
     ]
   }
   ```

5. **Enable S3 encryption**
   ```bash
   aws s3api put-bucket-encryption --bucket my-bucket \\
     --server-side-encryption-configuration '{
       "Rules": [{
         "ApplyServerSideEncryptionByDefault": {
           "SSEAlgorithm": "AES256"
         }
       }]
     }'
   ```
""",
        "prevention": """
- Enable S3 Block Public Access at account level
- Use AWS Config rule s3-bucket-public-read-prohibited
- Enable S3 access logging
- Use CloudTrail for S3 data events
- Regular bucket policy audits
- Use Macie for sensitive data discovery
""",
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ],
    },

    # AWS Metadata Service
    "aws_metadata_exposed": {
        "title": "AWS Metadata Service Exposed via SSRF",
        "severity": "critical",
        "cwe_id": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "description": "The EC2 instance metadata service (IMDS) is accessible via SSRF, allowing credential theft.",
        "impact": """
- AWS credential theft
- IAM role privilege abuse
- Account compromise
- Data exfiltration
""",
        "fix": """
1. **Use IMDSv2 (requires session tokens)**

   ```bash
   aws ec2 modify-instance-metadata-options \\
     --instance-id i-1234567890abcdef0 \\
     --http-tokens required \\
     --http-endpoint enabled
   ```

   Terraform:
   ```hcl
   resource "aws_instance" "example" {
     metadata_options {
       http_tokens   = "required"
       http_endpoint = "enabled"
     }
   }
   ```

2. **Block metadata access in application code**
   ```python
   BLOCKED_HOSTS = ['169.254.169.254', '169.254.170.2']

   def validate_url(url):
       parsed = urlparse(url)
       if parsed.hostname in BLOCKED_HOSTS:
           raise ValueError("Metadata service access blocked")
   ```

3. **Use IAM roles with minimal permissions**
   - Only attach necessary permissions to EC2 instance role
   - Use resource-based conditions

4. **Network-level blocking**
   ```bash
   # iptables rule to block metadata for non-root
   iptables -A OUTPUT -m owner ! --uid-owner root \\
     -d 169.254.169.254 -j DROP
   ```
""",
        "prevention": """
- Require IMDSv2 for all EC2 instances
- Block metadata IP in application SSRF checks
- Use minimal IAM permissions on instance roles
- Enable VPC Flow Logs to detect metadata access
- Use AWS Config for IMDSv2 enforcement
""",
        "references": [
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        ],
    },

    # Azure Managed Identity
    "azure_managed_identity": {
        "title": "Azure Managed Identity Token Theft",
        "severity": "critical",
        "cwe_id": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "description": "Azure Instance Metadata Service (IMDS) is accessible via SSRF, allowing managed identity token theft.",
        "impact": """
- Azure credential theft
- Access to Azure resources
- Subscription compromise
- Data breach
""",
        "fix": """
1. **Block IMDS access in application code**

   ```python
   BLOCKED_HOSTS = [
       '169.254.169.254',  # Azure IMDS
       'metadata.azure.com'
   ]

   def validate_url(url):
       parsed = urlparse(url)
       if parsed.hostname in BLOCKED_HOSTS:
           raise ValueError("Metadata service access blocked")
   ```

2. **Use minimal managed identity permissions**
   ```bash
   # Assign specific role, not broad access
   az role assignment create \\
     --assignee <managed-identity-id> \\
     --role "Storage Blob Data Reader" \\
     --scope /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<storage>
   ```

3. **Use network isolation**
   - Deploy in private subnets
   - Use NSGs to restrict outbound traffic

4. **Monitor IMDS access**
   - Enable Azure Activity Log
   - Alert on suspicious token requests
""",
        "prevention": """
- Block IMDS endpoints in SSRF validation
- Apply least privilege to managed identities
- Use Conditional Access policies
- Monitor token usage with Azure Monitor
- Use Private Endpoints where possible
""",
        "references": [
            "https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview",
        ],
    },

    # Docker Socket Exposed
    "docker_socket_exposed": {
        "title": "Docker Socket Exposed",
        "severity": "critical",
        "cwe_id": "CWE-269",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "The Docker socket (/var/run/docker.sock) is accessible to the container or exposed over the network, allowing container escape and host compromise.",
        "impact": """
- Container escape
- Host system compromise
- Full infrastructure takeover
- Data access across all containers
""",
        "fix": """
1. **Never mount Docker socket unless absolutely necessary**

   ```yaml
   # DANGEROUS - Don't do this
   volumes:
     - /var/run/docker.sock:/var/run/docker.sock

   # If required, use read-only (still dangerous)
   volumes:
     - /var/run/docker.sock:/var/run/docker.sock:ro
   ```

2. **Use Docker-in-Docker (dind) for CI/CD**
   ```yaml
   services:
     docker:
       image: docker:dind
       privileged: true  # Runs in isolated container
   ```

3. **Use rootless Docker**
   ```bash
   # Install rootless Docker
   dockerd-rootless-setuptool.sh install
   ```

4. **Use Podman instead of Docker**
   - Podman is daemonless and more secure
   - No socket to expose

5. **If socket access needed, use proxy**
   ```yaml
   # Use socket-proxy with limited API access
   services:
     socket-proxy:
       image: tecnativa/docker-socket-proxy
       environment:
         CONTAINERS: 1
         IMAGES: 0
         NETWORKS: 0
         VOLUMES: 0
       volumes:
         - /var/run/docker.sock:/var/run/docker.sock
   ```
""",
        "prevention": """
- Never mount Docker socket in containers
- Use Docker-in-Docker for CI/CD pipelines
- Use rootless Docker or Podman
- If socket needed, use socket proxy with minimal permissions
- Run containers with read-only root filesystem
- Use seccomp profiles to restrict syscalls
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
        ],
    },

    # Kubernetes RBAC Misconfiguration
    "kubernetes_rbac": {
        "title": "Kubernetes RBAC Misconfiguration",
        "severity": "high",
        "cwe_id": "CWE-269",
        "owasp": "A01:2021-Broken Access Control",
        "description": "Kubernetes Role-Based Access Control is misconfigured, allowing privilege escalation or unauthorized access to cluster resources.",
        "impact": """
- Pod escape
- Secrets access
- Cluster takeover
- Data breach
""",
        "fix": """
1. **Avoid cluster-admin for applications**

   ```yaml
   # BAD - Too permissive
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRoleBinding
   metadata:
     name: app-admin
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: ClusterRole
     name: cluster-admin
   subjects:
   - kind: ServiceAccount
     name: app-sa
     namespace: default
   ```

2. **Create minimal roles**
   ```yaml
   # GOOD - Minimal permissions
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: app-role
     namespace: app-namespace
   rules:
   - apiGroups: [""]
     resources: ["configmaps"]
     resourceNames: ["app-config"]  # Specific resource
     verbs: ["get"]
   ```

3. **Don't mount service account tokens automatically**
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: app-sa
   automountServiceAccountToken: false  # Disable auto-mount
   ```

4. **Use Pod Security Standards**
   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: app-namespace
     labels:
       pod-security.kubernetes.io/enforce: restricted
       pod-security.kubernetes.io/audit: restricted
       pod-security.kubernetes.io/warn: restricted
   ```
""",
        "prevention": """
- Use namespace-scoped Roles instead of ClusterRoles
- Apply least privilege to service accounts
- Disable service account token auto-mounting
- Enable Pod Security Standards/Policies
- Audit RBAC with kubectl auth can-i
- Use tools like rbac-police or kube-bench
""",
        "references": [
            "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
        ],
    },

    # Exposed Services
    "exposed_redis": {
        "title": "Exposed Redis Instance",
        "severity": "critical",
        "cwe_id": "CWE-284",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Redis is accessible without authentication, allowing data theft and potential remote code execution.",
        "impact": """
- Data theft
- Data modification
- Remote code execution via EVAL
- Denial of service
- Use as pivot point
""",
        "fix": """
1. **Enable authentication**

   redis.conf:
   ```
   requirepass your-strong-password-here
   ```

   Or via command:
   ```bash
   redis-cli CONFIG SET requirepass "your-strong-password"
   ```

2. **Bind to localhost only**
   ```
   bind 127.0.0.1
   protected-mode yes
   ```

3. **Disable dangerous commands**
   ```
   rename-command FLUSHALL ""
   rename-command FLUSHDB ""
   rename-command CONFIG ""
   rename-command DEBUG ""
   rename-command SHUTDOWN ""
   rename-command EVAL ""
   ```

4. **Use network-level protection**
   - Place Redis in private subnet
   - Use security groups/firewall rules
   - Use VPC/private networking

5. **Enable TLS**
   ```
   tls-port 6379
   port 0
   tls-cert-file /path/to/cert.pem
   tls-key-file /path/to/key.pem
   tls-ca-cert-file /path/to/ca.pem
   ```
""",
        "prevention": """
- Always require authentication
- Bind to localhost or private IPs only
- Disable dangerous commands
- Use TLS for encryption
- Monitor with Redis ACLs (Redis 6+)
- Regular security scanning
""",
        "references": [
            "https://redis.io/docs/management/security/",
        ],
    },
}
