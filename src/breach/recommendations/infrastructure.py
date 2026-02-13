"""
BREACH.AI - Infrastructure Security Vulnerability Recommendations

Fix recommendations for:
- Linux Privilege Escalation
- Container Escape
- Network Security
- Service Hardening
- Secrets Management
"""

INFRASTRUCTURE_RECOMMENDATIONS = {
    # SUID Binary Abuse
    "suid_binary": {
        "title": "SUID Binary Privilege Escalation",
        "severity": "critical",
        "cwe_id": "CWE-269",
        "owasp": "A01:2021-Broken Access Control",
        "description": "SUID binaries with shell escape capabilities (vim, find, python, etc.) can be abused to escalate privileges to root.",
        "impact": """
- Root privilege escalation
- Full system compromise
- Data theft
- Persistent access
""",
        "fix": """
1. **Remove unnecessary SUID bits**

   ```bash
   # Find all SUID binaries
   find / -perm -4000 -type f 2>/dev/null

   # Remove SUID from unnecessary binaries
   chmod u-s /usr/bin/dangerous-binary
   ```

2. **Known dangerous SUID binaries to remove/audit**
   ```bash
   # These should NOT have SUID set:
   vim, vi, nano, less, more
   find, awk, sed, perl, python, ruby, php
   bash, sh, zsh, tcsh
   nmap, nc, netcat
   tar, zip, gzip
   git, ssh, scp
   ```

3. **Use capabilities instead of SUID**
   ```bash
   # Instead of SUID root
   chmod u-s /usr/bin/myapp

   # Grant specific capability
   setcap cap_net_bind_service=+ep /usr/bin/myapp
   ```

4. **Implement AppArmor/SELinux profiles**
   ```bash
   # AppArmor profile example
   /usr/bin/myapp {
     capability net_bind_service,
     /etc/myapp/** r,
     deny /etc/shadow r,
     deny /etc/passwd w,
   }
   ```
""",
        "prevention": """
- Regular SUID binary audits
- Remove SUID from interpreters and text editors
- Use Linux capabilities instead of SUID
- Implement mandatory access control (AppArmor/SELinux)
- Monitor SUID changes with auditd
- Use chroot/containers to limit SUID scope
""",
        "references": [
            "https://gtfobins.github.io/",
        ],
    },

    # Sudo Misconfiguration
    "sudo_misconfiguration": {
        "title": "Sudo Misconfiguration",
        "severity": "critical",
        "cwe_id": "CWE-269",
        "owasp": "A01:2021-Broken Access Control",
        "description": "Sudo rules allow execution of commands that can be abused for privilege escalation (NOPASSWD, wildcards, shell escapes).",
        "impact": """
- Root privilege escalation
- Command execution as root
- Full system compromise
""",
        "fix": """
1. **Avoid dangerous sudoers configurations**

   ```bash
   # DANGEROUS - Avoid these patterns:
   user ALL=(ALL) NOPASSWD: ALL
   user ALL=(ALL) NOPASSWD: /usr/bin/vim *
   user ALL=(ALL) NOPASSWD: /bin/bash
   user ALL=(root) /bin/cat /var/log/*  # Wildcard abuse

   # SECURE - Specific, no wildcards:
   user ALL=(root) NOPASSWD: /usr/bin/systemctl restart myapp.service
   user ALL=(root) /usr/bin/cat /var/log/myapp.log
   ```

2. **Audit current sudo configuration**
   ```bash
   # Check sudo rules for user
   sudo -l

   # Audit sudoers file
   visudo -c
   grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/
   ```

3. **Use sudoers.d for organized configs**
   ```bash
   # /etc/sudoers.d/myapp
   %myapp-admins ALL=(root) /usr/bin/systemctl restart myapp
   %myapp-admins ALL=(root) /usr/bin/journalctl -u myapp
   ```

4. **Prevent shell escapes**
   ```bash
   # Use NOEXEC for editors that must have sudo
   Defaults!/usr/bin/vim noexec

   # Or use restricted editors
   Defaults    editor=/usr/bin/rvim
   ```
""",
        "prevention": """
- Minimize NOPASSWD usage
- Avoid wildcards in command specifications
- Use full paths in sudoers
- Don't allow sudo to interpreters or editors
- Regular sudoers audits
- Use sudo logging (log_input, log_output)
""",
        "references": [
            "https://www.sudo.ws/docs/man/sudoers.man/",
        ],
    },

    # Container Escape via Privileged Mode
    "container_privileged": {
        "title": "Privileged Container Escape",
        "severity": "critical",
        "cwe_id": "CWE-250",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Container running in privileged mode can access host devices and escape to the host system.",
        "impact": """
- Container escape
- Host system compromise
- Access to all containers
- Full infrastructure takeover
""",
        "fix": """
1. **Remove privileged flag**

   ```yaml
   # DANGEROUS
   docker run --privileged myimage

   # SECURE - Grant only needed capabilities
   docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myimage
   ```

2. **Use security contexts in Kubernetes**
   ```yaml
   apiVersion: v1
   kind: Pod
   spec:
     securityContext:
       runAsNonRoot: true
       runAsUser: 1000
     containers:
     - name: app
       securityContext:
         privileged: false
         allowPrivilegeEscalation: false
         capabilities:
           drop:
             - ALL
           add:
             - NET_BIND_SERVICE
         readOnlyRootFilesystem: true
   ```

3. **Use Pod Security Standards**
   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: secure-namespace
     labels:
       pod-security.kubernetes.io/enforce: restricted
   ```

4. **Use gVisor or Kata Containers for isolation**
   ```yaml
   # Use gVisor runtime
   apiVersion: node.k8s.io/v1
   kind: RuntimeClass
   metadata:
     name: gvisor
   handler: runsc

   # Pod using gVisor
   apiVersion: v1
   kind: Pod
   spec:
     runtimeClassName: gvisor
   ```
""",
        "prevention": """
- Never use --privileged in production
- Drop all capabilities, add only needed ones
- Use read-only root filesystem
- Run as non-root user
- Enable Pod Security Standards
- Use container runtime sandboxing (gVisor, Kata)
- Regular container security scanning
""",
        "references": [
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ],
    },

    # Secrets in Environment Variables
    "secrets_env_vars": {
        "title": "Secrets Exposed in Environment Variables",
        "severity": "high",
        "cwe_id": "CWE-526",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "Sensitive secrets are stored in environment variables which can be exposed through /proc, debugging tools, or error messages.",
        "impact": """
- Credential theft
- API key exposure
- Database compromise
- Service impersonation
""",
        "fix": """
1. **Use secrets management solutions**

   AWS Secrets Manager:
   ```python
   import boto3

   def get_secret(secret_name):
       client = boto3.client('secretsmanager')
       response = client.get_secret_value(SecretId=secret_name)
       return response['SecretString']

   DB_PASSWORD = get_secret('prod/db/password')
   ```

   HashiCorp Vault:
   ```python
   import hvac

   client = hvac.Client(url='https://vault.example.com')
   client.token = os.environ['VAULT_TOKEN']  # Only token in env

   secret = client.secrets.kv.read_secret_version(path='database/prod')
   DB_PASSWORD = secret['data']['data']['password']
   ```

2. **Use Kubernetes Secrets (mounted as files)**
   ```yaml
   apiVersion: v1
   kind: Pod
   spec:
     containers:
     - name: app
       volumeMounts:
       - name: secrets
         mountPath: /etc/secrets
         readOnly: true
     volumes:
     - name: secrets
       secret:
         secretName: app-secrets
   ```

   ```python
   # Read from file, not environment
   with open('/etc/secrets/db-password') as f:
       DB_PASSWORD = f.read().strip()
   ```

3. **Use sealed secrets for GitOps**
   ```bash
   # Encrypt secrets for git storage
   kubeseal --format yaml < secret.yaml > sealed-secret.yaml
   ```
""",
        "prevention": """
- Use dedicated secrets management (Vault, AWS Secrets Manager)
- Mount secrets as files, not environment variables
- Use short-lived credentials where possible
- Rotate secrets regularly
- Encrypt secrets at rest
- Audit secret access
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
    },

    # Writable Root Filesystem
    "writable_rootfs": {
        "title": "Writable Container Root Filesystem",
        "severity": "medium",
        "cwe_id": "CWE-732",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Container has a writable root filesystem, allowing attackers to modify binaries, plant backdoors, or tamper with configurations.",
        "impact": """
- Binary tampering
- Backdoor installation
- Configuration manipulation
- Log tampering
""",
        "fix": """
1. **Use read-only root filesystem**

   Docker:
   ```bash
   docker run --read-only myimage
   ```

   Docker Compose:
   ```yaml
   services:
     app:
       image: myimage
       read_only: true
       tmpfs:
         - /tmp
         - /var/run
   ```

   Kubernetes:
   ```yaml
   apiVersion: v1
   kind: Pod
   spec:
     containers:
     - name: app
       securityContext:
         readOnlyRootFilesystem: true
       volumeMounts:
       - name: tmp
         mountPath: /tmp
       - name: var-run
         mountPath: /var/run
     volumes:
     - name: tmp
       emptyDir: {}
     - name: var-run
       emptyDir: {}
   ```

2. **Use tmpfs for writable directories**
   ```yaml
   # Only /tmp and /var/run are writable
   volumes:
     - name: tmp
       emptyDir:
         medium: Memory
         sizeLimit: 100Mi
   ```

3. **Use immutable container images**
   ```dockerfile
   # Multi-stage build for minimal image
   FROM golang:1.20 AS builder
   WORKDIR /app
   COPY . .
   RUN CGO_ENABLED=0 go build -o /myapp

   FROM scratch
   COPY --from=builder /myapp /myapp
   USER 65534
   ENTRYPOINT ["/myapp"]
   ```
""",
        "prevention": """
- Use read-only root filesystem by default
- Use tmpfs for required writable directories
- Use minimal base images (distroless, scratch)
- Sign and verify container images
- Use immutable infrastructure patterns
- Regular container image scanning
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
        ],
    },

    # Kernel Exploit Vectors
    "kernel_exploit": {
        "title": "Kernel Vulnerability Exploitation",
        "severity": "critical",
        "cwe_id": "CWE-269",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "description": "System is running a kernel version with known privilege escalation vulnerabilities (DirtyPipe, DirtyCow, etc.).",
        "impact": """
- Kernel-level privilege escalation
- Container escape
- Full system compromise
- Persistent root access
""",
        "fix": """
1. **Update kernel to patched version**

   ```bash
   # Check current kernel
   uname -r

   # Update kernel (Debian/Ubuntu)
   apt update && apt upgrade linux-image-$(uname -r)
   reboot

   # Update kernel (RHEL/CentOS)
   yum update kernel
   reboot
   ```

2. **Known vulnerable kernels (examples)**
   ```
   DirtyPipe (CVE-2022-0847): Linux 5.8 - 5.16.11, 5.15.25, 5.10.102
   DirtyCow (CVE-2016-5195): Linux 2.6.22 - 4.8.3
   OverlayFS (CVE-2021-3493): Ubuntu kernels before patches
   ```

3. **Use live patching if immediate reboot not possible**
   ```bash
   # Ubuntu Livepatch
   canonical-livepatch enable $TOKEN

   # RHEL kpatch
   kpatch install kpatch-patch-$(uname -r)
   ```

4. **Enable kernel hardening options**
   ```bash
   # /etc/sysctl.conf
   kernel.dmesg_restrict = 1
   kernel.kptr_restrict = 2
   kernel.perf_event_paranoid = 3
   kernel.unprivileged_bpf_disabled = 1
   kernel.unprivileged_userns_clone = 0
   ```
""",
        "prevention": """
- Keep kernel updated with security patches
- Use long-term support (LTS) kernels
- Enable automatic security updates
- Use live patching for critical systems
- Monitor CVE databases for kernel vulnerabilities
- Enable kernel hardening (sysctl parameters)
- Use gVisor/Kata for untrusted workloads
""",
        "references": [
            "https://www.kernel.org/category/releases.html",
        ],
    },

    # Hardcoded Credentials
    "hardcoded_credentials": {
        "title": "Hardcoded Credentials in Source Code",
        "severity": "critical",
        "cwe_id": "CWE-798",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "description": "Credentials (passwords, API keys, tokens) are hardcoded in source code, configuration files, or scripts.",
        "impact": """
- Credential exposure to anyone with code access
- Cannot rotate credentials without code changes
- Credentials in version control history forever
- Easy target for automated scanners
""",
        "fix": """
1. **Remove credentials from code**

   ```python
   # VULNERABLE
   DB_PASSWORD = "SuperSecret123!"
   API_KEY = "sk_live_abc123xyz"

   # SECURE - Environment variables
   import os
   DB_PASSWORD = os.environ['DB_PASSWORD']
   API_KEY = os.environ['API_KEY']
   ```

2. **Use secrets management**
   ```python
   # AWS Secrets Manager
   import boto3

   def get_db_password():
       client = boto3.client('secretsmanager')
       response = client.get_secret_value(SecretId='prod/database')
       return json.loads(response['SecretString'])['password']
   ```

3. **Remove from git history**
   ```bash
   # Use BFG Repo-Cleaner
   bfg --replace-text passwords.txt repo.git

   # Or git-filter-repo
   git filter-repo --invert-paths --path config/secrets.py
   ```

4. **Use pre-commit hooks to prevent**
   ```yaml
   # .pre-commit-config.yaml
   repos:
     - repo: https://github.com/Yelp/detect-secrets
       rev: v1.4.0
       hooks:
         - id: detect-secrets
           args: ['--baseline', '.secrets.baseline']
   ```

5. **Enable secrets scanning in CI/CD**
   ```yaml
   # GitHub Actions
   - name: Scan for secrets
     uses: trufflesecurity/trufflehog@main

   # GitLab CI
   include:
     - template: Security/Secret-Detection.gitlab-ci.yml
   ```
""",
        "prevention": """
- Never commit credentials to version control
- Use environment variables or secrets management
- Use pre-commit hooks for secrets detection
- Scan repositories for secrets regularly
- Rotate any exposed credentials immediately
- Review code for credentials before merging
- Use .gitignore for config files
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
    },

    # Insecure Network Configuration
    "insecure_network": {
        "title": "Insecure Network Configuration",
        "severity": "high",
        "cwe_id": "CWE-284",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Network configuration allows unnecessary exposure, such as binding services to 0.0.0.0, missing firewall rules, or insecure protocols.",
        "impact": """
- Unauthorized service access
- Man-in-the-middle attacks
- Data interception
- Lateral movement
""",
        "fix": """
1. **Bind services to specific interfaces**

   ```python
   # VULNERABLE - Listens on all interfaces
   app.run(host='0.0.0.0', port=8080)

   # SECURE - Localhost only (use reverse proxy for external)
   app.run(host='127.0.0.1', port=8080)
   ```

2. **Configure firewall rules**
   ```bash
   # iptables - Allow only necessary ports
   iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
   iptables -A INPUT -p tcp --dport 443 -j ACCEPT
   iptables -A INPUT -p tcp --dport 80 -j ACCEPT
   iptables -A INPUT -j DROP

   # UFW (Ubuntu)
   ufw default deny incoming
   ufw allow from 10.0.0.0/8 to any port 22
   ufw allow 443/tcp
   ufw enable
   ```

3. **Use TLS for all network communication**
   ```python
   # Use TLS
   app.run(ssl_context=('cert.pem', 'key.pem'))

   # Or behind nginx
   server {
       listen 443 ssl;
       ssl_certificate /etc/ssl/cert.pem;
       ssl_certificate_key /etc/ssl/key.pem;
       ssl_protocols TLSv1.2 TLSv1.3;
   }
   ```

4. **Use network segmentation**
   - Place databases in private subnets
   - Use security groups/firewall rules
   - Implement zero-trust networking
""",
        "prevention": """
- Bind services to localhost, use reverse proxy
- Implement defense in depth with firewalls
- Use TLS for all network traffic
- Segment networks by function
- Regular network security scans
- Monitor for unauthorized connections
""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        ],
    },
}
