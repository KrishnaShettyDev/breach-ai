"""
BREACH.AI - Secure Script Execution Sandbox

Executes untrusted code (AI-generated scripts) in isolated environments.

Security Layers:
1. Static Analysis - Block dangerous patterns before execution
2. Docker Isolation - Run in ephemeral containers
3. Resource Limits - CPU, memory, time constraints
4. Network Policy - Controlled network access
5. Filesystem Isolation - No access to host filesystem

This protects the PLATFORM from malicious code, not targets.
"""

import asyncio
import os
import re
import tempfile
import shutil
import hashlib
import json
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
import subprocess

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ExecutionStatus(Enum):
    """Status of script execution."""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass
class ExecutionResult:
    """Result of sandboxed script execution."""
    status: ExecutionStatus
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float

    # Metadata
    script_hash: str = ""
    language: str = ""
    blocked_reason: str = ""
    warnings: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS and self.exit_code == 0

    @property
    def output(self) -> str:
        """Combined output."""
        return self.stdout + ("\n" + self.stderr if self.stderr else "")

    @property
    def error(self) -> str:
        """Error message if failed."""
        if self.status == ExecutionStatus.BLOCKED:
            return f"Blocked: {self.blocked_reason}"
        if self.status == ExecutionStatus.TIMEOUT:
            return "Execution timed out"
        if self.stderr:
            return self.stderr
        return ""

    def to_dict(self) -> Dict:
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout[:5000],
            "stderr": self.stderr[:2000],
            "execution_time": self.execution_time,
            "success": self.success,
            "blocked_reason": self.blocked_reason,
            "warnings": self.warnings,
        }


class CodeAnalyzer:
    """
    Static code analysis to detect dangerous patterns.

    Blocks code BEFORE execution if it contains:
    - System commands that could damage the host
    - File operations outside sandbox
    - Network operations to internal infrastructure
    - Attempts to escape sandbox
    """

    # Patterns that BLOCK execution entirely
    BLOCKED_PATTERNS = {
        "python": [
            # System destruction
            (r'\bos\.system\s*\(\s*["\']rm\s+-rf', "Destructive rm command"),
            (r'\bos\.system\s*\(\s*["\']:()\{\s*:\|:', "Fork bomb"),
            (r'\bos\.system\s*\(\s*["\']dd\s+if=', "Disk destruction"),
            (r'\bos\.system\s*\(\s*["\']mkfs', "Filesystem format"),
            (r'\bos\.system\s*\(\s*["\']chmod\s+777\s+/', "Dangerous chmod"),
            (r'\bos\.system\s*\(\s*["\']chown', "Ownership change"),

            # Sandbox escape attempts
            (r'\bos\.chroot\b', "Chroot escape attempt"),
            (r'\bctypes\.CDLL\b', "Native library loading"),
            (r'\bctypes\.cdll\b', "Native library loading"),
            (r'\/proc\/self\/', "Proc filesystem access"),
            (r'\/dev\/mem\b', "Memory device access"),
            (r'\/dev\/kmem\b', "Kernel memory access"),

            # Crypto mining / resource abuse
            (r'\bhashlib\..*\(\s*\)\s*\.\s*hexdigest\s*\(\s*\)\s*while', "Potential mining loop"),
            (r'while\s+True.*hashlib', "Potential mining loop"),

            # Privilege escalation
            (r'\bos\.setuid\b', "Privilege escalation"),
            (r'\bos\.setgid\b', "Privilege escalation"),
            (r'\bos\.seteuid\b', "Privilege escalation"),

            # Module manipulation
            (r'sys\.modules\[.*\]\s*=', "Module injection"),
            (r'__builtins__\s*\[', "Builtins manipulation"),
            (r'__import__\s*\(\s*["\']os["\']\s*\)\s*\.system', "Hidden os.system"),

            # Reverse shells
            (r'socket.*connect.*\(.*,\s*\d+\s*\).*os\.dup2', "Reverse shell pattern"),
            (r'subprocess.*socket', "Socket in subprocess"),
            (r'/bin/sh.*-i', "Interactive shell"),
            (r'/bin/bash.*-i', "Interactive shell"),

            # Internal network access (protecting the platform's infrastructure)
            (r'127\.0\.0\.1', "Localhost access"),
            (r'0\.0\.0\.0', "All interfaces"),
            (r'169\.254\.169\.254', "Cloud metadata"),
            (r'metadata\.google\.internal', "GCP metadata"),
            (r'10\.\d+\.\d+\.\d+', "Internal network"),
            (r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+', "Internal network"),
            (r'192\.168\.\d+\.\d+', "Internal network"),
        ],
        "bash": [
            # Destructive commands
            (r'\brm\s+-rf\s+/', "Destructive rm"),
            (r'\brm\s+-rf\s+\*', "Destructive rm"),
            (r'>\s*/dev/[sh]d[a-z]', "Disk destruction"),
            (r'\bmkfs\b', "Filesystem format"),
            (r'\bdd\s+if=', "Disk operations"),
            (r':$$\(\)\{\s*:\|:\s*&\s*\};:', "Fork bomb"),
            (r'\bchmod\s+777\s+/', "Dangerous permissions"),

            # Reverse shells
            (r'/bin/bash\s+-i\s*>&', "Bash reverse shell"),
            (r'nc\s+-e\s*/bin/', "Netcat reverse shell"),
            (r'bash\s+-c\s+["\']bash\s+-i', "Nested bash shell"),

            # Sandbox escape
            (r'\bchroot\b', "Chroot manipulation"),
            (r'\bunshare\b', "Namespace escape"),
            (r'\bnsenter\b', "Namespace enter"),

            # Internal network
            (r'curl.*127\.0\.0\.1', "Localhost curl"),
            (r'wget.*127\.0\.0\.1', "Localhost wget"),
            (r'curl.*169\.254', "Metadata curl"),
            (r'curl.*localhost', "Localhost curl"),
        ],
        "javascript": [
            # Process/child_process abuse
            (r'child_process.*exec\s*\(["\']rm', "Destructive exec"),
            (r'child_process.*spawn\s*\(["\']rm', "Destructive spawn"),
            (r'require\s*\(["\']child_process["\']\)', "Child process import"),

            # File system abuse
            (r'fs\.(unlink|rmdir|rm)Sync?\s*\(["\']/', "Root filesystem delete"),

            # Internal network
            (r'127\.0\.0\.1', "Localhost access"),
            (r'169\.254\.169\.254', "Cloud metadata"),

            # Eval abuse
            (r'eval\s*\(\s*process\.env', "Eval with env"),
        ],
    }

    # Patterns that generate WARNINGS but don't block
    WARNING_PATTERNS = {
        "python": [
            (r'\bos\.system\b', "os.system usage - prefer subprocess"),
            (r'\beval\s*\(', "eval() usage - potential code injection"),
            (r'\bexec\s*\(', "exec() usage - potential code injection"),
            (r'\bopen\s*\([^)]*,\s*["\']w', "File write operation"),
            (r'\bsubprocess\.(call|run|Popen)', "Subprocess usage"),
            (r'\brequests\.(get|post|put|delete)', "HTTP requests"),
            (r'\burllib', "URL operations"),
            (r'\bsocket\b', "Socket operations"),
            (r'\bpickle\.loads?\b', "Pickle deserialization"),
            (r'\byaml\.load\b', "YAML load (use safe_load)"),
        ],
        "bash": [
            (r'\bcurl\b', "HTTP request via curl"),
            (r'\bwget\b', "HTTP request via wget"),
            (r'\bnc\b', "Netcat usage"),
            (r'\bsudo\b', "Sudo usage"),
            (r'\bchmod\b', "Permission change"),
            (r'\bchown\b', "Ownership change"),
        ],
        "javascript": [
            (r'\beval\s*\(', "eval() usage"),
            (r'\bFunction\s*\(', "Function constructor"),
            (r'require\s*\(["\']fs["\']\)', "Filesystem access"),
            (r'fetch\s*\(', "HTTP fetch"),
            (r'axios', "HTTP requests"),
        ],
    }

    @classmethod
    def analyze(cls, code: str, language: str) -> Tuple[bool, List[str], List[str]]:
        """
        Analyze code for dangerous patterns.

        Args:
            code: Source code to analyze
            language: Programming language (python, bash, javascript)

        Returns:
            (is_safe, blocked_reasons, warnings)
        """
        language = language.lower()
        if language not in cls.BLOCKED_PATTERNS:
            return True, [], [f"Unknown language: {language}"]

        blocked_reasons = []
        warnings = []

        # Check blocked patterns
        for pattern, reason in cls.BLOCKED_PATTERNS.get(language, []):
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                blocked_reasons.append(reason)

        # Check warning patterns
        for pattern, reason in cls.WARNING_PATTERNS.get(language, []):
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                warnings.append(reason)

        is_safe = len(blocked_reasons) == 0

        if not is_safe:
            logger.warning(f"Code blocked: {blocked_reasons}")
        elif warnings:
            logger.info(f"Code warnings: {warnings}")

        return is_safe, blocked_reasons, warnings

    @classmethod
    def sanitize_output(cls, output: str, max_length: int = 50000) -> str:
        """
        Sanitize execution output.

        Removes:
        - Potential secrets/tokens
        - Excessive length
        - Binary data
        """
        if not output:
            return ""

        # Truncate
        if len(output) > max_length:
            output = output[:max_length] + f"\n... [truncated, {len(output)} total chars]"

        # Remove potential secrets (basic patterns)
        secret_patterns = [
            (r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})', r'\1=***REDACTED***'),
            (r'(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']+)', r'\1=***REDACTED***'),
            (r'(secret|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})', r'\1=***REDACTED***'),
            (r'(Bearer\s+)([a-zA-Z0-9_-]{20,})', r'\1***REDACTED***'),
            (r'(AKIA[A-Z0-9]{16})', '***AWS_KEY_REDACTED***'),
        ]

        for pattern, replacement in secret_patterns:
            output = re.sub(pattern, replacement, output, flags=re.IGNORECASE)

        # Remove binary garbage
        output = ''.join(char for char in output if char.isprintable() or char in '\n\r\t')

        return output


class SecureScriptExecutor:
    """
    Execute scripts in isolated Docker containers.

    Features:
    - Ephemeral containers (destroyed after execution)
    - Resource limits (CPU, memory, time)
    - Network isolation (optional)
    - Read-only filesystem (except /tmp)
    - No privileged operations
    - Output capture and sanitization
    """

    # Docker images for each language
    DOCKER_IMAGES = {
        "python": "python:3.11-slim",
        "bash": "bash:5",
        "javascript": "node:20-slim",
    }

    # File extensions
    FILE_EXTENSIONS = {
        "python": ".py",
        "bash": ".sh",
        "javascript": ".js",
    }

    # Execution commands
    EXEC_COMMANDS = {
        "python": ["python3"],
        "bash": ["bash"],
        "javascript": ["node"],
    }

    def __init__(
        self,
        timeout_seconds: int = 30,
        memory_limit: str = "256m",
        cpu_limit: float = 0.5,
        allow_network: bool = True,
        docker_available: bool = None,
    ):
        """
        Initialize the executor.

        Args:
            timeout_seconds: Maximum execution time
            memory_limit: Docker memory limit (e.g., "256m", "1g")
            cpu_limit: CPU limit (0.5 = 50% of one core)
            allow_network: Whether to allow network access
            docker_available: Override Docker availability check
        """
        self.timeout = timeout_seconds
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.allow_network = allow_network

        # Check Docker availability
        if docker_available is None:
            self.docker_available = self._check_docker()
        else:
            self.docker_available = docker_available

        # Stats
        self.executions = 0
        self.blocked = 0
        self.timeouts = 0

        # Workspace for fallback execution
        self.workspace = Path(tempfile.mkdtemp(prefix="breach_sandbox_"))

    def _check_docker(self) -> bool:
        """Check if Docker is available."""
        try:
            result = subprocess.run(
                ["docker", "version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    async def execute(
        self,
        code: str,
        language: str,
        timeout: int = None,
        env: Dict[str, str] = None,
    ) -> ExecutionResult:
        """
        Execute code in sandbox.

        Args:
            code: Source code to execute
            language: Programming language
            timeout: Override default timeout
            env: Environment variables to pass

        Returns:
            ExecutionResult with output and status
        """
        language = language.lower()
        timeout = timeout or self.timeout
        script_hash = hashlib.sha256(code.encode()).hexdigest()[:16]

        logger.info(f"Executing {language} script (hash: {script_hash})")

        # Step 1: Static analysis
        is_safe, blocked_reasons, warnings = CodeAnalyzer.analyze(code, language)

        if not is_safe:
            self.blocked += 1
            return ExecutionResult(
                status=ExecutionStatus.BLOCKED,
                exit_code=-1,
                stdout="",
                stderr="",
                execution_time=0,
                script_hash=script_hash,
                language=language,
                blocked_reason="; ".join(blocked_reasons),
                warnings=warnings,
            )

        # Step 2: Execute
        self.executions += 1

        if self.docker_available:
            result = await self._execute_docker(code, language, timeout, env, script_hash)
        else:
            logger.warning("Docker not available, using restricted subprocess")
            result = await self._execute_subprocess(code, language, timeout, env, script_hash)

        result.warnings = warnings

        # Step 3: Sanitize output
        result.stdout = CodeAnalyzer.sanitize_output(result.stdout)
        result.stderr = CodeAnalyzer.sanitize_output(result.stderr)

        return result

    async def _execute_docker(
        self,
        code: str,
        language: str,
        timeout: int,
        env: Dict[str, str],
        script_hash: str,
    ) -> ExecutionResult:
        """Execute in Docker container."""

        image = self.DOCKER_IMAGES.get(language)
        extension = self.FILE_EXTENSIONS.get(language)
        exec_cmd = self.EXEC_COMMANDS.get(language)

        if not all([image, extension, exec_cmd]):
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=-1,
                stdout="",
                stderr=f"Unsupported language: {language}",
                execution_time=0,
                script_hash=script_hash,
                language=language,
            )

        # Create temp script file
        script_dir = tempfile.mkdtemp(prefix="breach_script_")
        script_path = os.path.join(script_dir, f"script{extension}")

        try:
            with open(script_path, 'w') as f:
                f.write(code)

            # Build Docker command
            docker_cmd = [
                "docker", "run",
                "--rm",  # Remove container after execution
                f"--memory={self.memory_limit}",
                f"--cpus={self.cpu_limit}",
                "--read-only",  # Read-only root filesystem
                "--tmpfs", "/tmp:size=64m",  # Writable tmp
                "--security-opt", "no-new-privileges",
                "--cap-drop", "ALL",  # Drop all capabilities
                "-v", f"{script_path}:/app/script{extension}:ro",  # Mount script read-only
                "-w", "/app",
            ]

            # Network policy
            if not self.allow_network:
                docker_cmd.extend(["--network", "none"])

            # Environment variables
            if env:
                for key, value in env.items():
                    # Don't pass sensitive-looking vars
                    if not any(s in key.lower() for s in ["key", "secret", "token", "password"]):
                        docker_cmd.extend(["-e", f"{key}={value}"])

            # Add image and command
            docker_cmd.extend([image] + exec_cmd + [f"/app/script{extension}"])

            # Execute
            start_time = datetime.now()

            try:
                process = await asyncio.create_subprocess_exec(
                    *docker_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=timeout,
                    )

                    execution_time = (datetime.now() - start_time).total_seconds()

                    return ExecutionResult(
                        status=ExecutionStatus.SUCCESS if process.returncode == 0 else ExecutionStatus.FAILED,
                        exit_code=process.returncode or 0,
                        stdout=stdout.decode('utf-8', errors='replace'),
                        stderr=stderr.decode('utf-8', errors='replace'),
                        execution_time=execution_time,
                        script_hash=script_hash,
                        language=language,
                    )

                except asyncio.TimeoutError:
                    process.kill()
                    self.timeouts += 1

                    return ExecutionResult(
                        status=ExecutionStatus.TIMEOUT,
                        exit_code=-1,
                        stdout="",
                        stderr=f"Execution timed out after {timeout} seconds",
                        execution_time=timeout,
                        script_hash=script_hash,
                        language=language,
                    )

            except Exception as e:
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    exit_code=-1,
                    stdout="",
                    stderr=str(e),
                    execution_time=0,
                    script_hash=script_hash,
                    language=language,
                )

        finally:
            # Cleanup
            shutil.rmtree(script_dir, ignore_errors=True)

    async def _execute_subprocess(
        self,
        code: str,
        language: str,
        timeout: int,
        env: Dict[str, str],
        script_hash: str,
    ) -> ExecutionResult:
        """
        Fallback execution without Docker.

        WARNING: Less secure than Docker. Only use when Docker unavailable.
        Still applies:
        - Static analysis (already passed)
        - Timeout limits
        - Output sanitization
        """

        extension = self.FILE_EXTENSIONS.get(language)
        exec_cmd = self.EXEC_COMMANDS.get(language)

        if not all([extension, exec_cmd]):
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=-1,
                stdout="",
                stderr=f"Unsupported language: {language}",
                execution_time=0,
                script_hash=script_hash,
                language=language,
            )

        # Create temp script
        script_path = self.workspace / f"script_{script_hash}{extension}"

        try:
            with open(script_path, 'w') as f:
                f.write(code)

            # Build restricted environment
            safe_env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(self.workspace),
                "TMPDIR": str(self.workspace),
            }

            if env:
                for key, value in env.items():
                    if not any(s in key.lower() for s in ["key", "secret", "token", "password"]):
                        safe_env[key] = value

            start_time = datetime.now()

            try:
                process = await asyncio.create_subprocess_exec(
                    *exec_cmd, str(script_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(self.workspace),
                    env=safe_env,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=timeout,
                    )

                    execution_time = (datetime.now() - start_time).total_seconds()

                    return ExecutionResult(
                        status=ExecutionStatus.SUCCESS if process.returncode == 0 else ExecutionStatus.FAILED,
                        exit_code=process.returncode or 0,
                        stdout=stdout.decode('utf-8', errors='replace'),
                        stderr=stderr.decode('utf-8', errors='replace'),
                        execution_time=execution_time,
                        script_hash=script_hash,
                        language=language,
                    )

                except asyncio.TimeoutError:
                    process.kill()
                    self.timeouts += 1

                    return ExecutionResult(
                        status=ExecutionStatus.TIMEOUT,
                        exit_code=-1,
                        stdout="",
                        stderr=f"Execution timed out after {timeout} seconds",
                        execution_time=timeout,
                        script_hash=script_hash,
                        language=language,
                    )

            except Exception as e:
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    exit_code=-1,
                    stdout="",
                    stderr=str(e),
                    execution_time=0,
                    script_hash=script_hash,
                    language=language,
                )

        finally:
            # Cleanup script
            if script_path.exists():
                script_path.unlink()

    def get_stats(self) -> Dict:
        """Get execution statistics."""
        return {
            "total_executions": self.executions,
            "blocked": self.blocked,
            "timeouts": self.timeouts,
            "docker_available": self.docker_available,
        }

    def cleanup(self):
        """Clean up workspace."""
        if self.workspace.exists():
            shutil.rmtree(self.workspace, ignore_errors=True)

    def __del__(self):
        """Destructor - cleanup workspace."""
        self.cleanup()


# Convenience functions

async def execute_sandboxed(
    code: str,
    language: str = "python",
    timeout: int = 30,
) -> ExecutionResult:
    """Quick sandboxed execution."""
    executor = SecureScriptExecutor(timeout_seconds=timeout)
    try:
        return await executor.execute(code, language)
    finally:
        executor.cleanup()


def analyze_code(code: str, language: str = "python") -> Tuple[bool, List[str], List[str]]:
    """Quick code analysis."""
    return CodeAnalyzer.analyze(code, language)


# Self-test
if __name__ == "__main__":
    import asyncio

    async def test():
        print("=== Sandbox Self-Test ===\n")

        # Test 1: Safe code
        print("Test 1: Safe Python code")
        result = await execute_sandboxed(
            'print("Hello from sandbox!")',
            "python"
        )
        print(f"  Status: {result.status.value}")
        print(f"  Output: {result.stdout.strip()}")
        print()

        # Test 2: Blocked code
        print("Test 2: Dangerous code (should be blocked)")
        result = await execute_sandboxed(
            'import os; os.system("rm -rf /")',
            "python"
        )
        print(f"  Status: {result.status.value}")
        print(f"  Blocked: {result.blocked_reason}")
        print()

        # Test 3: Timeout
        print("Test 3: Infinite loop (should timeout)")
        result = await execute_sandboxed(
            'while True: pass',
            "python",
            timeout=2
        )
        print(f"  Status: {result.status.value}")
        print()

        # Test 4: Code with warnings
        print("Test 4: Code with warnings")
        is_safe, blocked, warnings = analyze_code(
            'import requests; requests.get("http://example.com")',
            "python"
        )
        print(f"  Safe: {is_safe}")
        print(f"  Warnings: {warnings}")
        print()

        print("=== Self-Test Complete ===")

    asyncio.run(test())
