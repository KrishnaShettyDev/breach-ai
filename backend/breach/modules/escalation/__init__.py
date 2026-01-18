"""
BREACH.AI v2 - Privilege Escalation Modules

5 MVP Escalation Modules:
1. linux_escalator - Linux privilege escalation
2. container_escaper - Container escape techniques
3. aws_escalator - AWS IAM privilege escalation
4. azure_escalator - Azure privilege escalation
5. gcp_escalator - GCP privilege escalation
"""

from backend.breach.modules.escalation.linux_escalator import LinuxEscalator
from backend.breach.modules.escalation.container_escaper import ContainerEscaper
from backend.breach.modules.escalation.aws_escalator import AWSEscalator
from backend.breach.modules.escalation.azure_escalator import AzureEscalator
from backend.breach.modules.escalation.gcp_escalator import GCPEscalator

__all__ = [
    "LinuxEscalator",
    "ContainerEscaper",
    "AWSEscalator",
    "AzureEscalator",
    "GCPEscalator",
]
