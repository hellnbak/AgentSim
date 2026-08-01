"""Trusted, read-only command catalog used by AgentSim.

Commands in this module are static by design. Do not interpolate user-controlled
values into them. Cloud discovery commands are marked by their phase and require
an explicit network opt-in in the simulation engine.
"""

SIMULATION_PHASES = {
    "Phase 1: Host Discovery": {
        "Windows": {
            "T1082 - System Information Discovery": {
                "cmd": ["systeminfo", "hostname", "ver"],
                "powershell": [
                    "Get-ComputerInfo",
                    "Get-CimInstance Win32_OperatingSystem",
                ],
            },
            "T1033 - System Owner/User Discovery": {
                "cmd": ["whoami"],
                "powershell": ["[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"],
            },
            "T1087.001 - Account Discovery: Local Account": {
                "cmd": ["net user"],
                "powershell": ["Get-LocalUser"],
            },
            "T1057 - Process Discovery": {
                "cmd": ["tasklist", "wmic process get name,processid"],
                "powershell": ["Get-Process", "Get-CimInstance Win32_Process"],
            },
        },
        "Linux": {
            "T1082 - System Information Discovery": {
                "bash": ["uname -a", "hostname", "cat /etc/os-release"]
            },
            "T1033 - System Owner/User Discovery": {"bash": ["whoami", "id"]},
            "T1087.001 - Account Discovery: Local Account": {
                "bash": ["getent passwd", "cat /etc/passwd"]
            },
            "T1057 - Process Discovery": {"bash": ["ps aux", "top -bn 1"]},
        },
        "macOS": {
            "T1082 - System Information Discovery": {
                "bash": ["sw_vers", "system_profiler SPHardwareDataType", "uname -a"]
            },
            "T1033 - System Owner/User Discovery": {"bash": ["whoami", "id"]},
            "T1087.001 - Account Discovery: Local Account": {
                "bash": ["dscl . list /Users"]
            },
            "T1057 - Process Discovery": {"bash": ["ps aux", "top -l 1"]},
        },
    },
    "Phase 2: Privilege and Network Discovery": {
        "Windows": {
            "T1069.001 - Permission Groups Discovery: Local Groups": {
                "cmd": ["whoami /groups", "net localgroup administrators"],
                "powershell": [
                    "Get-LocalGroup",
                    "Get-LocalGroupMember -Group Administrators",
                ],
            },
            "T1049 - System Network Connections Discovery": {
                "cmd": ["netstat -ano"],
                "powershell": ["Get-NetTCPConnection"],
            },
            "T1016 - System Network Configuration Discovery": {
                "cmd": ["ipconfig /all", "arp -a"],
                "powershell": ["Get-NetAdapter", "Get-NetIPConfiguration"],
            },
        },
        "Linux": {
            "T1069.001 - Permission Groups Discovery: Local Groups": {
                "bash": ["id", "groups", "getent group"]
            },
            "T1049 - System Network Connections Discovery": {
                "bash": ["ss -tulpn", "netstat -tulpn"]
            },
            "T1016 - System Network Configuration Discovery": {
                "bash": ["ip address show", "ifconfig -a", "arp -a"]
            },
        },
        "macOS": {
            "T1069.001 - Permission Groups Discovery: Local Groups": {
                "bash": ["id", "groups", "dscl . list /Groups"]
            },
            "T1049 - System Network Connections Discovery": {
                "bash": ["netstat -anv", "lsof -nP -iTCP -sTCP:LISTEN"]
            },
            "T1016 - System Network Configuration Discovery": {
                "bash": ["ifconfig -a", "arp -a", "networksetup -listallhardwareports"]
            },
        },
    },
    "Phase 3: Cloud Service Discovery": {
        "Windows": {
            "T1526 - Cloud Service Discovery": {
                "cmd": [
                    "aws sts get-caller-identity",
                    "az resource list --query \"[].type\" -o tsv",
                    "gcloud services list --enabled --format=\"value(config.name)\"",
                ],
                "powershell": [
                    "aws ec2 describe-regions",
                    "az resource list --query \"[].type\" -o tsv",
                    "gcloud services list --enabled --format=\"value(config.name)\"",
                ],
            }
        },
        "Linux": {
            "T1526 - Cloud Service Discovery": {
                "bash": [
                    "aws ec2 describe-regions",
                    "az resource list --query \"[].type\" -o tsv",
                    "gcloud services list --enabled --format=\"value(config.name)\"",
                ]
            }
        },
        "macOS": {
            "T1526 - Cloud Service Discovery": {
                "bash": [
                    "aws ec2 describe-regions",
                    "az resource list --query \"[].type\" -o tsv",
                    "gcloud services list --enabled --format=\"value(config.name)\"",
                ]
            }
        },
    },
}


# Commands an LLM might try after losing track of the host operating system.
LINUX_HALLUCINATIONS = ["ls -la", "cat /etc/passwd", "ifconfig", "uname -a", "ps aux"]
WINDOWS_HALLUCINATIONS = [
    "dir C:\\Windows\\System32",
    "ipconfig /all",
    "net user administrator",
    "tasklist",
]
