<div align="center">

# 🪓 LogReaper v1.0

### High-Speed Log Analysis & Forensics Tool

<p>
  <img src="https://img.shields.io/badge/version-1.0.0-00ff00?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/patterns-500%2B-ff0000?style=for-the-badge" alt="Patterns">
  <img src="https://img.shields.io/badge/parsers-25-blue?style=for-the-badge" alt="Parsers">
  <img src="https://img.shields.io/badge/license-MIT-purple?style=for-the-badge" alt="License">
</p>

<p>
  <a href="https://github.com/bad-antics/nullsec-logreaper"><img src="https://img.shields.io/github/stars/bad-antics/nullsec-logreaper?style=social" alt="Stars"></a>
  <a href="https://github.com/bad-antics"><img src="https://img.shields.io/badge/NullSec-Toolkit-000000?style=flat-square&logo=github" alt="NullSec"></a>
</p>

*Blazing-fast log analysis for incident response, threat hunting, and forensic investigations*

</div>

---

## 💻 Tech Stack

### Core
![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![POSIX](https://img.shields.io/badge/POSIX-000000?style=for-the-badge&logo=gnu&logoColor=white)

### Log Sources
![Syslog](https://img.shields.io/badge/Syslog-000000?style=for-the-badge&logo=linux&logoColor=white)
![Journald](https://img.shields.io/badge/Journald-0078D6?style=for-the-badge&logo=systemd&logoColor=white)
![Apache](https://img.shields.io/badge/Apache-D22128?style=for-the-badge&logo=apache&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white)
![AWS](https://img.shields.io/badge/CloudTrail-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)

### Output Formats
![JSON](https://img.shields.io/badge/JSON-000000?style=for-the-badge&logo=json&logoColor=white)
![CSV](https://img.shields.io/badge/CSV-217346?style=for-the-badge&logo=microsoftexcel&logoColor=white)
![SIEM](https://img.shields.io/badge/SIEM-FF6600?style=for-the-badge&logo=elastic&logoColor=white)

---

## 🎯 Features

<table>
<tr>
<td width="50%" valign="top">

### 🔬 Analysis Modules (8)

| Module | Flag | Description |
|--------|:----:|-------------|
| **Auth Analysis** | `-a` | SSH brute force, sudo abuse |
| **Web Forensics** | `-w` | SQLi, XSS, path traversal |
| **Network Events** | `-n` | Firewall, connection anomalies |
| **System Events** | `-s` | User changes, service starts |
| **Timeline** | `-t` | Event correlation timeline |
| **IOC Extract** | `-i` | IPs, hashes, domains |
| **Baseline Diff** | `-b` | Compare against known-good |
| **Live Stream** | `-l` | Real-time log monitoring |

</td>
<td width="50%" valign="top">

### 📋 Supported Logs (25+)

| Category | Sources |
|----------|---------|
| **System** | syslog, auth.log, secure, messages |
| **Journald** | systemd journal binary logs |
| **Web** | Apache, Nginx, IIS, HAProxy |
| **Apps** | PostgreSQL, MySQL, Redis, MongoDB |
| **Cloud** | AWS CloudTrail, Azure Activity |
| **Auth** | PAM, SSSD, Kerberos, LDAP |
| **Firewall** | iptables, nftables, firewalld |
| **Container** | Docker, Kubernetes audit |

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/bad-antics/nullsec-logreaper
cd nullsec-logreaper
make

# Install system-wide (optional)
sudo make install
```

### Basic Usage

```bash
# Analyze auth logs for brute force
./logreaper -a /var/log/auth.log

# Hunt for web attacks
./logreaper -w /var/log/nginx/access.log

# Full system analysis with timeline
./logreaper -t /var/log/

# Real-time monitoring
./logreaper -l /var/log/syslog

# Extract IOCs to JSON
./logreaper -i /var/log/ -o iocs.json
```

---

## 📊 Detection Patterns

### Authentication Threats
| Pattern | Description | Severity |
|---------|-------------|:--------:|
| `AUTH_BRUTE_SSH` | SSH brute force attempts | 🔴 High |
| `AUTH_SUDO_ABUSE` | Unusual sudo usage | 🟡 Medium |
| `AUTH_SU_ROOT` | Privilege escalation via su | 🔴 High |
| `AUTH_FAIL_BURST` | Rapid auth failures | 🔴 High |
| `AUTH_NEW_USER` | New user created | 🟡 Medium |
| `AUTH_PASSWD_CHG` | Password changed | 🟡 Medium |

### Web Attack Signatures
| Pattern | Description | Severity |
|---------|-------------|:--------:|
| `WEB_SQLI` | SQL injection attempts | 🔴 Critical |
| `WEB_XSS` | Cross-site scripting | 🔴 High |
| `WEB_LFI` | Local file inclusion | 🔴 Critical |
| `WEB_RFI` | Remote file inclusion | 🔴 Critical |
| `WEB_PATH_TRAV` | Path traversal (../) | 🔴 High |
| `WEB_CMD_INJ` | Command injection | 🔴 Critical |
| `WEB_SCANNER` | Automated scanner detected | 🟡 Medium |

### System Anomalies
| Pattern | Description | Severity |
|---------|-------------|:--------:|
| `SYS_KERNEL_MOD` | Kernel module loaded | 🟡 Medium |
| `SYS_SELINUX_OFF` | SELinux disabled | 🔴 High |
| `SYS_CRON_CHANGE` | Cron job modified | 🟡 Medium |
| `SYS_SERVICE_NEW` | New systemd service | 🟡 Medium |
| `SYS_MOUNT_EXEC` | Exec mount option | 🟡 Medium |

---

## 📈 Output Formats

### JSON Report
```json
{
  "scan_id": "lr-20250127-143022",
  "total_events": 15847,
  "threats_found": 23,
  "timeline": [...],
  "iocs": {
    "ips": ["192.168.1.100", "10.0.0.5"],
    "domains": ["evil.example.com"],
    "hashes": []
  },
  "findings": [...]
}
```

### Terminal Output
```
╔══════════════════════════════════════════════════════════════╗
║                    🪓 LogReaper v1.0                         ║
╠══════════════════════════════════════════════════════════════╣
║  Target: /var/log/auth.log                                   ║
║  Lines:  15,847                                              ║
║  Period: 2025-01-20 → 2025-01-27                            ║
╠══════════════════════════════════════════════════════════════╣
║  🔴 CRITICAL  │ 3                                            ║
║  🟠 HIGH      │ 12                                           ║
║  🟡 MEDIUM    │ 8                                            ║
║  🟢 LOW       │ 0                                            ║
╚══════════════════════════════════════════════════════════════╝

[!] AUTH_BRUTE_SSH detected
    Time:   2025-01-26 14:32:15
    Source: 192.168.1.100
    Count:  847 attempts in 5 minutes
    User:   root, admin, ubuntu
```

---

## 🔧 Advanced Usage

### Timeline Correlation
```bash
# Build attack timeline from multiple sources
./logreaper -t \
    /var/log/auth.log \
    /var/log/nginx/access.log \
    /var/log/syslog \
    -o timeline.json
```

### IOC Extraction for SIEM
```bash
# Extract IOCs in Splunk-compatible format
./logreaper -i /var/log/ --format splunk > iocs.txt

# Extract for ELK Stack
./logreaper -i /var/log/ --format elastic | curl -X POST ...
```

### Integration with RKHunt
```bash
# Run LogReaper → pipe suspicious IPs to firewall
./logreaper -a /var/log/auth.log --extract-ips | \
    xargs -I {} iptables -A INPUT -s {} -j DROP

# Correlate with RKHunt findings
./logreaper -s /var/log/syslog | grep -f <(rkhunt --list-iocs)
```

---

## 🛠️ Build Options

```bash
# Standard build
make

# Build with debug symbols
make DEBUG=1

# Build with PCRE2 regex (faster patterns)
make PCRE2=1

# Build static binary
make STATIC=1

# Cross-compile for ARM64
make ARCH=aarch64
```

---

## 📁 Project Structure

```
nullsec-logreaper/
├── src/
│   ├── main.c           # Entry point, arg parsing
│   ├── parser.c         # Log format parsers
│   ├── analyzer.c       # Pattern matching engine
│   ├── timeline.c       # Event correlation
│   ├── output.c         # Report generation
│   ├── patterns.h       # Detection signatures
│   └── utils.c          # Helper functions
├── patterns/
│   ├── auth.rules       # Authentication patterns
│   ├── web.rules        # Web attack signatures
│   └── system.rules     # System anomaly patterns
├── Makefile
├── LICENSE
└── README.md
```

---

## 🔗 NullSec Toolkit Integration

LogReaper works seamlessly with other NullSec tools:

| Tool | Integration |
|------|-------------|
| **RKHunt** | Correlate rootkit indicators with log anomalies |
| **Specter** | Feed extracted IOCs for threat intelligence |
| **NetSniff** | Combine network + log analysis |
| **MemScan** | Timeline memory artifacts with system logs |

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">

**Part of the [NullSec Toolkit](https://github.com/bad-antics)**

*"From logs to leads."*

</div>
