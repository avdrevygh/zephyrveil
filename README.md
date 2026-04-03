# Zephyrveil

**Linux Threat Detection & Security Intelligence**

A powerful CLI security console for Linux — inspired by Metasploit's interface. Parses system logs, detects intrusion attempts, enriches attacker IPs with threat intelligence, audits system security, generates reports, and sends Telegram alerts.

```
███████╗███████╗██████╗ ██╗  ██╗██╗   ██╗██████╗ ██╗   ██╗███████╗██╗██╗     
╚══███╔╝██╔════╝██╔══██╗██║  ██║╚██╗ ██╔╝██╔══██╗██║   ██║██╔════╝██║██║     
  ███╔╝ █████╗  ██████╔╝███████║ ╚████╔╝ ██████╔╝██║   ██║█████╗  ██║██║     
 ███╔╝  ██╔══╝  ██╔═══╝ ██╔══██║  ╚██╔╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██║██║     
███████╗███████╗██║     ██║  ██║   ██║   ██║  ██║ ╚████╔╝ ███████╗██║███████╗
╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝╚══════╝
            Linux Threat Detection & Security Intelligence  v1.0.0
```

---

## Features

- **Log Parsing** — journalctl and /var/log/auth.log with custom file support
- **5 Threat Types** — SSH brute force, credential stuffing, root login, sudo abuse, repeated auth failures
- **Threat Intelligence** — IPInfo, AbuseIPDB, VirusTotal, Shodan, Fail2ban
- **System Audit** — security tools, open ports, firewall, SSH config, LUKS, sudo
- **CVE Check** — checks installed packages against NVD/NIST database
- **Reports** — PDF + JSON with full timestamp, never overwrites
- **Telegram Alerts** — auto-sends when threats are detected
- **Full History** — everything stored in SQLite, full history never deleted
- **Metasploit-style console** — use/run/back/show options pattern

---

## Install

```bash
# Recommended — install via uv
uv tool install zephyrveil

# Or via pip
pip install zephyrveil

# Or run from source
git clone https://github.com/avdrevygh/zephyrveil
cd zephyrveil
uv sync
uv run python -m zephyrveil
```

After install, just type:
```bash
zephyrveil
```

---

## First Run

On first run, Zephyrveil automatically creates:

- `~/.config/zephyrveil/config.toml` — configuration file
- `~/.local/share/zephyrveil/zephyrveil.db` — SQLite database
- `~/Documents/zephyrveil/` — reports output directory

No manual setup needed.

---

## Usage

```
zephyrveil > help            # Show all commands
zephyrveil > show options    # List all modules
zephyrveil > use scan        # Run full scan (recommended)
zephyrveil > use log         # Parse logs + enrich IPs
zephyrveil > use ip          # Investigate single IP
zephyrveil > use health      # System security audit
zephyrveil > use report      # Generate report from last scan
zephyrveil > use doctor      # Self-diagnostic
zephyrveil > use alerts      # Configure Telegram
zephyrveil > clear           # Clear screen
zephyrveil > exit            # Quit
```

### Inside a module

```
zephyrveil > use scan
scan > show options          # See current settings
scan > set SOURCE auto       # Set log source
scan > set VERBOSE true      # Enable verbose output
scan > run                   # Execute the scan
scan > back                  # Return to main console
```

### Custom log file

```
scan > set SOURCE /home/user/honeypot.log
scan > run
```

---

## CLI Flags (non-interactive)

```bash
zephyrveil --scan            # Run full scan and exit
zephyrveil --health          # Run health audit and exit
zephyrveil --ip 1.2.3.4      # Investigate IP and exit
zephyrveil --version         # Show version
zephyrveil --verbose         # Enable verbose output
zephyrveil --source /path    # Use custom log file
```

---

## API Keys

Add keys to `~/.config/zephyrveil/config.toml`:

```toml
[api_keys]
abuseipdb  = "your_key_here"   # abuseipdb.com/api — 1000/day free
ipinfo     = "your_key_here"   # ipinfo.io/signup — 50k/month free
virustotal = "your_key_here"   # virustotal.com/gui/my-apikey — 500/day free
shodan     = "your_key_here"   # account.shodan.io — limited free
nvd        = "your_key_here"   # nvd.nist.gov/developers — free
```

Missing keys are skipped with a warning — Zephyrveil never crashes.

Run `use doctor` to see which keys are missing and where to get them.

---

## Telegram Alerts

```toml
[telegram]
bot_token = "your_bot_token"
chat_id   = "your_chat_id"
enabled   = true
```

Or configure via the console:
```
zephyrveil > use alerts
alerts > set TOKEN your_bot_token
alerts > set CHAT_ID your_chat_id
alerts > set TEST true
alerts > run
```

---

## Threat Detection Rules

| Threat | Trigger |
|--------|---------|
| SSH Brute Force | 5+ failed logins from same IP |
| Credential Stuffing | 3+ different usernames from same IP |
| Root Login Attempt | any root SSH login attempt |
| Sudo Abuse | failed sudo or auth failure |
| Repeated Auth Failure | 10+ failures for same username |

---

## Reports

Every scan generates:
- `zephyrveil_report_2025-01-15_14-32-05.pdf`
- `zephyrveil_report_2025-01-15_14-32-05.json`

Saved to `~/Documents/zephyrveil/` — never overwrites old reports.

---

## Database

All data stored at `~/.local/share/zephyrveil/zephyrveil.db`:

- `scans` — scan sessions
- `threats` — detected threats
- `events` — raw log events
- `ip_intel` — IP intelligence results
- `audit_results` — system audit data
- `alerts_sent` — Telegram alert history

Full history, never deleted.

---

## Development

```bash
git clone https://github.com/avdrevygh/zephyrveil
cd zephyrveil
uv sync
uv add --dev python-dotenv

# Create .env for API keys during development
cp .env.example .env
# Edit .env with your keys

uv run python -m zephyrveil
```

---

## Requirements

- Linux (any modern distro)
- Python 3.11+
- journalctl OR /var/log/auth.log access
- Internet connection (for API features)

---

## License

MIT License — see LICENSE file.

---

*Zephyrveil v1.0.0 — Built for security professionals and learners alike.*
