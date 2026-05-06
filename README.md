# Security Log Parser — SSH Brute-Force Detection

A Python command-line tool that parses Linux `auth.log` files and flags source IPs with repeated failed SSH login attempts. Built as a lightweight, dependency-free implementation of the brute-force detection pattern used by SIEM tooling.

## What It Does

- Parses standard Linux `auth.log` format
- Extracts source IPs from failed SSH login attempts using regex
- Counts attempts per IP across the full log
- Flags IPs exceeding a configurable threshold
- Outputs a clean report with IP, attempt count, and first-seen timestamp

## MITRE ATT&CK Mapping

| Technique | ID | Detected Via |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Failed-logon volume per source IP |
| Valid Accounts | T1078 | First-seen timestamps for unusual sources |

## Setup

No external dependencies. Runs on Python 3.6+.

```bash
git clone https://github.com/suhaibkhan916/security-log-parser.git
cd security-log-parser
```

## Usage

Quick start with synthetic log data:

```bash
python generate_sample_log.py
python log_parser.py
```

Against a real auth log:

```bash
python log_parser.py /var/log/auth.log --threshold 5
```

With custom threshold:

```bash
python log_parser.py sample_auth.log --threshold 10
```

## Example Output

```
[*] Parsing: sample_auth.log
[*] Threshold: 5 failed attempts

==================================================
  FAILED LOGIN REPORT — Threshold: 5+
==================================================
  3 suspicious IP(s) flagged:

  IP: 45.33.32.156
    Failed attempts : 18
    First seen      : Jan 14 02:11:43

  IP: 203.0.113.99
    Failed attempts : 12
    First seen      : Feb  3 17:44:09

  IP: 198.51.100.22
    Failed attempts : 9
    First seen      : Mar  7 23:05:31

==================================================
```

## Arguments

| Argument | Description | Default |
|---|---|---|
| `log_file` | Path to auth.log file | Required |
| `--threshold` | Minimum failed attempts to flag | 5 |

## Detection Logic

The parser looks for lines matching the standard SSH failed-authentication signature:

```
sshd[PID]: Failed password for [user] from [IP] port [PORT] ssh2
```

Source IP is captured via regex, attempt counts are accumulated in a dictionary keyed by IP, and any IP whose count crosses the threshold is reported alongside its first-seen timestamp from the log.

## What This Demonstrates

- Python scripting and CLI tooling with `argparse`
- Log analysis and pattern extraction with regex
- Practical brute-force detection logic, the same pattern SIEM rules implement
- Translation of a SOC detection use case into working code

## Limitations and Honest Notes

- Simple threshold-based detection. Real SIEMs add time-window logic (for example, 5 failed logins in 60 seconds) and session correlation, which this tool does not.
- No de-duplication of legitimate retries (a user who fat-fingers their password three times will be counted).
- Parses only the `Failed password` signature. Other failure modes (invalid user, key-based auth failure) are not currently captured. Open as future work.

---

Author: Muhammad Suhaib — [LinkedIn](https://linkedin.com/in/muhsuhaib) — suhaibkhan916@gmail.com
MSc Cyber Security (Distinction), University of the West of England — CompTIA Security+

Author: Muhammad Suhaib — [LinkedIn](https://linkedin.com/in/muhsuhaib) — suhaibkhan916@gmail.com
MSc Cyber Security (Distinction), University of the West of England — CompTIA Security+
