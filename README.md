# Security Log Parser — Brute Force Detection

A Python command-line tool that parses Linux `auth.log` files and flags IP addresses with repeated failed login attempts. Built to identify brute force and credential stuffing patterns in SSH authentication logs.

---

## What It Does

- Reads standard Linux `auth.log` format
- Extracts source IPs from failed SSH login attempts
- Counts attempts per IP across the full log
- Flags any IP exceeding a configurable threshold
- Outputs a clean report with IP, attempt count, and first seen timestamp

---

## Setup

No external dependencies. Runs on Python 3.6+.

```bash
git clone https://github.com/YOUR_USERNAME/security-log-parser.git
cd security-log-parser
```

---

## Usage

**Quick start (no arguments needed):**
```bash
python generate_sample_log.py
python log_parser.py
```

**Against a real auth log:**
```bash
python log_parser.py /var/log/auth.log --threshold 5
```

**With custom threshold:**
```bash
python log_parser.py sample_auth.log --threshold 10
```

**Example output:**
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

---

## Arguments

| Argument | Description | Default |
|---|---|---|
| `log_file` | Path to auth.log file | Required |
| `--threshold` | Minimum failed attempts to flag | 5 |

---

## Skills Demonstrated

- Python scripting and CLI tooling
- Log analysis and pattern extraction with regex
- Security operations — brute force and threat detection
- Practical application of SIEM concepts in lightweight tooling

---

## Author

Muhammad Suhaib — [LinkedIn](https://www.linkedin.com/in/muhsuhaib) | [suhaibkhan916@gmail.com](mailto:suhaibkhan916@gmail.com)

MSc Cyber Security (Distinction), UWE | CompTIA Security+
