import random

LEGITIMATE_IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.2"]
SUSPICIOUS_IPS = ["45.33.32.156", "198.51.100.22", "203.0.113.99"]
MONTHS = ["Jan", "Feb", "Mar"]

lines = []

for ip in SUSPICIOUS_IPS:
    attempts = random.randint(8, 20)
    for i in range(attempts):
        day = random.randint(1, 28)
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        month = random.choice(MONTHS)
        lines.append(
            f"{month} {day:2d} {hour:02d}:{minute:02d}:{second:02d} "
            f"server sshd[1234]: Failed password for root from {ip} port 22 ssh2"
        )

for ip in LEGITIMATE_IPS:
    day = random.randint(1, 28)
    lines.append(
        f"Jan {day:2d} 09:00:00 server sshd[1234]: "
        f"Accepted password for user from {ip} port 22 ssh2"
    )

random.shuffle(lines)

with open("sample_auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print("[+] sample_auth.log created. Run the parser against it:")
print("    python log_parser.py sample_auth.log --threshold 5")
