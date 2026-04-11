import re
import argparse
from collections import Counter
from datetime import datetime


def parse_failed_logins(log_file_path, threshold=5):
    """
    Parses a Linux auth.log file and flags IPs with repeated
    failed login attempts — useful for identifying brute force patterns.
    """
    failed_attempts = Counter()
    timestamps = {}
    pattern = re.compile(
        r'(\w+\s+\d+\s[\d:]+).*Failed password.*from (\d+\.\d+\.\d+\.\d+)'
    )

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    timestamp, ip = match.group(1), match.group(2)
                    failed_attempts[ip] += 1
                    if ip not in timestamps:
                        timestamps[ip] = timestamp
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_file_path}")
        return {}

    flagged = {
        ip: {"count": count, "first_seen": timestamps.get(ip, "unknown")}
        for ip, count in failed_attempts.items()
        if count >= threshold
    }

    return flagged


def print_report(flagged, threshold):
    print("\n" + "=" * 50)
    print(f"  FAILED LOGIN REPORT — Threshold: {threshold}+")
    print("=" * 50)

    if not flagged:
        print("  No suspicious IPs detected.\n")
        return

    print(f"  {len(flagged)} suspicious IP(s) flagged:\n")
    for ip, data in sorted(flagged.items(), key=lambda x: -x[1]["count"]):
        print(f"  IP: {ip}")
        print(f"    Failed attempts : {data['count']}")
        print(f"    First seen      : {data['first_seen']}")
        print()

    print("=" * 50 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Detect brute force patterns in Linux auth logs."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        default="sample_auth.log",
        help="Path to the auth log file (default: sample_auth.log)"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Minimum failed attempts to flag an IP (default: 5)"
    )
    args = parser.parse_args()

    print(f"\n[*] Parsing: {args.log_file}")
    print(f"[*] Threshold: {args.threshold} failed attempts")

    flagged = parse_failed_logins(args.log_file, args.threshold)
    print_report(flagged, args.threshold)


if __name__ == "__main__":
    main()
