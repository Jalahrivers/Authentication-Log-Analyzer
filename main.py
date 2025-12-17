"""
Authentication Log Analyzer
Author: Jalah Rivers

This script:
- Reads an authentication log file
- Counts failed login attempts per IP address
- Flags suspicious IPs that cross a configurable threshold
- Saves report to a text file
"""

import argparse
from collections import defaultdict
from pathlib import Path
from datetime import datetime


def parse_logs(file_path, threshold=3):
    """
    Parse an authentication log file and:
    - Count failed login attempts per IP
    - Return (all_failed_dict, suspicious_dict)
    """
    failed_attempts = defaultdict(int)

    with open(file_path, "r", encoding="utf-8") as logs:
        for line in logs:
            line_lower = line.lower()

            if "failed password" in line_lower:
                parts = line.split()

                if "from" in parts:
                    ip_index = parts.index("from") + 1
                    if ip_index < len(parts):
                        ip = parts[ip_index]
                        failed_attempts[ip] += 1

    suspicious = {
        ip: count for ip, count in failed_attempts.items()
        if count >= threshold
    }

    return dict(failed_attempts), suspicious


def save_report(suspicious_dict, output_file):
    """
    Save suspicious IPs and counts to a report file.
    """
    output_path = Path(output_file)

    with open(output_path, "w", encoding="utf-8") as report:
        report.write("Authentication Log Analyzer Report\n")
        report.write("=================================\n")
        report.write(f"Generated: {datetime.now()}\n\n")

        if not suspicious_dict:
            report.write("No suspicious IPs detected.\n")
        else:
            report.write("Suspicious IPs (potential brute-force activity):\n\n")
            for ip, count in suspicious_dict.items():
                report.write(f"{ip} -> {count} failed login attempts\n")

    print(f"[+] Report saved to {output_path.resolve()}")


def main():
    parser = argparse.ArgumentParser(
        description="Authentication Log Analyzer - detect failed login attempts by IP."
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the authentication log file (e.g., sample_logs.txt)."
    )

    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=3,
        help="Number of failed attempts before an IP is considered suspicious (default: 3)."
    )

    parser.add_argument(
        "-o", "--output",
        default="suspicious_report.txt",
        help="Output report filename (default: suspicious_report.txt)."
    )

    args = parser.parse_args()
    log_file = Path(args.file)

    if not log_file.exists():
        print(f"[!] Log file not found: {log_file}")
        return

    print(f"[+] Parsing log file: {log_file}")
    all_attempts, suspicious_ips = parse_logs(
        log_file,
        threshold=args.threshold
    )

    print("\nX All failed login attempts:")
    if all_attempts:
        for ip, count in all_attempts.items():
            print(f"{ip} -> {count}")
    else:
        print("No failed login attempts found.")

    print("\nIoC Suspicious IPs:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip} -> {count}")
    else:
        print("No IPs exceeded the threshold.")

    save_report(suspicious_ips, args.output)


if __name__ == "__main__":
    main()