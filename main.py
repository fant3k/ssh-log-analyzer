import re
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_PATH = "sample_logs/example_auth.log"



def parse_log(file_path):

    pattern = re.compile(r"Failed password for (invalid user )?(\w+) from ([\d.]+)")
    failed_attempts = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                user = match.group(2)
                ip = match.group(3)
                failed_attempts.append((user, ip))
    return failed_attempts


def report(failed_attempts):
    #Делает отчет по неудач попыткам
    ip_counter = Counter(ip for _, ip in failed_attempts)
    print(f"\nSSH Log Analyzer Report {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total failed attempts: {len(failed_attempts)}")
    print(f"Unique IPs: {len(ip_counter)}\n")

    print("Top offending IP addresses:")
    for ip, count in ip_counter.most_common(10):
        print(f"  {ip} — {count} attempts")


def main():
    log_file = Path(LOG_PATH)
    if not log_file.exists():
        print(f"Лог не найден: {log_file}")
        return

    attempts = parse_log(log_file)
    if attempts:
        report(attempts)
    else:
        print("No failed log")


if __name__ == "__main__":
    main()
