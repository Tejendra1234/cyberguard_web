import csv
import random
from datetime import datetime, timedelta

CSV_FILE = "auth_logs.csv"

users = ["admin", "root", "guest", "test", "user1", "user2"]
ips = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.8",
    "10.0.0.15",
    "172.16.0.5"
]

statuses = ["FAIL", "FAIL", "FAIL", "SUCCESS"]  # more failures

start_time = datetime.now() - timedelta(minutes=15)

rows_to_add = 200

with open(CSV_FILE, "a", newline="") as f:
    writer = csv.writer(f)

    for i in range(rows_to_add):
        start_time += timedelta(seconds=random.randint(2, 8))
        writer.writerow([
            start_time.strftime("%Y-%m-%d %H:%M:%S"),
            random.choice(ips),
            random.choice(users),
            random.choice(statuses)
        ])

print("✅ 200 logs added to auth_logs.csv")
