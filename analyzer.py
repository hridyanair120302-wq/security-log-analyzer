
from collections import defaultdict

LOG_FILE = "sample_logs.txt"
FAILED_LOGIN_THRESHOLD = 3
MULTIPLE_USERS_THRESHOLD = 3

failed_attempts = defaultdict(int)
failed_by_ip = defaultdict(int)
users_by_ip = defaultdict(set)

with open(LOG_FILE, "r") as file:
    for line in file:
        if "status=FAILED" not in line:
            continue

        parts = line.split()
        username = parts[2].split("=")[1]
        ip_address = parts[3].split("=")[1]

        failed_attempts[(username, ip_address)] += 1
        failed_by_ip[ip_address] += 1
        users_by_ip[ip_address].add(username)

print("=== Security Log Analyzer ===")

alerts_found = False

for (username, ip_address), count in failed_attempts.items():
    if count >= FAILED_LOGIN_THRESHOLD:
        print(
            f"ALERT: {username} from {ip_address} "
            f"had {count} failed login attempts!"
        )
        alerts_found = True

for ip_address, users in users_by_ip.items():
    if len(users) >= MULTIPLE_USERS_THRESHOLD:
        print(
            f"ALERT: {ip_address} had failed logins "
            f"for {len(users)} different accounts!"
        )
        alerts_found = True

if not alerts_found:
    print("No suspicious login patterns detected.")
