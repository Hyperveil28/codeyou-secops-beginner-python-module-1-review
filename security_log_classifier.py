# ------------------------------------------------------------
# Module 1 Homework: Security Log Classifier
# Description:
# This script reads login records from a text file, counts
# successful and failed logins, classifies IP addresses, and
# reports possible brute-force activity.
# ------------------------------------------------------------

# Ask the user for the filename.
# Press Enter to use the default file name.
filename = input("Enter log filename, or press Enter for logins.txt: ")

if filename == "":
    filename = "logins.txt"


# ------------------------------------------------------------
# Read login records from the file
# ------------------------------------------------------------

with open(filename, "r") as file:
    lines = file.readlines()

print(f"Loaded {len(lines)} login records.")


# ------------------------------------------------------------
# Create lists to store parsed log data
# ------------------------------------------------------------

users = []
ips = []
results = []


# ------------------------------------------------------------
# Create counters
# ------------------------------------------------------------

successful_logins = 0
failed_logins = 0

internal_ips = 0
external_ips = 0


# ------------------------------------------------------------
# Parse each line from the log file
# ------------------------------------------------------------

for line in lines:
    parts = line.strip().split()

    username = parts[0]
    ip_address = parts[1]
    result = parts[2]

    users.append(username)
    ips.append(ip_address)
    results.append(result)

    # Count successful and failed logins
    if result == "FAILURE":
        failed_logins += 1
    else:
        successful_logins += 1

    # Classify IP addresses
    # For this assignment, internal IPs start with 10. or 192.168.
    if ip_address.startswith("10.") or ip_address.startswith("192.168."):
        internal_ips += 1
    else:
        external_ips += 1


# ------------------------------------------------------------
# Detect possible brute-force activity
# This checks for 3 or more failed logins from the same user/IP.
# ------------------------------------------------------------

brute_force_alerts = []

for i in range(len(users)):
    current_user = users[i]
    current_ip = ips[i]
    failure_count = 0

    if results[i] == "FAILURE":
        for j in range(len(users)):
            if users[j] == current_user and ips[j] == current_ip and results[j] == "FAILURE":
                failure_count += 1

        if failure_count >= 3:
            alert_message = (
                f"User '{current_user}' had {failure_count} failed logins "
                f"from IP {current_ip}"
            )

            if alert_message not in brute_force_alerts:
                brute_force_alerts.append(alert_message)


# ------------------------------------------------------------
# Build the summary report
# ------------------------------------------------------------

summary = ""

summary += "========================================\n"
summary += " Security Log Classifier Report\n"
summary += "========================================\n"
summary += f"Total login attempts: {len(lines)}\n"
summary += f"Successful logins: {successful_logins}\n"
summary += f"Failed logins: {failed_logins}\n"
summary += f"Internal IPs: {internal_ips}\n"
summary += f"External IPs: {external_ips}\n"
summary += "\n"

summary += "Possible brute-force alert:\n"

if len(brute_force_alerts) > 0:
    for alert in brute_force_alerts:
        summary += f"[!] {alert}\n"
else:
    summary += "[+] No brute-force activity detected.\n"

summary += "========================================\n"


# ------------------------------------------------------------
# Print the summary report
# ------------------------------------------------------------

print()
print(summary)


# ------------------------------------------------------------
# Bonus: Write summary report to a file
# ------------------------------------------------------------

with open("summary.txt", "w") as output_file:
    output_file.write(summary)

print("Summary report written to summary.txt.")