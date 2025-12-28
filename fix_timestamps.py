import json
from datetime import datetime, timedelta

# Load existing logs
with open('test_logs.json', 'r') as f:
    logs = json.load(f)

# Update timestamps to be recent (last few minutes)
# We'll space them out by 1 minute
for i, log in enumerate(logs):
    # Format: 2023-10-27 10:00:00 -> YYYY-MM-DD HH:MM:SS
    # We want valid MySQL datetime format
    new_time = datetime.now() - timedelta(minutes=len(logs) - i)
    log['timestamp'] = new_time.strftime("%Y-%m-%d %H:%M:%S")

# Save back
with open('test_logs.json', 'w') as f:
    json.dump(logs, f, indent=2)

print("Updated test_logs.json with current timestamps.")
