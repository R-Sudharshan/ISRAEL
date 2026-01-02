import json
from datetime import datetime, timedelta


with open('test_logs.json', 'r') as f:
    logs = json.load(f)

for i, log in enumerate(logs):
    new_time = datetime.now() - timedelta(minutes=len(logs) - i)
    log['timestamp'] = new_time.strftime("%Y-%m-%d %H:%M:%S")


with open('test_logs.json', 'w') as f:
    json.dump(logs, f, indent=2)

print("Updated test_logs.json with current timestamps.")
