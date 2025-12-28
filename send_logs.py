import requests
import os

def send_logs():
    url = 'http://localhost:5000/ingest'
    file_path = 'test_logs.json'
    
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return

    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(url, files=files)
            
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Failed to send logs: {e}")

if __name__ == "__main__":
    send_logs()
