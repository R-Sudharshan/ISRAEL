
import subprocess
import mysql.connector
from config import Config
import time

def verify():
    print("[-] Starting End-to-End Verification")
    
    # 1. Clear Logs
    print("[-] Clearing existing logs...")
    conn = mysql.connector.connect(
        host=Config.DB_HOST, user=Config.DB_USER, password=Config.DB_PASSWORD, database=Config.DB_NAME
    )
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    conn.commit()
    cursor.close()
    
    # 2. Generate Logs (Authentication Domain)
    print("[-] Generating Authentication logs...")
    cmd = ["python", "traffic_generator.py", "--domain", "Authentication", "--baseline", "5"]
    subprocess.run(cmd, check=True)
    
    # 3. Ingest Logs
    print("[-] Ingesting logs...")
    cmd_ingest = ["python", "ingest_logs.py"]
    subprocess.run(cmd_ingest, check=True)
    
    # 4. Verify in DB
    print("[-] Verifying database content...")
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM logs WHERE log_type='authentication'")
    rows = cursor.fetchall()
    
    if len(rows) >= 5:
        print(f"[+] Success: Found {len(rows)} authentication logs.")
        sample = rows[0]
        print("Sample Log Keys:", sample.keys())
        # Check for new columns
        if sample.get('auth_type') is not None or sample.get('user') is not None:
             print("[+] Verified new columns are populated.")
             print(f"Sample User: {sample.get('user')}")
             print(f"Sample Auth Type: {sample.get('auth_type')}")
        else:
             print("[!] Warning: New columns appear empty or missing.")
    else:
        print(f"[!] Failure: Expected 5 logs, found {len(rows)}")
        
    cursor.close()
    conn.close()

if __name__ == "__main__":
    verify()
