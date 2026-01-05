
import subprocess
import mysql.connector
from config import Config
import json

def debug_domains():
    print("[-] Clearing logs...")
    conn = mysql.connector.connect(
        host=Config.DB_HOST, user=Config.DB_USER, password=Config.DB_PASSWORD, database=Config.DB_NAME
    )
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    conn.commit()
    
    # 1. Generate Asset Logs
    print("[-] Generating Asset Logs...")
    subprocess.run(["python", "traffic_generator.py", "--domain", "Asset", "--baseline", "5"], check=True)
    
    # 2. Ingest
    print("[-] Ingesting Asset Logs...")
    subprocess.run(["python", "ingest_logs.py"], check=True)
    
    # 3. Check DB
    cursor.execute("SELECT * FROM logs WHERE log_type='asset'")
    assets = cursor.fetchall()
    print(f"[?] Asset Logs in DB: {len(assets)}")
    
    # 4. Generate Cloud Logs
    print("[-] Generating Cloud Logs...")
    subprocess.run(["python", "traffic_generator.py", "--domain", "Cloud", "--baseline", "5"], check=True)
    
    # 5. Ingest
    print("[-] Ingesting Cloud Logs...")
    subprocess.run(["python", "ingest_logs.py"], check=True)
    
    # 6. Check DB
    cursor.execute("SELECT * FROM logs WHERE log_type='cloud'")
    clouds = cursor.fetchall()
    print(f"[?] Cloud Logs in DB: {len(clouds)}")
    
    conn.close()

if __name__ == "__main__":
    debug_domains()
