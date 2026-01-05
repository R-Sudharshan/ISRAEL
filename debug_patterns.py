
from pattern_manager import PatternManager
import subprocess
import mysql.connector
from config import Config

def verify_patterns():
    pm = PatternManager()
    
    # 1. Check SQL Injection Payloads
    print("[-] Checking SQL INJECTION payloads...")
    sqli_loads = pm.load_payloads("SQL INJECTION")
    print(f"[?] Payloads found: {len(sqli_loads)}")
    if sqli_loads:
        print(f"Sample: {sqli_loads[:3]}") # Show first 3
        
    # 2. Clear Logs
    print("[-] Clearing logs...")
    conn = mysql.connector.connect(
        host=Config.DB_HOST, user=Config.DB_USER, password=Config.DB_PASSWORD, database=Config.DB_NAME
    )
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    conn.commit()
    conn.close()
    
    # 3. Generate Traffic
    print("[-] Generating SQL Injection logs...")
    # Escape space for command line? subprocess handles list args safely.
    subprocess.run(["python", "traffic_generator.py", "--patterns", "SQL INJECTION", "--pattern_count", "5"], check=True)
    
    # 4. Ingest
    print("[-] Ingesting...")
    subprocess.run(["python", "ingest_logs.py"], check=True)
    
    # 5. Verify DB
    conn = mysql.connector.connect(
        host=Config.DB_HOST, user=Config.DB_USER, password=Config.DB_PASSWORD, database=Config.DB_NAME
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM logs WHERE msg LIKE '%SQL INJECTION%'")
    rows = cursor.fetchall()
    print(f"[+] SQL Injection Logs in DB: {len(rows)}")
    if rows:
        print(f"Sample Msg: {rows[0]['msg']}")
        
    conn.close()

if __name__ == "__main__":
    verify_patterns()
