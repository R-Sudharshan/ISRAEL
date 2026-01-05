
import mysql.connector
from config import Config

def fix_cloud():
    conn = mysql.connector.connect(
        host=Config.DB_HOST, user=Config.DB_USER, password=Config.DB_PASSWORD, database=Config.DB_NAME
    )
    cursor = conn.cursor()
    
    # 1. Add region
    try:
        print("[-] Adding region column...")
        cursor.execute("ALTER TABLE logs ADD COLUMN region VARCHAR(50)")
        print("[+] Added region.")
    except Exception as e:
        print(f"[!] Error adding region: {e}")

    # Check for other cloud columns just in case
    cloud_cols = ["cloud_provider", "account_id", "api_call", "resource", "result"]
    for c in cloud_cols:
         try:
            cursor.execute(f"ALTER TABLE logs ADD COLUMN {c} VARCHAR(100)")
            print(f"[+] Added {c}")
         except:
            pass # Assume exists

    conn.close()

if __name__ == "__main__":
    fix_cloud()
