
import mysql.connector
from config import Config

def fix_and_check():
    conn = mysql.connector.connect(
        host=Config.DB_HOST, user=Config.DB_USER, password=Config.DB_PASSWORD, database=Config.DB_NAME
    )
    cursor = conn.cursor()
    
    # 1. Add ip_address
    try:
        print("[-] Adding ip_address column...")
        cursor.execute("ALTER TABLE logs ADD COLUMN ip_address VARCHAR(45)")
        print("[+] Added ip_address.")
    except Exception as e:
        print(f"[!] Error adding ip_address: {e}")
        
    # 2. Check Schema
    cursor.execute("DESCRIBE logs")
    rows = cursor.fetchall()
    print("[-] Current Columns:")
    cols = [r[0] for r in rows]
    print(cols)
    
    if "region" in cols:
        print("[+] 'region' column exists.")
    else:
        print("[!] 'region' column MISSING.")

    conn.close()

if __name__ == "__main__":
    fix_and_check()
