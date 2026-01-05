
import mysql.connector
from config import Config

def relax_constraints():
    print("[-] Connecting to database...")
    conn = mysql.connector.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME
    )
    cursor = conn.cursor()
    
    # Make src_ip and dst_ip nullable
    try:
        print("[-] Modifying src_ip to allow NULL...")
        # Note: We must repeat the full definition.
        cursor.execute("ALTER TABLE logs MODIFY src_ip VARCHAR(45) NULL")
        print("[+] src_ip modified.")
    except Exception as e:
        print(f"[!] Error modifying src_ip: {e}")

    try:
        print("[-] Modifying dst_ip to allow NULL...")
        cursor.execute("ALTER TABLE logs MODIFY dst_ip VARCHAR(45) NULL")
        print("[+] dst_ip modified.")
    except Exception as e:
        print(f"[!] Error modifying dst_ip: {e}")
                
    conn.commit()
    conn.close()
    print("[+] Constraints relaxed.")

if __name__ == "__main__":
    relax_constraints()
