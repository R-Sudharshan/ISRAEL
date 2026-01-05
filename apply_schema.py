import mysql.connector
from config import Config

def apply_update():
    print("[-] Connecting to database...")
    conn = mysql.connector.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME
    )
    cursor = conn.cursor()
    
    with open('update_schema_domains.sql', 'r') as f:
        sql = f.read()
        
    print("[-] Returning statements...")
    # Split by ; and execute
    statements = sql.split(';')
    for stmt in statements:
        if stmt.strip():
            print(f"Executing: {stmt.strip()[:50]}...")
            try:
                cursor.execute(stmt)
            except Exception as e:
                print(f"[!] Error: {e}")
                
    conn.commit()
    print("[+] Schema update applied successfully.")
    cursor.close()
    conn.close()

if __name__ == "__main__":
    apply_update()
