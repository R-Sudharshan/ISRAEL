
import mysql.connector
from config import Config

def fix_schema():
    print("[-] Connecting to database...")
    conn = mysql.connector.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME
    )
    cursor = conn.cursor()
    
    # List of columns we expect
    # Format: (name, definition)
    columns_to_ensure = [
        ("log_type", "VARCHAR(50)"),
        ("source", "VARCHAR(100)"),
        ("host", "VARCHAR(100)"),
        ("direction", "VARCHAR(20)"),
        ("auth_type", "VARCHAR(50)"),
        ("auth_result", "VARCHAR(50)"),
        ("failure_reason", "VARCHAR(255)"),
        ("location", "VARCHAR(100)"),
        ("process_name", "VARCHAR(100)"),
        ("process_id", "VARCHAR(50)"),
        ("parent_process", "VARCHAR(100)"),
        ("command_line", "TEXT"),
        ("file_path", "TEXT"),
        ("hash", "VARCHAR(255)"),
        ("integrity_level", "VARCHAR(50)"),
        ("http_method", "VARCHAR(10)"),
        ("url", "TEXT"),
        ("status_code", "INT"),
        ("user_agent", "TEXT"),
        ("request_size", "INT"),
        ("response_size", "INT"),
        ("session_id", "VARCHAR(100)"),
        ("asset_id", "VARCHAR(50)"),
        ("hostname", "VARCHAR(100)"),
        ("mac_address", "VARCHAR(50)"),
        ("os", "VARCHAR(50)"),
        ("os_version", "VARCHAR(50)"),
        ("role", "VARCHAR(50)"),
        ("criticality", "VARCHAR(50)"),
        ("last_seen", "DATETIME"),
        ("alert_name", "VARCHAR(100)"),
        ("detection_engine", "VARCHAR(100)"),
        ("action_taken", "VARCHAR(100)"),
        ("confidence", "VARCHAR(50)"),
        ("query", "VARCHAR(255)"),
        ("query_type", "VARCHAR(20)"),
        ("response", "TEXT"),
        ("rcode", "VARCHAR(20)"),
        ("ttl", "INT"),
        ("resolver", "VARCHAR(50)"),
        ("cloud_provider", "VARCHAR(50)"),
        ("account_id", "VARCHAR(50)"),
        ("api_call", "VARCHAR(100)"),
        ("resource", "VARCHAR(255)"),
        ("result", "VARCHAR(50)"),
        ("client_ip", "VARCHAR(45)"),
        ("src_country", "VARCHAR(100)"),
        ("dst_country", "VARCHAR(100)"),
        ("msg", "TEXT")
    ]
    
    for col_name, col_def in columns_to_ensure:
        try:
            print(f"[-] Checking/Adding column {col_name}...")
            # We use IF NOT EXISTS syntax by trying to ADD. 
            # MySQL < 8.0 doesn't support ADD COLUMN IF NOT EXISTS directly in all versions reliably without stored procedure, 
            # but let's try strict ADD and catch 'Duplicate column' error.
            
            stmt = f"ALTER TABLE logs ADD COLUMN {col_name} {col_def}"
            cursor.execute(stmt)
            print(f"[+] Added {col_name}")
        except mysql.connector.errors.ProgrammingError as e:
            if e.errno == 1060: # Duplicate column name
                print(f"[.] Column {col_name} already exists.")
            else:
                print(f"[!] Error adding {col_name}: {e}")
                
    conn.commit()
    conn.close()
    print("[+] Schema fix complete.")

if __name__ == "__main__":
    fix_schema()
