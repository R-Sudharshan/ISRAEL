from api.db import get_db_connection
import mysql.connector

try:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    count = cursor.fetchone()[0]
    print(f"Total logs in DB: {count}")
    
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 1")
    last_log = cursor.fetchone()
    print(f"Last log: {last_log}")
    
except Exception as e:
    print(f"Error: {e}")
finally:
    if 'conn' in locals() and conn.is_connected():
        conn.close()
