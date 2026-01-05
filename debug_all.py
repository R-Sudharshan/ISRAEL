
import subprocess
import mysql.connector
from config import Config

def debug_all():
    conn = mysql.connector.connect(
        host=Config.DB_HOST, user=Config.DB_USER, password=Config.DB_PASSWORD, database=Config.DB_NAME
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, log_type, src_ip, ip_address, timestamp FROM logs")
    rows = cursor.fetchall()
    print(f"Total Logs: {len(rows)}")
    for row in rows:
        print(row)
    conn.close()

if __name__ == "__main__":
    debug_all()
