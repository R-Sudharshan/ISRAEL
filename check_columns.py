
import mysql.connector
from config import Config

def check_schema():
    conn = mysql.connector.connect(
        host=Config.DB_HOST, user=Config.DB_USER, password=Config.DB_PASSWORD, database=Config.DB_NAME
    )
    cursor = conn.cursor()
    cursor.execute("DESCRIBE logs")
    rows = cursor.fetchall()
    print(f"Columns in 'logs' table ({len(rows)}):")
    for row in rows:
        print(f"- {row[0]} ({row[1]})")
    conn.close()

if __name__ == "__main__":
    check_schema()
