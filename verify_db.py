
import mysql.connector
from config import Config

def check_columns():
    try:
        conn = mysql.connector.connect(
            host=Config.DB_HOST,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME
        )
        cursor = conn.cursor()
        cursor.execute("DESCRIBE logs")
        columns = [row[0] for row in cursor.fetchall()]
        print(f"FULL Columns in 'logs' table: {columns}")
        
        expected = ["src_port", "dst_port", "src_country", "dst_country", "service"]
        missing = [col for col in expected if col not in columns]
        
        if missing:
            print(f"STILL MISSING: {missing}")
        else:
            print("ALL REQUIRED COLUMNS PRESENT.")
            
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_columns()
