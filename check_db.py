from api.db import get_db_connection

def check_data():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check count
        cursor.execute("SELECT COUNT(*) as count FROM alerts")
        count = cursor.fetchone()['count']
        print(f"Total Alerts in DB: {count}")
        
        # Check latest
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5")
        rows = cursor.fetchall()
        
        print("\nLatest 5 Alerts:")
        for row in rows:
            print(f"- Time: {row['timestamp']}, Type: {row['detection_type']}, Severity: {row['severity']}")
            
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_data()
