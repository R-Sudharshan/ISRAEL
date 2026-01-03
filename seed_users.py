from auth_manager import AuthManager
from api.db import get_db_connection

def seed_users():
    print("Seeding default users...")
    
    # Check/Create columns if not exist (quick migration)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if managed_by exists
        cursor.execute("DESCRIBE users")
        cols = [row[0] for row in cursor.fetchall()]
        if 'managed_by' not in cols:
            print("Migrating: Adding managed_by column...")
            cursor.execute("ALTER TABLE users ADD COLUMN managed_by INT")
            cursor.execute("ALTER TABLE users ADD FOREIGN KEY (managed_by) REFERENCES users(id) ON DELETE SET NULL")
            conn.commit()
    except Exception as e:
        print(f"Migration check ignored: {e}")
    finally:
        cursor.close()
        conn.close()

    # Create Admin
    AuthManager.create_user('admin', 'admin123', 'admin')
    admin_id = AuthManager.get_user_id('admin')
    
    if admin_id:
        print(f"Admin ID resolved: {admin_id}")
        # Create Analyst managed by Admin
        if AuthManager.create_user('analyst', 'user123', 'user', managed_by=admin_id):
            print(f"Created/Reset: analyst (Linked to admin)")
        else:
             # Try to update existing analyst to link to admin
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE users SET managed_by = %s WHERE username = 'analyst'", (admin_id,))
            conn.commit()
            c.close()
            conn.close()
            print("Updated: analyst linked to admin")

if __name__ == "__main__":
    seed_users()
