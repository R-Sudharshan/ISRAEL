import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from api.db import get_db_connection

class AuthManager:
    @staticmethod
    def login(username, password):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            # Strip whitespace
            clean_user = username.strip()
            cursor.execute("SELECT * FROM users WHERE username = %s", (clean_user,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                return {
                    "id": user['id'],
                    "username": user['username'], 
                    "role": user['role'],
                    "managed_by": user['managed_by']
                }
            return None
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def create_user(username, password, role='user', managed_by=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            hashed_pw = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, managed_by) VALUES (%s, %s, %s, %s)",
                (username, hashed_pw, role, managed_by)
            )
            conn.commit()
            return True
        except mysql.connector.Error as err:
            print(f"Error creating user: {err}")
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_team_members(admin_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT id, username, role, created_at 
                FROM users 
                WHERE managed_by = %s 
                ORDER BY created_at DESC
            """, (admin_id,))
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    
    @staticmethod
    def get_user_id(username):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            res = cursor.fetchone()
            return res[0] if res else None
        finally:
            cursor.close()
            conn.close()
