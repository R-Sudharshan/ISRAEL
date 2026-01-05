import os

class Config:
    DB_HOST = os.environ.get('DB_HOST', 'localhost') 
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'password123') # Ensure you set your local MySQL password here
    DB_NAME = os.environ.get('DB_NAME', 'iot_security')

    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')
    DEBUG = True
