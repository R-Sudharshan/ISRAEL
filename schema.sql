CREATE DATABASE IF NOT EXISTS iot_security;
USE iot_security;

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    device_type VARCHAR(100),
    protocol VARCHAR(20),
    action VARCHAR(50),
    raw_log TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    severity VARCHAR(20) NOT NULL,
    detection_type VARCHAR(100) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    device VARCHAR(100),
    timestamp DATETIME NOT NULL,
    raw_log_reference INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (raw_log_reference) REFERENCES logs(id)
);

CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_name VARCHAR(100),
    mac_address VARCHAR(17),
    ip_address VARCHAR(45),
    known_type VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
