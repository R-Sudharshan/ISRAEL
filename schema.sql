CREATE DATABASE IF NOT EXISTS iot_security;
USE iot_security;

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(20),
    service VARCHAR(100),
    action VARCHAR(50),
    policyid INT,
    sentbyte BIGINT DEFAULT 0,
    rcvdbyte BIGINT DEFAULT 0,
    duration INT,
    user VARCHAR(100) DEFAULT 'N/A',
    device_type VARCHAR(100),
    level VARCHAR(20),
    logid VARCHAR(50),
    src_country VARCHAR(100) DEFAULT 'Reserved',
    dst_country VARCHAR(100) DEFAULT 'United States',
    msg TEXT,
    qname VARCHAR(255),
    raw_log TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (timestamp),
    INDEX (src_ip),
    INDEX (dst_ip)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    severity VARCHAR(20) NOT NULL,
    detection_type VARCHAR(100) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45),
    timestamp DATETIME NOT NULL,
    raw_log_reference INT,
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (timestamp),
    INDEX (src_ip),
    FOREIGN KEY (raw_log_reference) REFERENCES logs(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user', 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    managed_by INT,
    FOREIGN KEY (managed_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    os VARCHAR(100),
    asset_type VARCHAR(50), 
    last_seen DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS asset_services (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT,
    port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    service_name VARCHAR(100),
    state VARCHAR(50), 
    version_info TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    UNIQUE KEY (asset_id, port, protocol)
) ENGINE=InnoDB;
