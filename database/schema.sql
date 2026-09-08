CREATE DATABASE IF NOT EXISTS cloud_forensics;
USE cloud_forensics;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(180) NOT NULL,
    role ENUM('ADMIN','USER','SELLER') NOT NULL,
    authorized BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS datasets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    investigation_type VARCHAR(100) NOT NULL,
    forensic_chain VARCHAR(150) NOT NULL,
    source_type ENUM('CONSUMER','PROVIDER') NOT NULL,
    owner_id INT NOT NULL,
    record_value DECIMAL(18,4) NOT NULL DEFAULT 0,
    record_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    content LONGTEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS disputes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    consumer_dataset_id INT NOT NULL,
    provider_dataset_id INT NOT NULL,
    consumer_value DECIMAL(18,4) NOT NULL,
    provider_value DECIMAL(18,4) NOT NULL,
    difference_value DECIMAL(18,4) NOT NULL,
    status VARCHAR(40) NOT NULL,
    resolution VARCHAR(500) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS inquiries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    dataset_id INT,
    question TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (dataset_id) REFERENCES datasets(id)
);

INSERT IGNORE INTO users(username,password_hash,full_name,email,role,authorized)
VALUES ('admin','admin123','System Administrator','admin@example.com','ADMIN',TRUE);
