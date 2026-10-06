CREATE TABLE trial_signals (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL,
    fingerprint_hash CHAR(64) NOT NULL,
    ip_hash CHAR(64) NOT NULL,
    browser VARCHAR(50) NULL,
    os VARCHAR(50) NULL,
    screen VARCHAR(20) NULL,
    language VARCHAR(20) NULL,
    timezone VARCHAR(100) NULL,
    payment_fingerprint CHAR(64) NULL,
    risk_score SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    risk_level ENUM('low','medium','high','very_high') NOT NULL DEFAULT 'low',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_fingerprint (fingerprint_hash),
    INDEX idx_ip (ip_hash),
    INDEX idx_payment (payment_fingerprint),
    INDEX idx_user (user_id),
    INDEX idx_created (created_at)
);

CREATE TABLE trial_blocks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    type ENUM('ip','fingerprint','payment') NOT NULL,
    value_hash CHAR(64) NOT NULL,
    reason VARCHAR(255) NULL,
    expires_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_block (type, value_hash),
    INDEX idx_expiry (expires_at)
);

CREATE TABLE trials (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    started_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    status ENUM('active','expired','cancelled','blocked') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_status (status)
);