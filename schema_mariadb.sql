-- ============================================================
-- Node Status — MariaDB / MySQL schema
-- Import via phpMyAdmin or CLI: mysql -u root -p dbname < schema_mariadb.sql
-- ============================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------------
-- admins
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS `admins` (
    `id`         INT          NOT NULL AUTO_INCREMENT,
    `username`   VARCHAR(60)  NOT NULL,
    `password`   VARCHAR(255) NOT NULL COMMENT 'bcrypt hash',
    `created_at` INT          NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_admins_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- NOTE: The default admin account (admin / admin123) is created automatically
--       on first page load via seed_default_admin() in PHP.
--       Change the password immediately via the admin panel.

-- -----------------------------------------------------------
-- nodes
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS `nodes` (
    `id`            INT          NOT NULL AUTO_INCREMENT,
    `name`          VARCHAR(120) NOT NULL,
    `node_type`     VARCHAR(20)  NOT NULL DEFAULT 'remote',
    `ssh_host`      VARCHAR(255) DEFAULT NULL,
    `ssh_port`      INT          DEFAULT NULL,
    `ssh_user`      VARCHAR(120) DEFAULT NULL,
    `ssh_password`  VARCHAR(255) DEFAULT NULL,
    `net_interface` VARCHAR(80)  DEFAULT NULL,
    `endpoint_url`  VARCHAR(400) DEFAULT NULL,
    `api_token`     VARCHAR(255) DEFAULT NULL,
    `is_active`     TINYINT(1)   NOT NULL DEFAULT 1,
    `country`       VARCHAR(10)  DEFAULT NULL,
    `created_at`    INT          NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- samples
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS `samples` (
    `id`             INT          NOT NULL AUTO_INCREMENT,
    `node_id`        INT          NOT NULL,
    `ts`             INT          NOT NULL,
    `status`         VARCHAR(20)  NOT NULL,
    `cpu_pct`        DOUBLE       DEFAULT NULL,
    `cpu_name`       VARCHAR(255) DEFAULT NULL,
    `cpu_cores`      INT          DEFAULT NULL,
    `hostname`       VARCHAR(120) DEFAULT NULL,
    `os_name`        VARCHAR(180) DEFAULT NULL,
    `mem_total_mb`   DOUBLE       DEFAULT NULL,
    `mem_used_mb`    DOUBLE       DEFAULT NULL,
    `mem_used_pct`   DOUBLE       DEFAULT NULL,
    `swap_total_mb`  DOUBLE       DEFAULT NULL,
    `swap_used_mb`   DOUBLE       DEFAULT NULL,
    `swap_used_pct`  DOUBLE       DEFAULT NULL,
    `disk_total_gb`  DOUBLE       DEFAULT NULL,
    `disk_used_gb`   DOUBLE       DEFAULT NULL,
    `disk_used_pct`  DOUBLE       DEFAULT NULL,
    `net_rx_bytes`   BIGINT       DEFAULT NULL,
    `net_tx_bytes`   BIGINT       DEFAULT NULL,
    `load1`          DOUBLE       DEFAULT NULL,
    `load5`          DOUBLE       DEFAULT NULL,
    `load15`         DOUBLE       DEFAULT NULL,
    `uptime_seconds` INT          DEFAULT NULL,
    `error_text`     TEXT         DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `idx_samples_node_ts` (`node_id`, `ts`),
    CONSTRAINT `fk_samples_node` FOREIGN KEY (`node_id`) REFERENCES `nodes` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- announcements
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS `announcements` (
    `id`          INT          NOT NULL AUTO_INCREMENT,
    `title`       VARCHAR(120) NOT NULL,
    `message`     TEXT         NOT NULL,
    `level`       VARCHAR(20)  NOT NULL DEFAULT 'info',
    `node_id`     INT          DEFAULT NULL,
    `starts_at`   INT          DEFAULT NULL,
    `ends_at`     INT          DEFAULT NULL,
    `pinned`      TINYINT(1)   NOT NULL DEFAULT 0,
    `resolved_at` INT          DEFAULT NULL,
    `created_at`  INT          NOT NULL,
    `created_by`  VARCHAR(60)  NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- app_state  (key-value store)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS `app_state` (
    `state_key`   VARCHAR(120) NOT NULL,
    `state_value` TEXT         NOT NULL,
    PRIMARY KEY (`state_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- subscribers
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS `subscribers` (
    `id`         INT          NOT NULL AUTO_INCREMENT,
    `email`      VARCHAR(255) NOT NULL,
    `token`      VARCHAR(64)  NOT NULL,
    `confirmed`  TINYINT(1)   NOT NULL DEFAULT 0,
    `created_at` INT          NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_subscribers_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- announcement_updates
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS `announcement_updates` (
    `id`              INT          NOT NULL AUTO_INCREMENT,
    `announcement_id` INT          NOT NULL,
    `message`         TEXT         NOT NULL,
    `status`          VARCHAR(20)  NOT NULL DEFAULT 'investigating',
    `created_at`      INT          NOT NULL,
    `created_by`      VARCHAR(60)  NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_updates_announcement` FOREIGN KEY (`announcement_id`) REFERENCES `announcements` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
