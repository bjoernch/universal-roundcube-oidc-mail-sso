CREATE TABLE IF NOT EXISTS `oidc_mail_sso_oidc_user` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned DEFAULT NULL,
  `oidc_sub` varchar(191) NOT NULL,
  `email` varchar(320) NOT NULL,
  `is_disabled` tinyint(1) NOT NULL DEFAULT 0,
  `disabled_reason` varchar(255) DEFAULT NULL,
  `disabled_at` datetime DEFAULT NULL,
  `admin_note` text DEFAULT NULL,
  `failed_auth_count` int unsigned NOT NULL DEFAULT 0,
  `lock_until` datetime DEFAULT NULL,
  `last_seen_ip` varchar(64) DEFAULT NULL,
  `last_login_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_oidc_sub` (`oidc_sub`),
  KEY `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `oidc_mail_sso_mailbox` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned DEFAULT NULL,
  `oidc_sub` varchar(191) NOT NULL,
  `email` varchar(320) NOT NULL,
  `imap_host` varchar(255) NOT NULL,
  `imap_port` smallint unsigned NOT NULL,
  `imap_security` enum('ssl','tls','starttls','none') NOT NULL DEFAULT 'ssl',
  `smtp_host` varchar(255) NOT NULL,
  `smtp_port` smallint unsigned NOT NULL,
  `smtp_security` enum('ssl','tls','starttls','none') NOT NULL DEFAULT 'tls',
  `smtp_auth` tinyint(1) NOT NULL DEFAULT 1,
  `smtp_user` varchar(320) NOT NULL,
  `password_enc` varbinary(4096) NOT NULL,
  `enc_alg` varchar(32) NOT NULL,
  `enc_nonce` varbinary(255) NOT NULL,
  `key_id` varchar(64) NOT NULL DEFAULT 'v1',
  `client_wrap_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `client_wrap_blob` varbinary(8192) DEFAULT NULL,
  `client_wrap_nonce` varbinary(255) DEFAULT NULL,
  `client_wrap_salt` varbinary(255) DEFAULT NULL,
  `client_wrap_kdf` varchar(32) DEFAULT NULL,
  `client_wrap_iters` int unsigned DEFAULT NULL,
  `client_wrap_version` varchar(16) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `last_used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_mailbox_oidc_sub` (`oidc_sub`),
  KEY `idx_mailbox_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `oidc_mail_sso_audit_log` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `event` varchar(64) NOT NULL,
  `status` varchar(16) NOT NULL,
  `oidc_sub` varchar(191) DEFAULT NULL,
  `email` varchar(320) DEFAULT NULL,
  `user_id` int unsigned DEFAULT NULL,
  `message` varchar(1024) DEFAULT NULL,
  `meta_json` text DEFAULT NULL,
  `hash_alg` varchar(16) NOT NULL DEFAULT 'sha256',
  `prev_hash` char(64) DEFAULT NULL,
  `row_hash` char(64) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_audit_event` (`event`),
  KEY `idx_audit_status` (`status`),
  KEY `idx_audit_created` (`created_at`),
  KEY `idx_audit_sub` (`oidc_sub`),
  KEY `idx_audit_row_hash` (`row_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `oidc_mail_sso_policy` (
  `policy_key` varchar(64) NOT NULL,
  `policy_value` text DEFAULT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`policy_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `oidc_mail_sso_rate_limit` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `scope` varchar(64) NOT NULL,
  `subject` varchar(255) NOT NULL,
  `window_start` datetime NOT NULL,
  `attempts` int unsigned NOT NULL DEFAULT 1,
  `last_attempt_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_scope_subject_window` (`scope`,`subject`,`window_start`),
  KEY `idx_scope_subject` (`scope`,`subject`),
  KEY `idx_last_attempt` (`last_attempt_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
