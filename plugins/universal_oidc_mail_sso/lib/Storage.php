<?php

declare(strict_types=1);

namespace UniversalOidcMailSso\Lib;

class Storage
{
    private $db;
    private string $prefix;

    public function __construct($rcmail)
    {
        $this->db = $rcmail->get_dbh();
        $this->prefix = (string) $rcmail->config->get('db_prefix', '');
    }

    public function ensureSchema(): void
    {
        $u = $this->prefix . 'oidc_mail_sso_oidc_user';
        $m = $this->prefix . 'oidc_mail_sso_mailbox';
        $a = $this->prefix . 'oidc_mail_sso_audit_log';
        $p = $this->prefix . 'oidc_mail_sso_policy';
        $r = $this->prefix . 'oidc_mail_sso_rate_limit';

        $queries = [
            "CREATE TABLE IF NOT EXISTS `{$r}` (
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "ALTER TABLE `{$u}` ADD COLUMN IF NOT EXISTS `disabled_reason` varchar(255) DEFAULT NULL",
            "ALTER TABLE `{$u}` ADD COLUMN IF NOT EXISTS `disabled_at` datetime DEFAULT NULL",
            "ALTER TABLE `{$u}` ADD COLUMN IF NOT EXISTS `admin_note` text DEFAULT NULL",
            "ALTER TABLE `{$u}` ADD COLUMN IF NOT EXISTS `failed_auth_count` int unsigned NOT NULL DEFAULT 0",
            "ALTER TABLE `{$u}` ADD COLUMN IF NOT EXISTS `lock_until` datetime DEFAULT NULL",
            "ALTER TABLE `{$u}` ADD COLUMN IF NOT EXISTS `last_seen_ip` varchar(64) DEFAULT NULL",
            "ALTER TABLE `{$m}` ADD COLUMN IF NOT EXISTS `key_id` varchar(64) NOT NULL DEFAULT 'v1'",
            "ALTER TABLE `{$m}` ADD COLUMN IF NOT EXISTS `client_wrap_enabled` tinyint(1) NOT NULL DEFAULT 0",
            "ALTER TABLE `{$m}` ADD COLUMN IF NOT EXISTS `client_wrap_blob` varbinary(8192) DEFAULT NULL",
            "ALTER TABLE `{$m}` ADD COLUMN IF NOT EXISTS `client_wrap_nonce` varbinary(255) DEFAULT NULL",
            "ALTER TABLE `{$m}` ADD COLUMN IF NOT EXISTS `client_wrap_salt` varbinary(255) DEFAULT NULL",
            "ALTER TABLE `{$m}` ADD COLUMN IF NOT EXISTS `client_wrap_kdf` varchar(32) DEFAULT NULL",
            "ALTER TABLE `{$m}` ADD COLUMN IF NOT EXISTS `client_wrap_iters` int unsigned DEFAULT NULL",
            "ALTER TABLE `{$m}` ADD COLUMN IF NOT EXISTS `client_wrap_version` varchar(16) DEFAULT NULL",
            "ALTER TABLE `{$a}` ADD COLUMN IF NOT EXISTS `hash_alg` varchar(16) NOT NULL DEFAULT 'sha256'",
            "ALTER TABLE `{$a}` ADD COLUMN IF NOT EXISTS `prev_hash` char(64) DEFAULT NULL",
            "ALTER TABLE `{$a}` ADD COLUMN IF NOT EXISTS `row_hash` char(64) DEFAULT NULL",
            "CREATE TABLE IF NOT EXISTS `{$p}` (
                `policy_key` varchar(64) NOT NULL,
                `policy_value` text DEFAULT NULL,
                `updated_at` datetime NOT NULL,
                PRIMARY KEY (`policy_key`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        ];

        foreach ($queries as $sql) {
            try {
                $this->db->query($sql);
            } catch (\Throwable $e) {
                // best-effort migration; continue to avoid hard outage
            }
        }

        if (!$this->indexExists($a, 'idx_audit_row_hash')) {
            try {
                $this->db->query("ALTER TABLE `{$a}` ADD KEY `idx_audit_row_hash` (`row_hash`)");
            } catch (\Throwable $e) {
                // best-effort migration; continue to avoid hard outage
            }
        }

        // Seed policy defaults once
        $this->setPolicyIfMissing('session_idle_timeout_sec', '1800');
        $this->setPolicyIfMissing('session_absolute_timeout_sec', '43200');
        $this->setPolicyIfMissing('login_rate_limit_per_5m', '20');
        $this->setPolicyIfMissing('callback_rate_limit_per_5m', '30');
        $this->setPolicyIfMissing('setup_rate_limit_per_5m', '8');
        $this->setPolicyIfMissing('auth_lock_seconds', '600');
        $this->setPolicyIfMissing('login_mode', 'auto');
        $this->setPolicyIfMissing('hide_standard_login_form', '1');
        $this->setPolicyIfMissing('login_button_text', 'Login with SSO');
        $this->setPolicyIfMissing('bootstrap_completed', '0');
    }

    public function upsertIdentity(string $oidcSub, string $email, ?int $userId = null): void
    {
        $table = $this->prefix . 'oidc_mail_sso_oidc_user';
        $sql = "INSERT INTO `{$table}` (`user_id`, `oidc_sub`, `email`, `is_disabled`, `last_login_at`, `created_at`, `updated_at`)\n"
            . "VALUES (?, ?, ?, ?, NOW(), NOW(), NOW())\n"
            . "ON DUPLICATE KEY UPDATE `email` = VALUES(`email`), `last_login_at` = NOW(), `updated_at` = NOW(), `user_id` = COALESCE(VALUES(`user_id`), `user_id`), `failed_auth_count` = 0, `lock_until` = NULL";

        $this->db->query($sql, $userId, $oidcSub, $email, 0);
    }

    public function getIdentityBySub(string $oidcSub): ?array
    {
        $table = $this->prefix . 'oidc_mail_sso_oidc_user';
        $result = $this->db->query("SELECT * FROM `{$table}` WHERE `oidc_sub` = ?", $oidcSub);
        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    public function getMailboxBySub(string $oidcSub): ?array
    {
        $table = $this->prefix . 'oidc_mail_sso_mailbox';
        $result = $this->db->query("SELECT * FROM `{$table}` WHERE `oidc_sub` = ?", $oidcSub);
        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    public function getIdentityByUserId(int $userId): ?array
    {
        $table = $this->prefix . 'oidc_mail_sso_oidc_user';
        $result = $this->db->query(
            "SELECT * FROM `{$table}` WHERE `user_id` = ? ORDER BY `updated_at` DESC LIMIT 1",
            $userId
        );
        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    public function getIdentityByEmail(string $email): ?array
    {
        $table = $this->prefix . 'oidc_mail_sso_oidc_user';
        $result = $this->db->query(
            "SELECT * FROM `{$table}` WHERE LOWER(`email`) = LOWER(?) ORDER BY `updated_at` DESC LIMIT 1",
            $email
        );
        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    public function getMailboxByUserId(int $userId): ?array
    {
        $table = $this->prefix . 'oidc_mail_sso_mailbox';
        $result = $this->db->query(
            "SELECT * FROM `{$table}` WHERE `user_id` = ? ORDER BY `updated_at` DESC LIMIT 1",
            $userId
        );
        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    public function getMailboxByEmail(string $email): ?array
    {
        $table = $this->prefix . 'oidc_mail_sso_mailbox';
        $result = $this->db->query(
            "SELECT * FROM `{$table}` WHERE LOWER(`email`) = LOWER(?) ORDER BY `updated_at` DESC LIMIT 1",
            $email
        );
        $row = $this->db->fetch_assoc($result);

        return $row ?: null;
    }

    public function upsertMailbox(array $data): void
    {
        $table = $this->prefix . 'oidc_mail_sso_mailbox';
        $sql = "INSERT INTO `{$table}`\n"
            . "(`user_id`,`oidc_sub`,`email`,`imap_host`,`imap_port`,`imap_security`,`smtp_host`,`smtp_port`,`smtp_security`,`smtp_auth`,`smtp_user`,`password_enc`,`enc_alg`,`enc_nonce`,`key_id`,`client_wrap_enabled`,`client_wrap_blob`,`client_wrap_nonce`,`client_wrap_salt`,`client_wrap_kdf`,`client_wrap_iters`,`client_wrap_version`,`created_at`,`updated_at`)\n"
            . "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NOW(),NOW())\n"
            . "ON DUPLICATE KEY UPDATE\n"
            . "`user_id` = COALESCE(VALUES(`user_id`), `user_id`),\n"
            . "`email` = VALUES(`email`),\n"
            . "`imap_host` = VALUES(`imap_host`),\n"
            . "`imap_port` = VALUES(`imap_port`),\n"
            . "`imap_security` = VALUES(`imap_security`),\n"
            . "`smtp_host` = VALUES(`smtp_host`),\n"
            . "`smtp_port` = VALUES(`smtp_port`),\n"
            . "`smtp_security` = VALUES(`smtp_security`),\n"
            . "`smtp_auth` = VALUES(`smtp_auth`),\n"
            . "`smtp_user` = VALUES(`smtp_user`),\n"
            . "`password_enc` = VALUES(`password_enc`),\n"
            . "`enc_alg` = VALUES(`enc_alg`),\n"
            . "`enc_nonce` = VALUES(`enc_nonce`),\n"
            . "`key_id` = VALUES(`key_id`),\n"
            . "`client_wrap_enabled` = VALUES(`client_wrap_enabled`),\n"
            . "`client_wrap_blob` = VALUES(`client_wrap_blob`),\n"
            . "`client_wrap_nonce` = VALUES(`client_wrap_nonce`),\n"
            . "`client_wrap_salt` = VALUES(`client_wrap_salt`),\n"
            . "`client_wrap_kdf` = VALUES(`client_wrap_kdf`),\n"
            . "`client_wrap_iters` = VALUES(`client_wrap_iters`),\n"
            . "`client_wrap_version` = VALUES(`client_wrap_version`),\n"
            . "`updated_at` = NOW()";

        $this->db->query(
            $sql,
            $data['user_id'] ?? null,
            $data['oidc_sub'],
            $data['email'],
            $data['imap_host'],
            (int) $data['imap_port'],
            $data['imap_security'],
            $data['smtp_host'],
            (int) $data['smtp_port'],
            $data['smtp_security'],
            !empty($data['smtp_auth']) ? 1 : 0,
            $data['smtp_user'],
            $data['password_enc'],
            $data['enc_alg'],
            $data['enc_nonce'],
            $data['key_id'] ?? 'v1',
            !empty($data['client_wrap_enabled']) ? 1 : 0,
            $data['client_wrap_blob'] ?? null,
            $data['client_wrap_nonce'] ?? null,
            $data['client_wrap_salt'] ?? null,
            $data['client_wrap_kdf'] ?? null,
            isset($data['client_wrap_iters']) ? (int) $data['client_wrap_iters'] : null,
            $data['client_wrap_version'] ?? null
        );
    }

    public function updateUserIdBySub(string $oidcSub, int $userId): void
    {
        $mailboxTable = $this->prefix . 'oidc_mail_sso_mailbox';
        $identityTable = $this->prefix . 'oidc_mail_sso_oidc_user';

        $this->db->query("UPDATE `{$mailboxTable}` SET `user_id` = ?, `updated_at` = NOW() WHERE `oidc_sub` = ?", $userId, $oidcSub);
        $this->db->query("UPDATE `{$identityTable}` SET `user_id` = ?, `updated_at` = NOW() WHERE `oidc_sub` = ?", $userId, $oidcSub);
    }

    public function touchMailboxUsage(string $oidcSub): void
    {
        $table = $this->prefix . 'oidc_mail_sso_mailbox';
        $this->db->query("UPDATE `{$table}` SET `last_used_at` = NOW(), `updated_at` = NOW() WHERE `oidc_sub` = ?", $oidcSub);
    }

    public function setIdentitySeenIp(string $oidcSub, string $ip): void
    {
        $table = $this->prefix . 'oidc_mail_sso_oidc_user';
        $this->db->query("UPDATE `{$table}` SET `last_seen_ip` = ?, `updated_at` = NOW() WHERE `oidc_sub` = ?", $ip, $oidcSub);
    }

    public function incrementFailedAuth(string $oidcSub, int $lockSeconds): void
    {
        $table = $this->prefix . 'oidc_mail_sso_oidc_user';
        $this->db->query(
            "UPDATE `{$table}` SET `failed_auth_count` = `failed_auth_count` + 1, `lock_until` = DATE_ADD(NOW(), INTERVAL ? SECOND), `updated_at` = NOW() WHERE `oidc_sub` = ?",
            $lockSeconds,
            $oidcSub
        );
    }

    public function clearAuthLock(string $oidcSub): void
    {
        $table = $this->prefix . 'oidc_mail_sso_oidc_user';
        $this->db->query(
            "UPDATE `{$table}` SET `failed_auth_count` = 0, `lock_until` = NULL, `updated_at` = NOW() WHERE `oidc_sub` = ?",
            $oidcSub
        );
    }

    public function addAudit(
        string $event,
        string $status,
        ?string $oidcSub,
        ?string $email,
        ?int $userId,
        string $message = '',
        array $meta = []
    ): void {
        $table = $this->prefix . 'oidc_mail_sso_audit_log';
        $jsonMeta = $meta ? json_encode($meta, JSON_UNESCAPED_SLASHES) : null;

        $prevHash = null;
        try {
            $res = $this->db->query("SELECT `row_hash` FROM `{$table}` ORDER BY `id` DESC LIMIT 1");
            $row = $this->db->fetch_assoc($res);
            $prevHash = (string) ($row['row_hash'] ?? '');
            if ($prevHash === '') {
                $prevHash = null;
            }
        } catch (\Throwable $e) {
            $prevHash = null;
        }

        $payload = implode('|', [
            $event,
            $status,
            (string) $oidcSub,
            (string) $email,
            (string) $userId,
            $message,
            (string) $jsonMeta,
            (string) $prevHash,
            (string) microtime(true),
        ]);
        $rowHash = hash('sha256', $payload);

        $this->db->query(
            "INSERT INTO `{$table}` (`event`,`status`,`oidc_sub`,`email`,`user_id`,`message`,`meta_json`,`hash_alg`,`prev_hash`,`row_hash`,`created_at`) VALUES (?,?,?,?,?,?,?,?,?,?,NOW())",
            $event,
            $status,
            $oidcSub,
            $email,
            $userId,
            $message,
            $jsonMeta,
            'sha256',
            $prevHash,
            $rowHash
        );
    }

    public function getAdminOverview(int $limit = 200): array
    {
        $limit = max(1, min($limit, 1000));
        $identityTable = $this->prefix . 'oidc_mail_sso_oidc_user';
        $mailboxTable = $this->prefix . 'oidc_mail_sso_mailbox';

        $sql = "SELECT i.`oidc_sub`, i.`email`, i.`user_id`, i.`is_disabled`, i.`disabled_reason`, i.`failed_auth_count`, i.`lock_until`, i.`last_seen_ip`, i.`last_login_at`, i.`updated_at`,\n"
            . "m.`imap_host`, m.`imap_port`, m.`imap_security`, m.`smtp_host`, m.`smtp_port`, m.`smtp_security`, m.`smtp_auth`, m.`key_id`, m.`last_used_at`\n"
            . "FROM `{$identityTable}` i\n"
            . "LEFT JOIN `{$mailboxTable}` m ON m.`oidc_sub` = i.`oidc_sub`\n"
            . "ORDER BY i.`updated_at` DESC LIMIT " . $limit;

        $res = $this->db->query($sql);
        $rows = [];
        while ($row = $this->db->fetch_assoc($res)) {
            $rows[] = $row;
        }

        return $rows;
    }

    public function getRecentAudit(int $limit = 200): array
    {
        $limit = max(1, min($limit, 1000));
        $table = $this->prefix . 'oidc_mail_sso_audit_log';
        $res = $this->db->query("SELECT * FROM `{$table}` ORDER BY `id` DESC LIMIT " . $limit);
        $rows = [];
        while ($row = $this->db->fetch_assoc($res)) {
            $rows[] = $row;
        }

        return $rows;
    }

    public function getPolicies(array $keys): array
    {
        if (empty($keys)) {
            return [];
        }

        $table = $this->prefix . 'oidc_mail_sso_policy';
        $in = implode(',', array_fill(0, count($keys), '?'));
        $res = $this->db->query("SELECT `policy_key`, `policy_value` FROM `{$table}` WHERE `policy_key` IN ({$in})", ...$keys);
        $out = [];
        while ($row = $this->db->fetch_assoc($res)) {
            $out[(string) $row['policy_key']] = (string) $row['policy_value'];
        }

        return $out;
    }

    public function setPolicy(string $key, string $value): void
    {
        $table = $this->prefix . 'oidc_mail_sso_policy';
        $this->db->query(
            "INSERT INTO `{$table}` (`policy_key`,`policy_value`,`updated_at`) VALUES (?,?,NOW()) ON DUPLICATE KEY UPDATE `policy_value`=VALUES(`policy_value`), `updated_at`=NOW()",
            $key,
            $value
        );
    }

    public function setPolicyIfMissing(string $key, string $value): void
    {
        $table = $this->prefix . 'oidc_mail_sso_policy';
        $this->db->query(
            "INSERT IGNORE INTO `{$table}` (`policy_key`,`policy_value`,`updated_at`) VALUES (?,?,NOW())",
            $key,
            $value
        );
    }

    public function setUserDisabledBySub(string $oidcSub, bool $disabled, string $reason = ''): void
    {
        $identityTable = $this->prefix . 'oidc_mail_sso_oidc_user';
        $this->db->query(
            "UPDATE `{$identityTable}` SET `is_disabled` = ?, `disabled_reason` = ?, `disabled_at` = ?, `updated_at` = NOW() WHERE `oidc_sub` = ?",
            $disabled ? 1 : 0,
            $reason !== '' ? $reason : null,
            $disabled ? date('Y-m-d H:i:s') : null,
            $oidcSub
        );
    }

    public function setUserNoteBySub(string $oidcSub, string $note): void
    {
        $identityTable = $this->prefix . 'oidc_mail_sso_oidc_user';
        $this->db->query(
            "UPDATE `{$identityTable}` SET `admin_note` = ?, `updated_at` = NOW() WHERE `oidc_sub` = ?",
            $note,
            $oidcSub
        );
    }

    public function deleteMappedUserBySub(string $oidcSub): void
    {
        $mailboxTable = $this->prefix . 'oidc_mail_sso_mailbox';
        $identityTable = $this->prefix . 'oidc_mail_sso_oidc_user';

        $this->db->query("DELETE FROM `{$mailboxTable}` WHERE `oidc_sub` = ?", $oidcSub);
        $this->db->query("DELETE FROM `{$identityTable}` WHERE `oidc_sub` = ?", $oidcSub);
    }

    public function clearMailboxBySub(string $oidcSub): void
    {
        $mailboxTable = $this->prefix . 'oidc_mail_sso_mailbox';
        $this->db->query("DELETE FROM `{$mailboxTable}` WHERE `oidc_sub` = ?", $oidcSub);
    }

    public function purgeMappingsForModeSwitch(bool $resetRoundcubeState = true): void
    {
        $mailboxTable = $this->prefix . 'oidc_mail_sso_mailbox';
        $identityTable = $this->prefix . 'oidc_mail_sso_oidc_user';
        $rateTable = $this->prefix . 'oidc_mail_sso_rate_limit';

        $this->db->query("DELETE FROM `{$mailboxTable}`");
        $this->db->query("DELETE FROM `{$identityTable}`");
        $this->db->query("DELETE FROM `{$rateTable}`");

        // Roundcube core session table name is not prefixed.
        try {
            $this->db->query("DELETE FROM `session`");
        } catch (\Throwable $e) {
            // Ignore when session table is not DB-backed.
        }

        if (!$resetRoundcubeState) {
            return;
        }

        // Best-effort reset of local Roundcube user state to force clean re-onboarding.
        $coreTables = [
            $this->prefix . 'users',
            $this->prefix . 'identities',
            $this->prefix . 'contacts',
            $this->prefix . 'contactgroups',
            $this->prefix . 'contactgroupmembers',
            $this->prefix . 'dictionary',
            $this->prefix . 'searches',
            $this->prefix . 'cache',
            $this->prefix . 'cache_index',
            $this->prefix . 'cache_messages',
            $this->prefix . 'cache_shared',
            $this->prefix . 'cache_thread',
        ];

        foreach ($coreTables as $table) {
            try {
                $this->db->query("DELETE FROM `{$table}`");
            } catch (\Throwable $e) {
                // Ignore tables not present in this Roundcube schema.
            }
        }
    }

    public function consumeRateLimit(string $scope, string $subject, int $windowSeconds, int $maxAttempts): bool
    {
        $table = $this->prefix . 'oidc_mail_sso_rate_limit';
        $windowSeconds = max(1, $windowSeconds);
        $maxAttempts = max(1, $maxAttempts);
        $bucket = date('Y-m-d H:i:s', (int) (floor(time() / $windowSeconds) * $windowSeconds));

        // cleanup old buckets (best effort)
        $this->db->query("DELETE FROM `{$table}` WHERE `last_attempt_at` < DATE_SUB(NOW(), INTERVAL 1 DAY)");

        $this->db->query(
            "INSERT INTO `{$table}` (`scope`,`subject`,`window_start`,`attempts`,`last_attempt_at`) VALUES (?,?,?,1,NOW())\n"
            . "ON DUPLICATE KEY UPDATE `attempts`=`attempts`+1, `last_attempt_at`=NOW()",
            $scope,
            $subject,
            $bucket
        );

        $res = $this->db->query(
            "SELECT `attempts` FROM `{$table}` WHERE `scope` = ? AND `subject` = ? AND `window_start` = ? LIMIT 1",
            $scope,
            $subject,
            $bucket
        );
        $row = $this->db->fetch_assoc($res);
        $attempts = (int) ($row['attempts'] ?? 0);

        return $attempts <= $maxAttempts;
    }

    private function indexExists(string $tableName, string $indexName): bool
    {
        try {
            $res = $this->db->query(
                "SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ? LIMIT 1",
                $tableName,
                $indexName
            );
            $row = $this->db->fetch_assoc($res);
            return !empty($row);
        } catch (\Throwable $e) {
            return false;
        }
    }
}
