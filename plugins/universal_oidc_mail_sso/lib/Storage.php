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

    public function upsertIdentity(string $oidcSub, string $email, ?int $userId = null): void
    {
        $table = $this->prefix . 'oidc_mail_sso_oidc_user';
        $sql = "INSERT INTO `{$table}` (`user_id`, `oidc_sub`, `email`, `is_disabled`, `last_login_at`, `created_at`, `updated_at`)\n"
            . "VALUES (?, ?, ?, ?, NOW(), NOW(), NOW())\n"
            . "ON DUPLICATE KEY UPDATE `email` = VALUES(`email`), `last_login_at` = NOW(), `updated_at` = NOW(), `user_id` = COALESCE(VALUES(`user_id`), `user_id`)";

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

    public function upsertMailbox(array $data): void
    {
        $table = $this->prefix . 'oidc_mail_sso_mailbox';
        $sql = "INSERT INTO `{$table}`\n"
            . "(`user_id`,`oidc_sub`,`email`,`imap_host`,`imap_port`,`imap_security`,`smtp_host`,`smtp_port`,`smtp_security`,`smtp_auth`,`smtp_user`,`password_enc`,`enc_alg`,`enc_nonce`,`created_at`,`updated_at`)\n"
            . "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NOW(),NOW())\n"
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
            $data['enc_nonce']
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

        $this->db->query(
            "INSERT INTO `{$table}` (`event`,`status`,`oidc_sub`,`email`,`user_id`,`message`,`meta_json`,`created_at`) VALUES (?,?,?,?,?,?,?,NOW())",
            $event,
            $status,
            $oidcSub,
            $email,
            $userId,
            $message,
            $jsonMeta
        );
    }

    public function getAdminOverview(int $limit = 200): array
    {
        $limit = max(1, min($limit, 1000));
        $identityTable = $this->prefix . 'oidc_mail_sso_oidc_user';
        $mailboxTable = $this->prefix . 'oidc_mail_sso_mailbox';

        $sql = "SELECT i.`oidc_sub`, i.`email`, i.`user_id`, i.`is_disabled`, i.`last_login_at`, i.`updated_at`,\n"
            . "m.`imap_host`, m.`imap_port`, m.`imap_security`, m.`smtp_host`, m.`smtp_port`, m.`smtp_security`, m.`smtp_auth`, m.`last_used_at`\n"
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

    public function setUserDisabledBySub(string $oidcSub, bool $disabled): void
    {
        $identityTable = $this->prefix . 'oidc_mail_sso_oidc_user';
        $this->db->query(
            "UPDATE `{$identityTable}` SET `is_disabled` = ?, `updated_at` = NOW() WHERE `oidc_sub` = ?",
            $disabled ? 1 : 0,
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
}
