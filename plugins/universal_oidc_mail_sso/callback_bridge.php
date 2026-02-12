<?php

declare(strict_types=1);

// OIDC Provider form_post bridge:
// Accept POST/GET callback and convert to Roundcube login callback URL via GET.
// This avoids Roundcube "invalid session" on cross-site POST callback.

$code = isset($_REQUEST['code']) ? (string) $_REQUEST['code'] : '';
$state = isset($_REQUEST['state']) ? (string) $_REQUEST['state'] : '';
$error = isset($_REQUEST['error']) ? (string) $_REQUEST['error'] : '';
$errorDesc = isset($_REQUEST['error_description']) ? (string) $_REQUEST['error_description'] : '';

$params = [
    '_task' => 'login',
    '_action' => 'plugin.universal_oidc_mail_sso_callback',
];

if ($code !== '') {
    $params['code'] = $code;
}
if ($state !== '') {
    $params['state'] = $state;
}
if ($error !== '') {
    $params['error'] = $error;
}
if ($errorDesc !== '') {
    $params['error_description'] = $errorDesc;
}

$target = '/?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
header('Location: ' . $target, true, 302);
exit;

