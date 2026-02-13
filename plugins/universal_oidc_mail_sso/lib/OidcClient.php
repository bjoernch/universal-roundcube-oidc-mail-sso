<?php

declare(strict_types=1);

namespace UniversalOidcMailSso\Lib;

use RuntimeException;

class OidcClient
{
    /** @var callable|null */
    private $httpHandler;

    private array $config;
    private JwksValidator $validator;

    public function __construct(array $config, ?callable $httpHandler = null, ?JwksValidator $validator = null)
    {
        $this->config = $config;
        $this->httpHandler = $httpHandler;
        $this->validator = $validator ?: new JwksValidator();
    }

    public function discover(): array
    {
        $issuer = rtrim($this->config['issuer'], '/');
        $discoveryUrl = $issuer . '/.well-known/openid-configuration';
        $doc = $this->httpJson('GET', $discoveryUrl);

        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'issuer'] as $key) {
            if (empty($doc[$key])) {
                throw new RuntimeException('OIDC discovery document missing: ' . $key);
            }
        }

        return $doc;
    }

    public function buildAuthorizationUrl(array $discovery, string $state, string $nonce, string $codeChallenge): string
    {
        $scope = trim((string) ($this->config['scope'] ?? 'openid email profile groups'));
        if ($scope === '') {
            $scope = 'openid email profile groups';
        }

        $params = [
            'client_id' => $this->config['client_id'],
            'redirect_uri' => $this->config['redirect_uri'],
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => $scope,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];

        return $discovery['authorization_endpoint'] . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    public function exchangeCode(array $discovery, string $code, string $codeVerifier): array
    {
        $postBase = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config['redirect_uri'],
            'client_id' => $this->config['client_id'],
            'code_verifier' => $codeVerifier,
        ];

        // Try client_secret_post first (common default)
        $post = $postBase;
        if (!empty($this->config['client_secret'])) {
            $post['client_secret'] = $this->config['client_secret'];
        }

        try {
            $token = $this->httpJson('POST', $discovery['token_endpoint'], [
                'headers' => ['Content-Type: application/x-www-form-urlencoded'],
                'body' => http_build_query($post, '', '&', PHP_QUERY_RFC3986),
            ]);
        } catch (RuntimeException $e) {
            // Fallback to client_secret_basic for providers requiring HTTP Basic auth.
            if (empty($this->config['client_secret']) || strpos($e->getMessage(), 'HTTP status 400') === false) {
                throw $e;
            }

            $basic = base64_encode($this->config['client_id'] . ':' . $this->config['client_secret']);
            $token = $this->httpJson('POST', $discovery['token_endpoint'], [
                'headers' => [
                    'Content-Type: application/x-www-form-urlencoded',
                    'Authorization: Basic ' . $basic,
                ],
                'body' => http_build_query($postBase, '', '&', PHP_QUERY_RFC3986),
            ]);
        }

        if (empty($token['id_token'])) {
            throw new RuntimeException('Token response missing id_token.');
        }

        return $token;
    }

    public function validateIdToken(array $discovery, string $idToken, string $nonce): array
    {
        $jwks = $this->httpJson('GET', $discovery['jwks_uri']);

        return $this->validator->validateIdToken($idToken, $jwks, [
            'issuer' => $discovery['issuer'],
            'client_id' => $this->config['client_id'],
            'nonce' => $nonce,
        ]);
    }

    public function fetchUserinfo(array $discovery, string $accessToken): array
    {
        if (empty($discovery['userinfo_endpoint'])) {
            return [];
        }

        return $this->httpJson('GET', $discovery['userinfo_endpoint'], [
            'headers' => [
                'Authorization: Bearer ' . $accessToken,
            ],
        ]);
    }

    public function buildEndSessionUrl(array $discovery, string $idTokenHint, string $postLogoutRedirectUri = ''): string
    {
        $endpoint = (string) ($discovery['end_session_endpoint'] ?? '');
        if ($endpoint === '') {
            return '';
        }

        $params = [
            'id_token_hint' => $idTokenHint,
        ];

        if ($postLogoutRedirectUri !== '') {
            $params['post_logout_redirect_uri'] = $postLogoutRedirectUri;
            if (!empty($this->config['client_id'])) {
                $params['client_id'] = (string) $this->config['client_id'];
            }
        }

        return $endpoint . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    private function httpJson(string $method, string $url, array $options = []): array
    {
        $body = $this->http($method, $url, $options);
        $json = json_decode($body, true);

        if (!is_array($json)) {
            throw new RuntimeException('Invalid JSON from ' . $url);
        }

        return $json;
    }

    private function http(string $method, string $url, array $options = []): string
    {
        if ($this->httpHandler) {
            return (string) call_user_func($this->httpHandler, $method, $url, $options);
        }

        if (!function_exists('curl_init')) {
            throw new RuntimeException('cURL extension is required for OIDC HTTP requests.');
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new RuntimeException('Unable to initialize HTTP client.');
        }

        $headers = $options['headers'] ?? [];
        $body = $options['body'] ?? null;

        $curlOptions = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_FOLLOWLOCATION => false,
        ];

        if (strtoupper($method) === 'POST') {
            $curlOptions[CURLOPT_POST] = true;
        } else {
            $curlOptions[CURLOPT_CUSTOMREQUEST] = $method;
        }

        curl_setopt_array($ch, $curlOptions);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            throw new RuntimeException('HTTP request failed: ' . $err);
        }

        if ($status < 200 || $status >= 300) {
            $snippet = trim((string) $response);
            if (strlen($snippet) > 400) {
                $snippet = substr($snippet, 0, 400) . '...';
            }

            throw new RuntimeException('HTTP status ' . $status . ' from ' . $url . ' body=' . $snippet);
        }

        return $response;
    }
}
