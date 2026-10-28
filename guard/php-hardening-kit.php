<?php
/**
 * PHP-Hardening-Kit - Zero-Dependency Runtime WAF & Hotfix Engine
 * 
 * Protects PHP 5.4 to 8.4+ environments against Top-5 critical vulnerabilities
 * without modifying CMS or application codebase.
 * 
 * Maintained by Anton Barinov
 * https://github.com/Anton-Barinov/PHP-Hardening-Kit
 * 
 * License: MIT
 */

if (defined('PHP_HARDENING_KIT_ACTIVE')) {
    return;
}
define('PHP_HARDENING_KIT_ACTIVE', true);
define('PHP_HARDENING_KIT_VERSION', '1.0.0');

class PhpHardeningGuard
{
    private static $instance = null;
    private $config = [];
    private $startTime = 0;

    public static function boot()
    {
        if (self::$instance === null) {
            self::$instance = new self();
            self::$instance->run();
        }
        return self::$instance;
    }

    public function __construct()
    {
        $this->startTime = microtime(true);
        $this->loadConfig();
    }

    private function loadConfig()
    {
        $customConfig = __DIR__ . '/config.php';
        $sampleConfig = __DIR__ . '/config.sample.php';

        if (file_exists($customConfig)) {
            $this->config = require $customConfig;
        } elseif (file_exists($sampleConfig)) {
            $this->config = require $sampleConfig;
        } else {
            // Built-in fail-safe defaults
            $this->config = [
                'mode'  => 'block',
                'rules' => [
                    'php2shell'            => true,
                    'cgi_injection'        => true,
                    'filter_chains'        => true,
                    'phar_deserialization' => true,
                    'command_mail_abuse'   => true,
                ],
                'logging' => [
                    'enabled'     => true,
                    'handler'     => 'error_log',
                    'log_format'  => 'json',
                    'log_payload' => true,
                    'max_payload' => 512,
                ],
                'trusted_proxies' => false,
                'response' => [
                    'http_status'  => 403,
                    'content_type' => 'text/html; charset=UTF-8',
                    'body'         => '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2>403 Forbidden</h2><p>Request blocked by PHP-Hardening-Kit.</p><p><small>Incident ID: {{INCIDENT_ID}}</small></p></body></html>',
                ],
                'whitelist' => [
                    'ips'   => [],
                    'paths' => [],
                ],
            ];
        }
    }

    public function run()
    {
        if (isset($this->config['mode']) && $this->config['mode'] === 'off') {
            return;
        }

        // Whitelist checks
        if ($this->isWhitelisted()) {
            return;
        }

        // Fast Host Header & Request Smuggling validation
        $hostViolation = $this->validateHostHeader();
        if ($hostViolation !== null) {
            $this->handleViolation($hostViolation);
            return;
        }

        $rules = [
            'php2shell'            => __DIR__ . '/rules/01_php2shell.php',
            'cgi_injection'        => __DIR__ . '/rules/02_cgi_injection.php',
            'filter_chains'        => __DIR__ . '/rules/03_filter_chains.php',
            'phar_deserialization' => __DIR__ . '/rules/04_phar_deserialization.php',
            'command_mail_abuse'   => __DIR__ . '/rules/05_command_mail_abuse.php',
        ];

        foreach ($rules as $ruleName => $ruleFile) {
            if (isset($this->config['rules'][$ruleName]) && !$this->config['rules'][$ruleName]) {
                continue;
            }

            if (!file_exists($ruleFile)) {
                continue;
            }

            $checker = require $ruleFile;
            if (is_callable($checker)) {
                $violation = call_user_func($checker, $this);
                if ($violation !== null && is_array($violation)) {
                    $this->handleViolation($violation);
                    break;
                }
            }
        }
    }

    public function validateHostHeader()
    {
        if (!isset($_SERVER['HTTP_HOST'])) {
            return null;
        }

        $host = (string)$_SERVER['HTTP_HOST'];
        if ($host === '') {
            return null;
        }

        // Reject newlines, carriage returns, null bytes (HTTP response splitting & request smuggling)
        if (preg_match('/[\r\n\0]/', $host)) {
            return [
                'rule'    => 'HOST_HEADER_INJECTION',
                'detail'  => 'Newline or null byte detected in HTTP Host header',
                'payload' => substr($host, 0, 64),
            ];
        }

        // Reject invalid host format (must be alphanumeric, dots, hyphens, and optional port :8080)
        if (!preg_match('/^[a-zA-Z0-9.\-_]+(?::\d{1,5})?$/', $host)) {
            return [
                'rule'    => 'MALFORMED_HOST_HEADER',
                'detail'  => 'Illegal characters in HTTP Host header',
                'payload' => substr($host, 0, 64),
            ];
        }

        return null;
    }

    public function getClientIp()
    {
        $remoteAddr = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        if (!empty($this->config['trusted_proxies'])) {
            $forwarded = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : null;
            if ($forwarded) {
                $ips = explode(',', $forwarded);
                $client = trim($ips[0]);
                if (filter_var($client, FILTER_VALIDATE_IP)) {
                    return $client;
                }
            }
        }

        return $remoteAddr;
    }

    private function isWhitelisted()
    {
        $ip = $this->getClientIp();
        if (!empty($this->config['whitelist']['ips']) && is_array($this->config['whitelist']['ips'])) {
            if (in_array($ip, $this->config['whitelist']['ips'], true)) {
                return true;
            }
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        if (!empty($this->config['whitelist']['paths']) && is_array($this->config['whitelist']['paths'])) {
            foreach ($this->config['whitelist']['paths'] as $pattern) {
                if (strpos($uri, $pattern) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    private function handleViolation($violation)
    {
        $incidentId = 'phk_' . substr(md5(uniqid(mt_rand(), true)), 0, 12);
        $clientIp   = $this->getClientIp();
        $uri        = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'CLI';
        $method     = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'CLI';
        $userAgent  = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '-';

        $logEntry = [
            'timestamp'   => date('Y-m-d H:i:s'),
            'incident_id' => $incidentId,
            'client_ip'   => $clientIp,
            'method'      => $method,
            'uri'         => $uri,
            'user_agent'  => $userAgent,
            'rule'        => isset($violation['rule']) ? $violation['rule'] : 'UNKNOWN',
            'detail'      => isset($violation['detail']) ? $violation['detail'] : '',
            'action'      => isset($this->config['mode']) ? $this->config['mode'] : 'block',
        ];

        if (!empty($this->config['logging']['log_payload']) && isset($violation['payload'])) {
            $maxLen = isset($this->config['logging']['max_payload']) ? (int)$this->config['logging']['max_payload'] : 512;
            $payload = (string)$violation['payload'];
            // Sanitize payload for logging (avoid breaking log lines)
            $logEntry['payload'] = substr(addcslashes($payload, "\0..\37"), 0, $maxLen);
        }

        $this->log($logEntry);

        if (isset($this->config['mode']) && $this->config['mode'] === 'monitor') {
            return; // Dry-run / audit mode: do not terminate request
        }

        // Block & terminate
        $status = isset($this->config['response']['http_status']) ? (int)$this->config['response']['http_status'] : 403;
        $ct     = isset($this->config['response']['content_type']) ? $this->config['response']['content_type'] : 'text/html; charset=UTF-8';
        $body   = isset($this->config['response']['body']) ? $this->config['response']['body'] : '403 Forbidden';

        $body = str_replace('{{INCIDENT_ID}}', $incidentId, $body);

        if (!headers_sent()) {
            if (function_exists('http_response_code')) {
                http_response_code($status);
            } else {
                header('HTTP/1.1 ' . $status . ' Forbidden', true, $status);
            }
            header('Content-Type: ' . $ct);
            header('X-Protected-By: PHP-Hardening-Kit/' . PHP_HARDENING_KIT_VERSION);
            header('X-Incident-ID: ' . $incidentId);
        }

        echo $body;
        exit(1);
    }

    private function log($entry)
    {
        if (empty($this->config['logging']['enabled'])) {
            return;
        }

        $handler = isset($this->config['logging']['handler']) ? $this->config['logging']['handler'] : 'error_log';
        $format  = isset($this->config['logging']['log_format']) ? $this->config['logging']['log_format'] : 'json';

        if ($format === 'json') {
            $line = json_encode($entry);
        } else {
            $line = sprintf(
                "[%s] [%s] [%s] %s %s - Rule: %s (%s)",
                $entry['timestamp'],
                $entry['incident_id'],
                $entry['client_ip'],
                $entry['method'],
                $entry['uri'],
                $entry['rule'],
                $entry['detail']
            );
        }

        if ($handler === 'file') {
            $logFile = isset($this->config['logging']['log_file']) ? $this->config['logging']['log_file'] : null;
            if ($logFile) {
                $dir = dirname($logFile);
                if (!is_dir($dir)) {
                    @mkdir($dir, 0750, true);
                }
                @file_put_contents($logFile, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
                return;
            }
        }

        if ($handler === 'syslog') {
            openlog('php-hardening-kit', LOG_PID | LOG_ODELAY, LOG_AUTH);
            syslog(LOG_WARNING, $line);
            closelog();
            return;
        }

        // Fallback: error_log
        error_log('[PHP-Hardening-Kit] ' . $line);
    }
}

// Auto-boot if included via auto_prepend_file or direct include
PhpHardeningGuard::boot();
