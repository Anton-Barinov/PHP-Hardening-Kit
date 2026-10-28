<?php
/**
 * PHP Hardening Kit - Configuration Template
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 * https://github.com/Anton-Barinov/PHP-Hardening-Kit
 * 
 * Works on PHP 5.4 to 8.4+.
 */

return [
    // Operational mode:
    // 'block'   - Terminate suspicious requests with HTTP 403 / alert (Recommended)
    // 'monitor' - Log suspicious requests only (Dry-run / Audit mode)
    // 'off'     - Completely disable runtime inspection
    'mode' => 'block',

    // Rules enabled
    'rules' => [
        'php2shell'           => true, // Vector 1: Multipart OOM & upload progress UAF/RCE
        'cgi_injection'       => true, // Vector 2: CGI argument injection & Windows best-fit (CVE-2024-4577, CVE-2012-1823)
        'filter_chains'       => true, // Vector 3: php://filter iconv chain RCE (CVE-2024-2961) & wrapper exploits
        'phar_deserialization'=> true, // Vector 4: phar:// wrapper POP gadget attacks & object injection
        'command_mail_abuse'  => true, // Vector 5: mail() parameter -X injection & null-byte poisoning
    ],

    // Logging configuration
    'logging' => [
        'enabled'      => true,
        'handler'      => 'file', // 'file', 'syslog', 'error_log', or 'none'
        'log_file'     => __DIR__ . '/../logs/security.log',
        'log_format'   => 'json', // 'json' or 'text'
        'log_payload'  => true,   // Include truncated sanitized attack payload
        'max_payload'  => 512,    // Maximum payload bytes to record in log
    ],

    // Client IP detection (set to true if behind Cloudflare, AWS ALB, Nginx reverse proxy)
    'trusted_proxies' => false, // array of CIDR/IP strings, or true to trust X-Forwarded-For

    // Custom response when an attack is blocked
    'response' => [
        'http_status'   => 403,
        'content_type'  => 'text/html; charset=UTF-8',
        'body'          => '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2>403 Forbidden</h2><p>Request rejected by security policy.</p><p><small>Incident ID: {{INCIDENT_ID}}</small></p></body></html>',
    ],

    // Path or IP Whitelist (exceptions for trusted dev/admin environments)
    'whitelist' => [
        'ips'   => [], // e.g. ['127.0.0.1', '192.168.1.100']
        'paths' => [], // e.g. ['/admin/legacy-upload.php']
    ],
];
