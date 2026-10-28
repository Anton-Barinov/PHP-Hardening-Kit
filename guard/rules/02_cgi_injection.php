<?php
/**
 * Vector 2: CGI Argument Injection & Unicode Best-Fit Protection
 * Targets: CVE-2024-4577, CVE-2012-1823, Query Parameter Smuggling
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

return function($guard) {
    // Check raw query string from SERVER superglobals
    $queryString = isset($_SERVER['QUERY_STRING']) ? (string)$_SERVER['QUERY_STRING'] : '';
    $requestUri  = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '';

    if ($queryString === '' && $requestUri === '') {
        return null;
    }

    // Exploit vector: Windows Best-Fit mapping (CVE-2024-4577)
    // Attackers send %ad or \xad (soft hyphen) which Windows maps to ASCII '-' (0x2D)
    if (preg_match('/(%ad|%u00ad|\xad)/i', $requestUri) || preg_match('/(%ad|%u00ad|\xad)/i', $queryString)) {
        return [
            'rule'    => 'VEC2_CGI_BESTFIT_INJECTION',
            'detail'  => 'Soft-hyphen / Unicode Best-Fit mapping exploit attempt detected (CVE-2024-4577)',
            'payload' => substr($queryString !== '' ? $queryString : $requestUri, 0, 128),
        ];
    }

    // Exploit vector: CGI command-line argument injection (CVE-2012-1823 / CVE-2024-4577)
    // Attackers pass switches like -d, -s, -w, -f, -n, -c directly in query string
    // e.g., ?+-d+allow_url_include%3d1 or ?-d+auto_prepend_file=php://input
    $patterns = [
        '/(?:^|&|\+|\s)-(?:d|s|w|f|n|c|b|-define|-syntax-check)\b/i',
        '/(?:^|&|\+|\s)%2d(?:d|s|w|f|n|c|b)/i',
        '/(?:allow_url_include|auto_prepend_file|auto_append_file|disable_functions)\s*=/i',
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $queryString) || preg_match($pattern, urldecode($queryString))) {
            return [
                'rule'    => 'VEC2_CGI_ARGUMENT_INJECTION',
                'detail'  => 'CGI command-line parameter injection attempt detected',
                'payload' => substr($queryString, 0, 128),
            ];
        }
    }

    // Inspect argv in web environments (FastCGI/mod_php/FPM should never have argv argument injection)
    if (isset($_SERVER['argv']) && is_array($_SERVER['argv']) && php_sapi_name() !== 'cli') {
        foreach ($_SERVER['argv'] as $arg) {
            if (is_string($arg) && preg_match('/^-(?:d|s|w|f|n|c)/i', ltrim($arg))) {
                return [
                    'rule'    => 'VEC2_CGI_ARGV_TAMPERING',
                    'detail'  => 'Dangerous PHP CLI switch present in web SAPI argv',
                    'payload' => substr($arg, 0, 128),
                ];
            }
        }
    }

    return null;
};
