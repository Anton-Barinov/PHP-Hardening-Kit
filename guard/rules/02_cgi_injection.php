<?php
/**
 * Vector 2: CGI Argument Injection & Unicode Best-Fit Protection
 * Targets: CVE-2024-4577, CVE-2012-1823, Query Parameter Smuggling & Overlong UTF-8
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

return function($guard) {
    // Check raw query string, URI, and rewrite/original headers from SERVER superglobals
    $queryString = isset($_SERVER['QUERY_STRING']) ? (string)$_SERVER['QUERY_STRING'] : '';
    $requestUri  = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '';
    $xOrigUrl    = isset($_SERVER['HTTP_X_ORIGINAL_URL']) ? (string)$_SERVER['HTTP_X_ORIGINAL_URL'] : '';
    $xRewriteUrl = isset($_SERVER['HTTP_X_REWRITE_URL']) ? (string)$_SERVER['HTTP_X_REWRITE_URL'] : '';

    if ($queryString === '' && $requestUri === '' && $xOrigUrl === '' && $xRewriteUrl === '') {
        return null;
    }

    $rawTarget = $queryString . ' ' . $requestUri . ' ' . $xOrigUrl . ' ' . $xRewriteUrl;

    // 1. Exploit vector: Windows Best-Fit mapping (CVE-2024-4577)
    // Attackers send %ad or \xad (soft hyphen) or Unicode variations which Windows maps to ASCII '-' (0x2D)
    if (preg_match('/(%ad|%u00ad|\xad)/i', $rawTarget)) {
        return [
            'rule'    => 'VEC2_CGI_BESTFIT_INJECTION',
            'detail'  => 'Soft-hyphen / Unicode Best-Fit mapping exploit attempt detected (CVE-2024-4577)',
            'payload' => substr($rawTarget, 0, 128),
        ];
    }

    // 2. Overlong UTF-8 & Unicode traversal bypasses (%c0%af, %c1%9c, %u2215)
    if (preg_match('/(%c0%af|%c1%9c|%c0%2f|%c0%5c|%u2215|%u2216)/i', $rawTarget)) {
        return [
            'rule'    => 'VEC2_OVERLONG_UTF8_TRAVERSAL',
            'detail'  => 'Overlong UTF-8 or Unicode path traversal bypass attempt detected',
            'payload' => substr($rawTarget, 0, 128),
        ];
    }

    // 3. Exploit vector: CGI command-line argument injection (CVE-2012-1823 / CVE-2024-4577)
    // Attackers pass switches like -d, -s, -w, -f, -n, -c directly in query string
    $patterns = [
        '/(?:^|&|\+|\s)-(?:d|s|w|f|n|c|b|-define|-syntax-check)\b/i',
        '/(?:^|&|\+|\s)%2d(?:d|s|w|f|n|c|b)/i',
        '/(?:allow_url_include|auto_prepend_file|auto_append_file|disable_functions)\s*=/i',
        '/(?:auto_prepend_file|auto_append_file)\s*%3d/i',
    ];

    $targetToScan = $queryString . ' ' . $xOrigUrl . ' ' . $xRewriteUrl;
    $decoded1 = urldecode($targetToScan);
    $decoded2 = urldecode($decoded1);

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $targetToScan) || preg_match($pattern, $decoded1) || preg_match($pattern, $decoded2)) {
            return [
                'rule'    => 'VEC2_CGI_ARGUMENT_INJECTION',
                'detail'  => 'CGI command-line parameter injection attempt detected',
                'payload' => substr($targetToScan, 0, 128),
            ];
        }
    }

    // 4. Inspect argv in web environments
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
