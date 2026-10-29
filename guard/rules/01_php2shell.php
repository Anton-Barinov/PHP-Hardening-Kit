<?php
/**
 * Vector 1: php2shell & Multipart Upload Protection
 * Targets: CVE-2026-109618, CVE-2026-109619, CVE-2026-115560
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

return function($guard) {
    // 1. Proactive runtime hardening for session upload progress
    // If running an unpatched or EOL version where upload_progress is enabled,
    // enforce safe default at runtime unless explicitly marked as C-patched.
    if (ini_get('session.upload_progress.enabled') && !defined('PHP_HARDENING_KIT_C_PATCHED')) {
        $v = PHP_VERSION_ID;
        // Check if version is within known vulnerable ranges without upstream fixes
        if ($v < 80235 || ($v >= 80300 && $v < 80336) || ($v >= 80400 && $v < 80427) || ($v >= 80500 && $v < 80512)) {
            @ini_set('session.upload_progress.enabled', '0');
        }
    }

    // 2. Inspect multipart request headers & POST body for upload_progress exploitation
    $progressName = ini_get('session.upload_progress.name');
    if (!$progressName) {
        $progressName = 'PHP_SESSION_UPLOAD_PROGRESS';
    }

    if (isset($_POST[$progressName])) {
        $val = (string)$_POST[$progressName];

        // Exploit vector: Null bytes, excessive length (OOM trigger), or session serializer injection characters
        if (strlen($val) > 256) {
            return [
                'rule'    => 'VEC1_PHP2SHELL_EXCESSIVE_KEY_LENGTH',
                'detail'  => 'Upload progress key length exceeds safe limit (' . strlen($val) . ' bytes)',
                'payload' => substr($val, 0, 128),
            ];
        }

        // Exploit vector: Serializer delimiters & control characters used to achieve RCE via session deserialization
        if (preg_match('/[\x00-\x1F\x7F|;!]/', $val)) {
            return [
                'rule'    => 'VEC1_PHP2SHELL_SERIALIZER_INJECTION',
                'detail'  => 'Malicious delimiter or control character in upload progress identifier',
                'payload' => $val,
            ];
        }
    }

    // 3. Inspect Content-Type for malformed multipart boundaries
    if (isset($_SERVER['CONTENT_TYPE']) && stripos($_SERVER['CONTENT_TYPE'], 'multipart/') !== false) {
        $ct = $_SERVER['CONTENT_TYPE'];
        if (preg_match('/boundary\s*=\s*(.+)$/i', $ct, $matches)) {
            $rawBoundary = $matches[1];
            // RFC 2046 boundary validation: reject shell metacharacters, separators, null bytes, newlines
            if (preg_match('/[;\$`|&><\r\n\0]/', $rawBoundary) || strlen($rawBoundary) > 256) {
                return [
                    'rule'    => 'VEC1_MALFORMED_MULTIPART_BOUNDARY',
                    'detail'  => 'Malicious characters or shell separators detected in multipart boundary',
                    'payload' => substr($rawBoundary, 0, 64),
                ];
            }
        }
    }

    // 4. Inspect filenames in $_FILES for null byte injection / path traversal
    if (!empty($_FILES)) {
        foreach ($_FILES as $field => $data) {
            $names = isset($data['name']) ? (array)$data['name'] : [];
            foreach ($names as $filename) {
                if (!is_string($filename)) {
                    continue;
                }
                // Check for null bytes in uploaded filename
                if (strpos($filename, "\0") !== false || stripos($filename, '%00') !== false) {
                    return [
                        'rule'    => 'VEC1_NULL_BYTE_FILENAME',
                        'detail'  => 'Null byte detected in uploaded filename',
                        'payload' => $filename,
                    ];
                }
                // Check for directory traversal sequences in uploaded filename
                if (strpos($filename, '..') !== false || strpos($filename, '/') !== false || strpos($filename, '\\') !== false) {
                    return [
                        'rule'    => 'VEC1_UPLOAD_PATH_TRAVERSAL',
                        'detail'  => 'Directory traversal sequence detected in uploaded filename',
                        'payload' => substr($filename, 0, 64),
                    ];
                }
            }
        }
    }

    return null;
};
