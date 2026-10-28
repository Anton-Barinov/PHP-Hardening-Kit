<?php
/**
 * Vector 3: PHP Filter Chains & Stream Wrapper Abuse Protection
 * Targets: CVE-2024-2961 (iconv buffer overflow RCE), LFI wrapper exploits
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

return function($guard) {
    $inspect = function($value, &$ruleOut) use (&$inspect) {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                if ($res = $inspect($k, $ruleOut)) return $res;
                if ($res = $inspect($v, $ruleOut)) return $res;
            }
            return null;
        }

        if (!is_string($value) || strlen($value) < 6) {
            return null;
        }

        $decoded = urldecode($value);

        // Exploit vector: CVE-2024-2961 & PHP Filter Chain Generator
        // Long chains of convert.iconv.* or convert.base64-decode used to trigger heap corruption or generate arbitrary content
        if (stripos($decoded, 'php://filter') !== false) {
            // Count filter operations: legit apps rarely chain more than 2 filters
            $filterCount = substr_count(strtolower($decoded), 'convert.iconv.') 
                         + substr_count(strtolower($decoded), 'convert.base64')
                         + substr_count(strtolower($decoded), 'zlib.deflate')
                         + substr_count(strtolower($decoded), 'zlib.inflate')
                         + substr_count(strtolower($decoded), 'string.rot13')
                         + substr_count(strtolower($decoded), 'string.strip_tags');

            if ($filterCount >= 3) {
                $ruleOut = [
                    'rule'    => 'VEC3_FILTER_CHAIN_EXPLOIT',
                    'detail'  => 'PHP filter chain exploit sequence detected (depth: ' . $filterCount . ')',
                    'payload' => substr($decoded, 0, 128),
                ];
                return $ruleOut;
            }

            // Specific check for dangerous iconv charsets targeted in CVE-2024-2961
            if (preg_match('/convert\.iconv\.(?:ISO[-_]?2022[-_]?CN[-_]?EXT|UTF[-_]?7|CP1361)/i', $decoded)) {
                $ruleOut = [
                    'rule'    => 'VEC3_ICONV_BUFFER_OVERFLOW',
                    'detail'  => 'Dangerous iconv charset exploit signature detected (CVE-2024-2961)',
                    'payload' => substr($decoded, 0, 128),
                ];
                return $ruleOut;
            }
        }

        // Exploit vector: Arbitrary code execution via remote stream wrappers in user input
        if (preg_match('/(?:expect|input|data):\/\//i', $decoded)) {
            // Check if wrapper is in suspicious context (e.g. data://text/plain;base64)
            if (preg_match('/data:(?:text\/plain|application\/octet-stream)[^,]*;base64/i', $decoded)) {
                $ruleOut = [
                    'rule'    => 'VEC3_DATA_WRAPPER_EXECUTION',
                    'detail'  => 'data:// stream wrapper with base64 payload detected',
                    'payload' => substr($decoded, 0, 128),
                ];
                return $ruleOut;
            }
            if (stripos($decoded, 'expect://') !== false) {
                $ruleOut = [
                    'rule'    => 'VEC3_EXPECT_WRAPPER_EXECUTION',
                    'detail'  => 'expect:// stream wrapper detected',
                    'payload' => substr($decoded, 0, 128),
                ];
                return $ruleOut;
            }
        }

        return null;
    };

    $result = null;

    // Check GET, POST, COOKIE inputs
    if (!empty($_GET) && ($res = $inspect($_GET, $result))) return $res;
    if (!empty($_POST) && ($res = $inspect($_POST, $result))) return $res;
    if (!empty($_COOKIE) && ($res = $inspect($_COOKIE, $result))) return $res;

    // Check raw request URI
    if (isset($_SERVER['REQUEST_URI'])) {
        if ($res = $inspect($_SERVER['REQUEST_URI'], $result)) return $res;
    }

    return null;
};
