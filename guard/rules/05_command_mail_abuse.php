<?php
/**
 * Vector 5: Dangerous Function Abuse, Mail Parameter RCE & Null-Byte Protection
 * Targets: CVE-2016-10033, CVE-2016-10045 (mail() -X RCE), Null-byte poisoning, Subshell injection
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

return function($guard) {
    // 1. Check for Null-Byte poisoning (%00 / \0) across all input vectors
    $checkNullByte = function($value, &$ruleOut) use (&$checkNullByte) {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                if ($res = $checkNullByte($k, $ruleOut)) return $res;
                if ($res = $checkNullByte($v, $ruleOut)) return $res;
            }
            return null;
        }

        if (is_string($value)) {
            $norm = $value;
            for ($p = 0; $p < 3; $p++) {
                if (strpos($norm, '%') === false) break;
                $prev = $norm;
                $norm = rawurldecode($norm);
                if ($norm === $prev) break;
            }
            if (strpos($value, "\0") !== false || stripos($value, '%00') !== false || strpos($norm, "\0") !== false || stripos($norm, '%00') !== false) {
                $ruleOut = [
                    'rule'    => 'VEC5_NULL_BYTE_POISONING',
                    'detail'  => 'Null byte (%00) path truncation attempt detected',
                    'payload' => substr($value, 0, 64),
                ];
                return $ruleOut;
            }
        }
        return null;
    };

    $nullResult = null;
    if (!empty($_GET) && ($res = $checkNullByte($_GET, $nullResult))) return $res;
    if (!empty($_POST) && ($res = $checkNullByte($_POST, $nullResult))) return $res;
    if (!empty($_COOKIE) && ($res = $checkNullByte($_COOKIE, $nullResult))) return $res;

    // 2. Exploit vector: Shellshock in User-Agent, Referer, or X-Forwarded-For headers
    $headersToCheck = ['HTTP_USER_AGENT', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR'];
    foreach ($headersToCheck as $h) {
        if (isset($_SERVER[$h]) && is_string($_SERVER[$h])) {
            $val = $_SERVER[$h];
            if (strpos($val, '() {') !== false && strpos($val, '};') !== false) {
                return [
                    'rule'    => 'VEC5_SHELLSHOCK_ATTEMPT',
                    'detail'  => 'Bash Shellshock injection signature detected in header ' . $h,
                    'payload' => substr($val, 0, 128),
                ];
            }
        }
    }

    // 3. Exploit vector: mail() sendmail 5th parameter injection (CVE-2016-10033 / CVE-2016-10045)
    // and subshell injection in mail parameters
    $checkMailInjection = function($key, $value, &$ruleOut) use (&$checkMailInjection) {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                if ($res = $checkMailInjection($k, $v, $ruleOut)) return $res;
            }
            return null;
        }

        if (!is_string($value) || strlen($value) < 3) {
            return null;
        }

        // Check for sendmail switches
        if (preg_match('/(?:^|\s)-(?:X|OQueueDirectory|C|o5|qI)\b/i', $value)) {
            $ruleOut = [
                'rule'    => 'VEC5_MAIL_PARAMETER_INJECTION',
                'detail'  => 'Dangerous sendmail switch (-X / -O / -C) detected in user input',
                'payload' => substr($value, 0, 128),
            ];
            return $ruleOut;
        }

        // If field name suggests an email destination or header, check for command substitution
        if (is_string($key) && preg_match('/(?:email|mail|recipient|from|reply|to|bcc|cc)/i', $key)) {
            if (preg_match('/(?:`|\$\([a-zA-Z0-9_\-\s]+\)|;\s*(?:id|whoami|cat|curl|wget|bash|sh)\b)/i', $value)) {
                $ruleOut = [
                    'rule'    => 'VEC5_COMMAND_SUBSTITUTION_IN_MAIL',
                    'detail'  => 'Command substitution or shell separator in email field',
                    'payload' => substr($value, 0, 128),
                ];
                return $ruleOut;
            }
        }

        return null;
    };

    $mailResult = null;
    if (!empty($_POST)) {
        foreach ($_POST as $k => $v) {
            if ($res = $checkMailInjection($k, $v, $mailResult)) return $res;
        }
    }
    if (!empty($_GET)) {
        foreach ($_GET as $k => $v) {
            if ($res = $checkMailInjection($k, $v, $mailResult)) return $res;
        }
    }

    return null;
};
