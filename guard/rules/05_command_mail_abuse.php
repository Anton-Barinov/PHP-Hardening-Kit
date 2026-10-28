<?php
/**
 * Vector 5: Dangerous Function Abuse, Mail Parameter RCE & Null-Byte Protection
 * Targets: CVE-2016-10033, CVE-2016-10045 (mail() -X RCE), Null-byte poisoning
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

return function($guard) {
    // 1. Check for Null-Byte poisoning (%00 / \0) across all input vectors
    // In PHP 5.4-5.6 and older 7.x, null bytes in file paths allow bypassing extension checks (e.g. shell.php\0.jpg)
    $checkNullByte = function($value, &$ruleOut) use (&$checkNullByte) {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                if ($res = $checkNullByte($k, $ruleOut)) return $res;
                if ($res = $checkNullByte($v, $ruleOut)) return $res;
            }
            return null;
        }

        if (is_string($value) && (strpos($value, "\0") !== false || stripos($value, '%00') !== false)) {
            $ruleOut = [
                'rule'    => 'VEC5_NULL_BYTE_POISONING',
                'detail'  => 'Null byte (%00) path truncation attempt detected',
                'payload' => substr($value, 0, 64),
            ];
            return $ruleOut;
        }
        return null;
    };

    $nullResult = null;
    if (!empty($_GET) && ($res = $checkNullByte($_GET, $nullResult))) return $res;
    if (!empty($_POST) && ($res = $checkNullByte($_POST, $nullResult))) return $res;
    if (!empty($_COOKIE) && ($res = $checkNullByte($_COOKIE, $nullResult))) return $res;

    // 2. Exploit vector: Shellshock & command injection in User-Agent or Referer headers
    $headersToCheck = ['HTTP_USER_AGENT', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR'];
    foreach ($headersToCheck as $h) {
        if (isset($_SERVER[$h]) && is_string($_SERVER[$h])) {
            $val = $_SERVER[$h];
            // Shellshock signature () { :;};
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
    // Attackers pass email addresses like: "attacker( -X/var/www/html/shell.php -OQueueDirectory=/tmp )"@example.com
    // or parameters containing sendmail flags -X, -O, -C
    $checkMailInjection = function($value, &$ruleOut) use (&$checkMailInjection) {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                if ($res = $checkMailInjection($v, $ruleOut)) return $res;
            }
            return null;
        }

        if (is_string($value) && strlen($value) > 3) {
            if (preg_match('/(?:^|\s)-(?:X|OQueueDirectory|C|o5|qI)\b/i', $value)) {
                $ruleOut = [
                    'rule'    => 'VEC5_MAIL_PARAMETER_INJECTION',
                    'detail'  => 'Dangerous sendmail switch (-X / -O / -C) detected in user input',
                    'payload' => substr($value, 0, 128),
                ];
                return $ruleOut;
            }
        }
        return null;
    };

    $mailResult = null;
    if (!empty($_POST) && ($res = $checkMailInjection($_POST, $mailResult))) return $res;
    if (!empty($_GET) && ($res = $checkMailInjection($_GET, $mailResult))) return $res;

    return null;
};
