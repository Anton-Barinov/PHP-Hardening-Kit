<?php
/**
 * Vector 4: Phar Deserialization & POP Gadget Chain Protection
 * Targets: CVE-2018-17082 (Phar metadata deserialization RCE), PHP Object Injection
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

return function($guard) {
    // Known dangerous POP gadget class signatures commonly found in PHPGGC exploits
    $gadgetPatterns = [
        '/O:\d+:"(?:GuzzleHttp|Monolog|Symfony|Laminas|Zend|Swift|League|Carbon|Doctrine|Illuminate|Twig|Pimple)\\\\/i',
        '/O:\d+:"(?:App\\\\|System\\\\|Think\\\\|yii\\\\)/i',
    ];

    $inspect = function($value, &$ruleOut) use (&$inspect, $gadgetPatterns) {
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                if ($res = $inspect($k, $ruleOut)) return $res;
                if ($res = $inspect($v, $ruleOut)) return $res;
            }
            return null;
        }

        if (!is_string($value) || strlen($value) < 5) {
            return null;
        }

        $decoded = urldecode($value);

        // Exploit vector: CVE-2018-17082 - Phar stream wrapper injection in file paths
        // Any filesystem function (file_exists, is_dir, getimagesize, file_get_contents)
        // receiving a phar:// stream automatically deserializes metadata.
        if (stripos($decoded, 'phar://') !== false) {
            $ruleOut = [
                'rule'    => 'VEC4_PHAR_WRAPPER_INJECTION',
                'detail'  => 'phar:// stream wrapper detected in user input (CVE-2018-17082)',
                'payload' => substr($decoded, 0, 128),
            ];
            return $ruleOut;
        }

        // Exploit vector: Direct PHP Object Injection (Serialized string in user parameter)
        if (preg_match('/^[OC]:\d+:"/i', $decoded) || (strlen($decoded) > 20 && preg_match('/(?:^|[^\w])O:\d+:"[a-zA-Z0-9_\\\\]+":\d+:{/i', $decoded))) {
            foreach ($gadgetPatterns as $pattern) {
                if (preg_match($pattern, $decoded)) {
                    $ruleOut = [
                        'rule'    => 'VEC4_POP_GADGET_INJECTION',
                        'detail'  => 'Serialized PHP object matching known exploit gadget chain detected',
                        'payload' => substr($decoded, 0, 128),
                    ];
                    return $ruleOut;
                }
            }
        }

        return null;
    };

    $result = null;

    if (!empty($_GET) && ($res = $inspect($_GET, $result))) return $res;
    if (!empty($_POST) && ($res = $inspect($_POST, $result))) return $res;
    if (!empty($_COOKIE) && ($res = $inspect($_COOKIE, $result))) return $res;

    return null;
};
