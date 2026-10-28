<?php
/**
 * PHP-Hardening-Kit: Legitimate Traffic & False-Positive Test Suite
 * Verifies that standard e-commerce & CMS traffic is NOT blocked.
 * 
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

$guardDir = dirname(__DIR__) . '/guard';

$passed = 0;
$failed = 0;

function assertLegitimateTrafficAllowed($description, $ruleFile, $serverState, $postState = [], $getState = [], $filesState = []) {
    global $passed, $failed;

    $_SERVER  = array_merge(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/index.php?route=product/product', 'REMOTE_ADDR' => '127.0.0.1'], $serverState);
    $_POST    = $postState;
    $_GET     = $getState;
    $_FILES   = $filesState;
    $_COOKIE  = [];

    $checker = require $ruleFile;
    $guardMock = new stdClass();
    $result = call_user_func($checker, $guardMock);

    if ($result === null) {
        echo "  [PASS] {$description} -> Allowed without false-positive.\n";
        $passed++;
    } else {
        echo "  [FAIL] {$description} -> FALSE POSITIVE triggered: {$result['rule']} ({$result['detail']})\n";
        $failed++;
    }
}

echo "=== Running PHP-Hardening-Kit False-Positive Tests ===\n\n";

// OpenCart product edit with Russian Cyrillic description
assertLegitimateTrafficAllowed(
    'OpenCart Cyrillic Product Submission',
    $guardDir . '/rules/01_php2shell.php',
    [],
    [
        'name'        => 'Смартфон Xiaomi Redmi Note 13',
        'description' => 'Отличный телефон с камерой 108 Мп и AMOLED экраном.',
        'price'       => '19990.00',
        'quantity'    => '15',
    ]
);

// Standard image upload
assertLegitimateTrafficAllowed(
    'Valid JPEG Image Upload',
    $guardDir . '/rules/01_php2shell.php',
    [],
    [],
    [],
    ['image' => ['name' => 'iphone_15_pro_max.jpg', 'type' => 'image/jpeg', 'tmp_name' => '/tmp/phpabc', 'error' => 0, 'size' => 125000]]
);

// Normal URL parameters with dashes and underscores
assertLegitimateTrafficAllowed(
    'SEF / SEO URL with hyphens and filters',
    $guardDir . '/rules/02_cgi_injection.php',
    ['QUERY_STRING' => 'route=product/category&path=20_27&sort=p.sort_order&order=ASC&filter=smartphones-apple']
);

// Normal email submission
assertLegitimateTrafficAllowed(
    'Legitimate Customer Contact Email',
    $guardDir . '/rules/05_command_mail_abuse.php',
    [],
    [
        'email'   => 'customer.service@example-store.com',
        'subject' => 'Вопрос по заказу #12543',
        'message' => 'Здравствуйте! Подскажите, когда будет доставлен товар?',
    ]
);

echo "\n------------------------------------------------------\n";
echo "Results: {$passed} Passed, {$failed} Failed\n";
echo "------------------------------------------------------\n";

if ($failed > 0) {
    exit(1);
}
echo "ALL FALSE-POSITIVE TESTS PASSED SUCCESSFULLY!\n";
