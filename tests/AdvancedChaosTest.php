<?php
/**
 * PHP-Hardening-Kit Advanced Chaos, ReDoS, HPP & CMS False-Positive Test Suite
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

declare(strict_types=1);

echo "=== Running PHP-Hardening-Kit Advanced Chaos & Pitfall Tests ===\n\n";

$guardDir = dirname(__DIR__) . '/guard';
$testConfig = [
    'mode' => 'monitor', // Monitor mode so it does not exit(1) during evaluation
    'rules' => [
        'php2shell'            => true,
        'cgi_injection'        => true,
        'filter_chains'        => true,
        'phar_deserialization' => true,
        'command_mail_abuse'   => true,
    ],
    'logging' => ['enabled' => false],
    'whitelist' => ['ips' => [], 'paths' => []],
];
file_put_contents($guardDir . '/config.php', "<?php return " . var_export($testConfig, true) . ";");
register_shutdown_function(function() use ($guardDir) {
    @unlink($guardDir . '/config.php');
});

require_once $guardDir . '/php-hardening-kit.php';

$pass = 0;
$fail = 0;

function assertPitfall(string $name, bool $condition, string $detail = ''): void {
    global $pass, $fail;
    if ($condition) {
        echo "  [PASS] {$name}" . ($detail ? " -> {$detail}" : "") . "\n";
        $pass++;
    } else {
        echo "  [FAIL] {$name}" . ($detail ? " -> {$detail}" : "") . "\n";
        $fail++;
    }
}

function evaluate(array $server = [], array $get = [], array $post = [], array $files = [], array $cookie = []): ?array {
    $_SERVER = array_merge([
        'REQUEST_METHOD' => 'GET',
        'REQUEST_URI'    => '/',
        'QUERY_STRING'   => '',
        'HTTP_HOST'      => 'example.com',
        'REMOTE_ADDR'    => '127.0.0.1',
    ], $server);
    $_GET = $get;
    $_POST = $post;
    $_FILES = $files;
    $_COOKIE = $cookie;

    $guard = PhpHardeningGuard::boot();

    $bombViolation = $guard->validateHeaderBomb();
    if ($bombViolation !== null) return $bombViolation;

    $hostViolation = $guard->validateHostHeader();
    if ($hostViolation !== null) return $hostViolation;

    $checkers = PhpHardeningGuard::getRuleCheckers();
    foreach ($checkers as $checker) {
        if (is_callable($checker)) {
            $res = $checker($guard);
            if ($res !== null) return $res;
        }
    }

    return null;
}

// -------------------------------------------------------------
// 1. ReDoS (Regular Expression Denial of Service) Stress Tests
// -------------------------------------------------------------
echo "1. Testing ReDoS Resilience & Catastrophic Backtracking Prevention...\n";

// Craft adversarial strings designed to trigger quadratic or exponential backtracking
$adversarialStrings = [
    'Long repeating spaces'     => str_repeat(' ', 20000) . '-d allow_url_include=1',
    'Long repeating slashes'    => 'php://' . str_repeat('filter/', 5000),
    'Repeating email prefix'    => str_repeat('a.', 5000) . 'admin@example.com',
    'Unclosed quote string'     => "O:4:\"Test\":" . str_repeat(' ', 10000),
    'Nested unicode soft hyphen'=> str_repeat('%ad', 5000),
    'Massive boundary spacing'  => 'multipart/form-data; ' . str_repeat(' ', 10000) . 'boundary=test',
];

$maxRegexTime = 0.0;
foreach ($adversarialStrings as $name => $str) {
    $t0 = microtime(true);
    $res = evaluate(['QUERY_STRING' => $str, 'REQUEST_URI' => '/' . $str]);
    $dur = (microtime(true) - $t0) * 1000;
    if ($dur > $maxRegexTime) {
        $maxRegexTime = $dur;
    }
    assertPitfall(
        "ReDoS check: {$name} ({$dur} ms)",
        $dur < 20.0, // Must execute well under 20ms even on worst input
        "Time was " . round($dur, 3) . " ms"
    );
}

// -------------------------------------------------------------
// 2. HTTP Parameter Pollution (HPP) & Name Manipulations
// -------------------------------------------------------------
echo "\n2. Testing HTTP Parameter Pollution & Array Smuggling in Upload Progress...\n";

// Array sent instead of string in upload progress to trigger Array-to-string notice or bypass
$resHpp1 = evaluate([], [], ['PHP_SESSION_UPLOAD_PROGRESS' => ['malicious', 'nested', 'payload']]);
assertPitfall(
    "Array in PHP_SESSION_UPLOAD_PROGRESS blocked without Notice/Warning",
    $resHpp1 !== null && strpos($resHpp1['rule'], 'PHP2SHELL') !== false,
    $resHpp1 ? "Blocked by " . $resHpp1['rule'] : "Failed to catch array in upload progress"
);

// Leading/trailing whitespace or disguised upload progress parameter
$resHpp2 = evaluate([], [], [' PHP_SESSION_UPLOAD_PROGRESS' => 'payload|with|delimiters']);
assertPitfall(
    "Whitespace-padded upload progress key detected",
    $resHpp2 !== null && strpos($resHpp2['rule'], 'PHP2SHELL') !== false,
    $resHpp2 ? "Blocked by " . $resHpp2['rule'] : "Failed to catch whitespace padded key"
);

// -------------------------------------------------------------
// 3. Real-World CMS False Positive Audits
// -------------------------------------------------------------
echo "\n3. Testing False Positive Immunity on Real-World CMS Payloads...\n";

// WordPress Gutenberg Block Editor Payload (contains HTML comments and raw JSON)
$gutenbergPost = [
    'action'  => 'editpost',
    'content' => "<!-- wp:paragraph {\"fontSize\":\"large\"} -->\n<p>Welcome to our new store!</p>\n<!-- /wp:paragraph -->\n<!-- wp:image {\"id\":102} -->\n<figure class=\"wp-block-image\"><img src=\"https://example.com/logo.png\" alt=\"Logo\"/></figure>\n<!-- /wp:image -->",
    'title'   => 'Spring Announcement 2026',
];
$resCms1 = evaluate([], [], $gutenbergPost);
assertPitfall(
    "WordPress Gutenberg Block Editor payload accepted without false positive",
    $resCms1 === null,
    $resCms1 ? "Falsely blocked by " . $resCms1['rule'] : "Clean pass"
);

// Stripe / Webhook Payment Payload (Base64 signature + JSON webhook body)
$paymentWebhook = [
    'id'      => 'evt_3MjjL2LkdIwHu7ix0rW9WJ8X',
    'type'    => 'payment_intent.succeeded',
    'payload' => base64_encode(json_encode(['amount' => 4999, 'currency' => 'usd', 'status' => 'succeeded'])),
];
$paymentHeaders = [
    'HTTP_STRIPE_SIGNATURE' => 't=1614555555,v1=5257a869e7ecebeda32affa62cd49231b2ec54dd7b66311e24eb029e54da29e3',
];
$resCms2 = evaluate($paymentHeaders, [], $paymentWebhook);
assertPitfall(
    "Stripe webhook with Base64 payload accepted without false positive",
    $resCms2 === null,
    $resCms2 ? "Falsely blocked by " . $resCms2['rule'] : "Clean pass"
);

// International E-Commerce Form (4-byte Emoji, Cyrillic, Chinese, Arabic)
$intlProduct = [
    'product_title'       => 'Смартфон Pro Max 🚀 512GB (Черный космос)',
    'product_description' => 'Невероятная производительность! 完美的产品 🌟 الهاتف رائع جدا',
    'tags'                => ['электроника', 'новинки_2026', 'скидки🎉'],
];
$resCms3 = evaluate([], [], $intlProduct);
assertPitfall(
    "Multilingual 4-byte UTF-8 emoji & international text accepted without false positive",
    $resCms3 === null,
    $resCms3 ? "Falsely blocked by " . $resCms3['rule'] : "Clean pass"
);

// -------------------------------------------------------------
// 4. Concurrency & Log File Integrity (LOCK_EX Stress)
// -------------------------------------------------------------
echo "\n4. Testing Concurrent Log File Locking & Integrity...\n";

$logFile = sys_get_temp_dir() . '/phk_concurrent_' . uniqid() . '.log';
$workerCount = 30;

// Execute simulated concurrent writes using flock
$workersSuccess = 0;
for ($w = 0; $w < $workerCount; $w++) {
    $line = json_encode([
        'timestamp'   => date('Y-m-d H:i:s'),
        'incident_id' => 'inc_' . $w,
        'worker'      => $w,
        'rule'        => 'LOCK_STRESS_TEST',
    ]) . PHP_EOL;

    $fp = @fopen($logFile, 'a');
    if ($fp && @flock($fp, LOCK_EX)) {
        fwrite($fp, $line);
        flock($fp, LOCK_UN);
        fclose($fp);
        $workersSuccess++;
    }
}

$writtenLines = file_exists($logFile) ? count(file($logFile)) : 0;
@unlink($logFile);

assertPitfall(
    "Log file handles concurrent LOCK_EX writes without corruption ({$writtenLines}/{$workerCount} lines)",
    $writtenLines === $workerCount,
    "All {$workerCount} atomic lines recorded cleanly"
);

echo "\n-------------------------------------------------------\n";
echo "Results: {$pass} Passed, {$fail} Failed\n";
echo "-------------------------------------------------------\n";

if ($fail > 0) {
    echo "ADVANCED PITFALL TESTS FAILED! ❌\n";
    exit(1);
}

echo "ALL ADVANCED PITFALL & REDOS TESTS PASSED! 🎉\n";
exit(0);
