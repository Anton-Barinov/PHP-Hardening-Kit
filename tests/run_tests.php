<?php
/**
 * PHP-Hardening-Kit Universal Test Runner
 * Part of PHP-Hardening-Kit by Anton Barinov
 */

echo "=========================================\n";
echo " Running PHP-Hardening-Kit Test Suite\n";
echo "=========================================\n\n";

$tests = [
    'ExploitVectorTests.php',
    'LegitimateTrafficTest.php',
    'benchmark.php',
];

$failed = 0;
foreach ($tests as $testFile) {
    $fullPath = __DIR__ . '/' . $testFile;
    echo "Running {$testFile}...\n";
    $code = 0;
    passthru(PHP_BINARY . ' ' . escapeshellarg($fullPath), $code);
    if ($code !== 0) {
        echo "❌ FAILED: {$testFile} (exit code {$code})\n\n";
        $failed++;
    } else {
        echo "✅ PASSED: {$testFile}\n\n";
    }
}

if ($failed > 0) {
    echo "❌ {$failed} test suite(s) failed!\n";
    exit(1);
}

echo "All PHP-Hardening-Kit tests passed successfully! 🎉\n";
exit(0);
