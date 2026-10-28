#!/usr/bin/env bash
# ==============================================================================
# PHP-Hardening-Kit - Automated Test Runner
# Part of PHP-Hardening-Kit by Anton Barinov
# https://github.com/Anton-Barinov/PHP-Hardening-Kit
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Running PHP-Hardening-Kit Test Suites ==="

echo -e "\n1. Running Exploit Vector Tests..."
php "${SCRIPT_DIR}/ExploitVectorTests.php"

echo -e "\n2. Running Legitimate Traffic & False-Positive Tests..."
php "${SCRIPT_DIR}/LegitimateTrafficTest.php"

echo -e "\n3. Running Performance Benchmark..."
php "${SCRIPT_DIR}/benchmark.php"

echo -e "\nAll tests & benchmarks completed successfully!"
