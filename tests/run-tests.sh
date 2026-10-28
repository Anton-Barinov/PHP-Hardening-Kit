#!/usr/bin/env bash
# ==============================================================================
# PHP-Hardening-Kit - Automated Test Runner
# Part of PHP-Hardening-Kit by Anton Barinov
# https://github.com/Anton-Barinov/PHP-Hardening-Kit
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Running PHP-Hardening-Kit Test Suites..."

php "${SCRIPT_DIR}/ExploitVectorTests.php"
echo ""
php "${SCRIPT_DIR}/LegitimateTrafficTest.php"
echo ""
echo "All tests finished successfully!"
