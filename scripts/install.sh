#!/usr/bin/env bash
# ==============================================================================
# PHP-Hardening-Kit - Installer & Configuration Script
# Part of PHP-Hardening-Kit by Anton Barinov
# https://github.com/Anton-Barinov/PHP-Hardening-Kit
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GUARD_PHP="${ROOT_DIR}/guard/php-hardening-kit.php"

# Color formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --install              Install PHP-Hardening-Kit into discovered PHP configurations
  --webroot <path>       Deploy .user.ini and .htaccess drop-in guards to target site webroot
  --mode <block|monitor> Set initial inspection mode (default: block)
  --check                Run vulnerability audit before installing
  --uninstall            Remove PHP-Hardening-Kit hooks
  --help, -h             Show this help screen
EOF
    exit 0
}

TARGET_WEBROOT=""
MODE="block"
ACTION="none"

while [ $# -gt 0 ]; do
    case "$1" in
        --install) ACTION="install"; shift ;;
        --uninstall) ACTION="uninstall"; shift ;;
        --check) ACTION="check"; shift ;;
        --webroot) TARGET_WEBROOT="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --help|-h) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

if [ "$ACTION" = "none" ]; then
    usage
fi

if [ "$ACTION" = "check" ]; then
    "${ROOT_DIR}/bin/php-hardening-check"
    exit 0
fi

if [ "$ACTION" = "install" ]; then
    echo -e "${CYAN}=== Installing PHP-Hardening-Kit Runtime Guard ===${NC}"

    # Initialize config.php if not present
    if [ ! -f "${ROOT_DIR}/guard/config.php" ]; then
        cp "${ROOT_DIR}/guard/config.sample.php" "${ROOT_DIR}/guard/config.php"
        sed -i.bak "s/'mode' => 'block'/'mode' => '${MODE}'/" "${ROOT_DIR}/guard/config.php" 2>/dev/null || true
        rm -f "${ROOT_DIR}/guard/config.php.bak" 2>/dev/null || true
        echo -e "${GREEN}✓ Created guard/config.php in '${MODE}' mode${NC}"
    fi

    # Webroot deployment (User-level or CMS level)
    if [ -n "$TARGET_WEBROOT" ]; then
        if [ ! -d "$TARGET_WEBROOT" ]; then
            echo -e "${RED}[ERROR] Webroot directory not found: ${TARGET_WEBROOT}${NC}" >&2
            exit 1
        fi

        USER_INI="${TARGET_WEBROOT}/.user.ini"
        echo -e "Deploying .user.ini into ${TARGET_WEBROOT}..."
        echo "auto_prepend_file = \"${GUARD_PHP}\"" >> "$USER_INI"
        echo -e "${GREEN}✓ Added auto_prepend_file to ${USER_INI}${NC}"

        # Copy Apache rules if Apache is detected
        if [ -f "${TARGET_WEBROOT}/.htaccess" ]; then
            echo -e "Appending Apache hardening rules to ${TARGET_WEBROOT}/.htaccess..."
            cat "${ROOT_DIR}/server-configs/apache/.htaccess-hardening" >> "${TARGET_WEBROOT}/.htaccess"
            echo -e "${GREEN}✓ Appended rules to .htaccess${NC}"
        fi

        echo -e "\n${BOLD}${GREEN}Deployment Complete!${NC}"
        echo -e "Webroot is now guarded by PHP-Hardening-Kit."
        exit 0
    fi

    # System-wide installation
    echo -e "Deploying system-wide auto_prepend_file..."
    echo -e "Add the following directive to your ${BOLD}php.ini${NC} or PHP-FPM pool configuration:"
    echo -e "\n  ${CYAN}auto_prepend_file = \"${GUARD_PHP}\"${NC}\n"
    echo -e "Or for PHP-FPM pool (e.g. /etc/php/*/fpm/pool.d/www.conf):"
    echo -e "  ${CYAN}php_admin_value[auto_prepend_file] = \"${GUARD_PHP}\"${NC}\n"

    echo -e "${GREEN}✓ Installation instructions generated. Verify with: bin/php-hardening-check${NC}"
    exit 0
fi

if [ "$ACTION" = "uninstall" ]; then
    echo -e "${YELLOW}Uninstalling PHP-Hardening-Kit...${NC}"
    if [ -n "$TARGET_WEBROOT" ] && [ -f "${TARGET_WEBROOT}/.user.ini" ]; then
        sed -i.bak '/php-hardening-kit\.php/d' "${TARGET_WEBROOT}/.user.ini" 2>/dev/null || true
        rm -f "${TARGET_WEBROOT}/.user.ini.bak" 2>/dev/null || true
        echo -e "${GREEN}✓ Removed directive from ${TARGET_WEBROOT}/.user.ini${NC}"
    else
        echo -e "Remove ${CYAN}auto_prepend_file = \"${GUARD_PHP}\"${NC} from your php.ini or pool configuration."
    fi
    exit 0
fi
