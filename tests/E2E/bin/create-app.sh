#!/usr/bin/env bash
#
# Creates a fresh Laravel application with this package installed, for the e2e suite.
#
#   tests/E2E/bin/create-app.sh <laravel-version> <target-dir>
#   e.g. tests/E2E/bin/create-app.sh 13 /tmp/e2e-app-13
#
# The package is installed from this checkout through a Composer "path" repository, so the
# app runs exactly the code you have locally, wired up by Composer and Laravel's package
# discovery just like `composer require jorijn/laravel-security-checker` would do.
#
# Set COMPOSER_INSTALL_FLAGS (default "--prefer-dist") to e.g. "--prefer-source" on networks
# where GitHub's dist downloads are blocked.

set -euo pipefail

LARAVEL_VERSION="${1:?usage: create-app.sh <laravel-version> <target-dir>}"
TARGET="${2:?usage: create-app.sh <laravel-version> <target-dir>}"
FLAGS="${COMPOSER_INSTALL_FLAGS:---prefer-dist}"
PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

if [ -e "$TARGET" ]; then
    echo "Target $TARGET already exists; remove it first." >&2
    exit 1
fi

# shellcheck disable=SC2086 # FLAGS is intentionally word-split
composer create-project "laravel/laravel:^${LARAVEL_VERSION}.0" "$TARGET" $FLAGS --no-interaction --no-progress

cd "$TARGET"

# A fixed version is declared for the path repository: otherwise Composer derives one from
# the checked-out branch name, and that version (a dev-* one) would not satisfy the stable require below.
composer config repositories.package "$(cat <<JSON
{"type": "path", "url": "${PACKAGE_DIR}", "options": {"symlink": true, "versions": {"jorijn/laravel-security-checker": "4.99.0"}}}
JSON
)"

# enlightn/security-checker is only needed by the deprecated "enlightn" driver, which the
# e2e suite still covers until it is removed in 5.0.
# shellcheck disable=SC2086
composer require "jorijn/laravel-security-checker:*" "laravel/slack-notification-channel:^3.0" "enlightn/security-checker:^2.0" \
    $FLAGS --no-interaction --no-progress --with-all-dependencies

# The e2e "translations" scenario checks that the app's own lang/ directory keeps working
# after publishing ours, so give the app a translation of its own.
mkdir -p lang/en
cat > lang/en/e2e.php <<'PHP'
<?php

return ['marker' => 'translated by the app'];
PHP

php artisan package:discover --ansi
php artisan list security-check
