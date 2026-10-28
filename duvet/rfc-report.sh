#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

# The inventory auditor needs the generator's own exit status, before the strict
# Python verdict. Its caller explicitly selects --ci false and audits that fresh
# report separately. Normal invocations retain both strict gates.
generate_only=0
if [ "${1-}" = "--generate-only" ]; then
    generate_only=1
    shift
fi

version=0.4.3
root="$PWD/workbench/tools"
if ! cargo install --list --root "$root" 2>/dev/null | grep -Fxq "duvet v$version:"; then
    CARGO_TARGET_DIR="$PWD/workbench/duvet-build" \
        cargo install duvet --version "$version" --locked --root "$root"
fi

mkdir -p workbench/duvet
cp duvet/duvet.toml workbench/duvet/config.toml
# Duvet 0.4.3 ignores CI when snapshots are disabled; select its gate explicitly.
has_ci=0
for argument do
    case "$argument" in --ci|--ci=*) has_ci=1 ;; esac
done
if [ "$has_ci" -eq 0 ]; then
    set -- --ci true "$@"
fi
"$root/bin/duvet" report --config-path workbench/duvet/config.toml --require-tests true "$@"
if [ "$generate_only" -eq 0 ]; then
    exec python3 duvet/check_rfc_coverage.py
fi
