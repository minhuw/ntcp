#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

version=0.4.3
root="$PWD/workbench/tools"
if ! cargo install --list --root "$root" 2>/dev/null | grep -Fxq "duvet v$version:"; then
    CARGO_TARGET_DIR="$PWD/workbench/duvet-build" \
        cargo install duvet --version "$version" --locked --root "$root"
fi

mkdir -p workbench/duvet
cp tools/duvet.toml workbench/duvet/config.toml
exec "$root/bin/duvet" report --config-path workbench/duvet/config.toml --require-tests true "$@"
