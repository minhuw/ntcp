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

# Run inside `nix develop`: the flake builds the pinned Duvet and fetches the RFC
# texts listed in duvet/rfc-texts.json by their SHA-256 (NTCP_RFC_TEXTS).
version=0.4.3
duvet=$(command -v duvet) || { echo 'rfc-report.sh: no duvet: run inside nix develop' >&2; exit 1; }
case "$duvet" in
    */*-duvet-"$version"/bin/duvet) ;;
    *) echo "rfc-report.sh: $duvet is not Duvet $version from nix develop" >&2; exit 1 ;;
esac
: "${NTCP_RFC_TEXTS:?run inside nix develop (NTCP_RFC_TEXTS holds the RFC texts)}"

mkdir -p workbench/duvet
cp duvet/duvet.toml workbench/duvet/config.toml
# Duvet downloads a specification that has no copy here; place the pinned download.
specifications=workbench/duvet/specifications/www.rfc-editor.org/rfc
mkdir -p "$specifications"
for text in "$NTCP_RFC_TEXTS"/rfc*.txt; do
    [ -e "$specifications/${text##*/}" ] || cp --no-preserve=mode "$text" "$specifications/"
done
# Duvet 0.4.3 ignores CI when snapshots are disabled; select its gate explicitly.
has_ci=0
for argument do
    case "$argument" in --ci|--ci=*) has_ci=1 ;; esac
done
if [ "$has_ci" -eq 0 ]; then
    set -- --ci true "$@"
fi
"$duvet" report --config-path workbench/duvet/config.toml --require-tests true "$@"
if [ "$generate_only" -eq 0 ]; then
    exec python3 duvet/check_rfc_coverage.py
fi
