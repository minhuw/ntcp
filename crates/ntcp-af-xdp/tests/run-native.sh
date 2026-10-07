#!/usr/bin/env bash
set -euo pipefail
trap 'echo "native AF_XDP runner failed at line $LINENO (requires kernel support and CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF)" >&2' ERR

root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
for tool in cargo clang python3 unshare mount umount ip bpftool readlink mktemp rm; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
privilege=()
if (( EUID != 0 )); then
    command -v sudo >/dev/null || { echo 'requires root capabilities or passwordless sudo' >&2; exit 1; }
    sudo -n true || { echo 'requires root capabilities or passwordless sudo' >&2; exit 1; }
    privilege=(sudo -n)
fi

# libbpf sanitizes dots in pin paths, so use a dot-free temporary directory.
assets=$(mktemp -d /tmp/ntcpxdpXXXXXX)
trap 'rm -rf "$assets"' EXIT
# Build outside the network namespace; all generated assets are disposable.
CARGO_TARGET_DIR="$assets/target" cargo test -p ntcp-af-xdp --test native --no-run --message-format=json >"$assets/build.json"
binary=$(python3 - "$assets/build.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as messages:
    binaries = [m['executable'] for line in messages if
                (m := json.loads(line)).get('reason') == 'compiler-artifact'
                and m['target']['name'] == 'native' and m.get('executable')]
assert len(binaries) == 1, f'expected one native test executable, got {binaries}'
print(binaries[0])
PY
)
multiarch=$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH") or "")')
clang -O2 -g -target bpf -I"/usr/include/$multiarch" -c crates/ntcp-af-xdp/tests/redirect.c -o "$assets/redirect.o"

# No setup command can run unless BOTH namespace identities differ from the caller.
"${privilege[@]}" "$(command -v unshare)" --net --mount --propagation private \
    "$(command -v bash)" -s -- "$assets" "$binary" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/mnt)" "$PATH" <<'SH'
set -euo pipefail
trap 'echo "isolated AF_XDP setup/test failed at line $LINENO: $BASH_COMMAND; requires CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW and CAP_BPF (or CAP_SYS_ADMIN on older kernels)" >&2' ERR
assets=$1
binary=$2
export PATH="$5"
if [[ $(readlink /proc/self/ns/net) == "$3" || $(readlink /proc/self/ns/mnt) == "$4" ]]; then
    echo 'refusing setup: independent network AND mount namespaces are required' >&2
    exit 1
fi
mount --make-rprivate /
mkdir "$assets/pins"
mount -t bpf bpf "$assets/pins"
trap 'umount "$assets/pins"' EXIT
ip link add xdp-a type veth peer name xdp-b
ip link set xdp-a up
ip link set xdp-b up
mkdir "$assets/pins/maps"
bpftool prog load "$assets/redirect.o" "$assets/pins/redirect" type xdp pinmaps "$assets/pins/maps"
ip link set xdp-a xdpgeneric pinned "$assets/pins/redirect"
NTCP_XSKMAP="$assets/pins/maps/xsks" "$binary" --ignored --exact copy_mode_roundtrip --nocapture
SH
