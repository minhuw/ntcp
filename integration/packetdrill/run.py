#!/usr/bin/env python3
import argparse
import ast
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

from expectations import (PORTED_EXCLUSION, PORTED_SCRIPTS,
                          apply_expectations, load_expectations)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PIN = json.loads((HERE / 'upstream.json').read_text())


LINUX_COOKIE_OPTION = 'linux-cookie'
LINUX_COOKIE_SCRIPTS = {
    'fastopen/server/opt34/' + name + '.pkt'
    for name in ('fin-close-socket', 'reset-after-accept', 'reset-before-accept')}
LINUX_COOKIE_SETTINGS = {
    'fast_open_client_default': False, 'fast_open_listener_default': False,
    'fast_open_cache': 'fresh runtime', 'fast_open_cookie_policy': 'linux-siphash24',
    'fast_open_key_hex': 'a1a1a1a1b2b2b2b2c3c3c3c3d4d4d4d4',
    'fast_open_cookie_input': 'remote address bytes + local address bytes',
    'fast_open_cookie_epoch': False, 'fast_open_option_kind': 34,
    'required_feature': 'tfo-linux-cookie',
    'implicit_listener_enablement': False, 'cookieless': False, 'foexp': False}


FASTOPEN_PMTUD_OPTION = 'pmtud1500'
FASTOPEN_PMTUD_SCRIPTS = {
    'fastopen/client/syn-data-icmp-unreach-frag-needed' + suffix + '.pkt'
    for suffix in ('', '-with-seq')}
FASTOPEN_PMTUD_SETTINGS = {
    'pmtud_first_hop_mtu': 1500,
    'mss': 1460, 'fast_open_client_default': False,
    'fast_open_listener_default': False, 'fast_open_cache': 'fresh runtime',
    'fast_open_cookie_policy': 'hmac-sha256'}


ADAPTIVE_ACK_OPTION = 'adaptive-ack'
ADAPTIVE_ACK_SCRIPTS = {
    'fastopen/client/' + name + '.pkt'
    for name in ('blocking-connect-bypass', 'blocking-sendmsg-multi-iov', 'blocking-sendto')}
ADAPTIVE_ACK_SETTINGS = {
    'mss': 1460,
    'fast_open_client_default': False, 'fast_open_listener_default': False,
    'fast_open_cache': 'fresh runtime', 'fast_open_cookie_policy': 'hmac-sha256',
    'adaptive_ack': True, 'delayed_ack_us': 200000, 'initial_ack_timeout_us': 40000}


FASTOPEN_CLIENT_SCRIPTS = {
    'fastopen/client/' + name + '.pkt'
    for name in ('blocking-connect-bypass-errno', 'blocking-sendto-errnos',
                 'cookie-req-timeout', 'fastopen-connect-keepalive',
                 'nonblocking-connect-bypass', 'nonblocking-sendmsg-multi-iov',
                 'nonblocking-sendto-empty-buf', 'nonblocking-sendto-over-mss',
                 'poll', 'simultaneous-fast-open', 'syn-data-rtt-from-syn-data',
                 'syn-data-timeout', 'valid-cookie-format')}
NON_TFO_SETUP_COMMANDS = {
    'fastopen/server/icmp-baseline.pkt': (
        b'`../../common/defaults.sh\n'
        b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_fastopen=0x30003`\n'),
    'fastopen/client/sendto-af-unspec.pkt': b'`../../common/defaults.sh`\n',
    'fastopen/server/basic-non-tfo-listener.pkt': (
        b'`../../common/defaults.sh\n'
        b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_fastopen=2`\n'),
    'fastopen/server/opt34/basic-non-tfo-listener.pkt': (
        b'`../../../common/defaults.sh\n sysctl -q net.ipv4.tcp_fastopen=2`\n'),
}


SLOW_START_ACK_SCRIPTS = {
    f'slow_start/slow-start-ack-per-{interval}pkt.pkt' for interval in (1, 2, 4)
}
SLOW_START_ACK_SETUP = (b'`../common/defaults.sh\n'
                        b'sysctl -q net.ipv4.tcp_tso_win_divisor=100`\n')


# Exact per-case option audit: setup-only adaptation never interprets shell/sysctl text.
UPSTREAM_OPTION_AUDIT = {
    'blocking/blocking-accept.pkt': {
        'immediate-ack': 'Original scripted receive ACK precedes application read; explicit immediate ACK compatibility, not Linux quickACK emulation.',
    },
    'blocking/blocking-read.pkt': {
        'immediate-ack': 'Original scripted receive ACK precedes application read; explicit immediate ACK compatibility, not Linux quickACK emulation.',
    },
    'cubic/cubic-rto-ss-ca-cwnd-bump.pkt': {
        'budget128m': 'Original SO_SNDBUF=200000 requires staged doubled400000-byte quota plus retained storage; the measured resize peak needs a bounded128MiB budget. No send-buffer semantics change.',
    },
    'cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt': {
        'ecn': 'Exact audited inline tcp_ecn setup enables ECN for the active case or this passive listener only; this is not global Linux mode2 active-open semantics.',
    },
    'ecn/ecn-uses-ect0.pkt': {
        'ecn': 'Exact audited inline tcp_ecn setup enables ECN for the active case or this passive listener only; this is not global Linux mode2 active-open semantics.',
    },
    'fastopen/client/blocking-connect-bypass-errno.pkt': {
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/blocking-connect-bypass.pkt': {
        'adaptive-ack': 'Audited interactive request/response trace requires the existing adaptive ACK policy (initial ATO40ms, maximum200ms); not Linux TCP_QUICKACK emulation.',
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/blocking-sendmsg-multi-iov.pkt': {
        'adaptive-ack': 'Audited interactive request/response trace requires the existing adaptive ACK policy (initial ATO40ms, maximum200ms); not Linux TCP_QUICKACK emulation.',
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/blocking-sendto-errnos.pkt': {
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/blocking-sendto.pkt': {
        'adaptive-ack': 'Audited interactive request/response trace requires the existing adaptive ACK policy (initial ATO40ms, maximum200ms); not Linux TCP_QUICKACK emulation.',
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/cookie-req-timeout.pkt': {
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/fastopen-connect-keepalive.pkt': {
        'budget224m': 'Trace creates 2 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/nonblocking-connect-bypass.pkt': {
        'budget224m': 'Trace creates 5 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/nonblocking-sendmsg-multi-iov.pkt': {
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/nonblocking-sendto-empty-buf.pkt': {
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/nonblocking-sendto-over-mss.pkt': {
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/poll.pkt': {
        'budget224m': 'Trace creates 4 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/simultaneous-fast-open.pkt': {
        'budget224m': 'Trace creates 2 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/syn-data-icmp-unreach-frag-needed-with-seq.pkt': {
        'budget224m': 'Trace creates 2 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'pmtud1500': 'Exact ICMP fragmentation-needed trace needs outbound PMTUD with first-hop MTU1500; receive MSS and packet assertions remain unchanged.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/syn-data-icmp-unreach-frag-needed.pkt': {
        'budget224m': 'Trace creates 2 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'pmtud1500': 'Exact ICMP fragmentation-needed trace needs outbound PMTUD with first-hop MTU1500; receive MSS and packet assertions remain unchanged.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/syn-data-rtt-from-syn-data.pkt': {
        'budget224m': 'Trace creates 3 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/syn-data-timeout.pkt': {
        'budget224m': 'Trace creates 2 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/client/valid-cookie-format.pkt': {
        'budget224m': 'Trace creates 7 client sockets; retained receive/send/scoreboard/RACK storage exceeds the 32 MiB single-connection budget. Keep the measured bounded seven-connection budget, not Linux skb accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Warmup and test sockets retain storage during timed events; reserve three owned pools before timed allocation, charged within budget224m.',
    },
    'fastopen/server/opt34/fin-close-socket.pkt': {
        'linux-cookie': 'Exact defaults key and explicit TCP_FASTOPEN listener require Linux SipHash-2-4 address-pair cookies; feature-gated and confined to these three opt34 scripts. No implicit listeners or FOEXP.',
    },
    'fastopen/server/opt34/reset-after-accept.pkt': {
        'linux-cookie': 'Exact defaults key and explicit TCP_FASTOPEN listener require Linux SipHash-2-4 address-pair cookies; feature-gated and confined to these three opt34 scripts. No implicit listeners or FOEXP.',
    },
    'fastopen/server/opt34/reset-before-accept.pkt': {
        'linux-cookie': 'Exact defaults key and explicit TCP_FASTOPEN listener require Linux SipHash-2-4 address-pair cookies; feature-gated and confined to these three opt34 scripts. No implicit listeners or FOEXP.',
    },
    'nagle/https_client.pkt': {
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
    },
    'notsent_lowat/notsent-lowat-sysctl.pkt': {
        'lowat4000': 'Exact setup sets global tcp_notsent_lowat=4000; raw per-socket zero still means inherit. No skb-accounting equivalence.',
    },
    'slow_start/slow-start-ack-per-1pkt.pkt': {
        'budget128m': 'Original SO_SNDBUF=200000 requires staged doubled400000-byte quota plus retained storage; the measured resize peak needs a bounded128MiB budget. No send-buffer semantics change.',
    },
    'slow_start/slow-start-ack-per-2pkt.pkt': {
        'budget128m': 'Original SO_SNDBUF=200000 requires staged doubled400000-byte quota plus retained storage; the measured resize peak needs a bounded128MiB budget. No send-buffer semantics change.',
    },
    'slow_start/slow-start-ack-per-4pkt.pkt': {
        'budget128m': 'Original SO_SNDBUF=200000 requires staged doubled400000-byte quota plus retained storage; the measured resize peak needs a bounded128MiB budget. No send-buffer semantics change.',
    },
    'slow_start/slow-start-app-limited-9-packets-out.pkt': {
        'budget128m': 'Original SO_SNDBUF=200000 requires staged doubled400000-byte quota plus retained storage; the measured resize peak needs a bounded128MiB budget. No send-buffer semantics change.',
    },
    'slow_start/slow-start-app-limited.pkt': {
        'budget128m': 'Original SO_SNDBUF=200000 requires staged doubled400000-byte quota plus retained storage; the measured resize peak needs a bounded128MiB budget. No send-buffer semantics change.',
    },
    'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt': {
        'budget224m': 'Four client sockets can retain charged storage through this short syscall-error trace; bounded seven-connection budget, not per-socket Linux memory accounting.',
        'no-timestamps': 'Exact audited setup explicitly disables tcp_timestamps; no host sysctl is executed.',
        'prealloc3': 'Reserve three owned connection pools before timed events; reservation is charged within budget224m.',
    },
}

def upstream_flags(relative):
    return "upstream,local=192.168.0.1" + "".join("," + token for token in sorted(UPSTREAM_OPTION_AUDIT.get(relative, {})))


SENDFILE_FIXTURE = 'sendfile-five-zero-bytes'
SENDFILE_SETUP = (b'`../../common/defaults.sh\n'
                  b'/bin/rm -f /tmp/testfile\n'
                  b'/bin/dd bs=1 count=5 if=/dev/zero of=/tmp/testfile status=none\n`\n')
FIXTURE_UNSUPPORTED = 'NTCP_PACKETDRILL_FIXTURE_UNSUPPORTED:'
# Executed only in the child, before LD_PRELOAD. No upstream shell is evaluated.
FIXTURE_CHILD = r"""
import ctypes, os, pathlib, sys
try:
    if os.readlink('/proc/self/ns/mnt') == sys.argv[1]:
        raise OSError('private mount namespace unavailable')
    argv = sys.argv[2:]
    script = pathlib.Path(argv[-1])
    if (not script.is_relative_to('/tmp') or '..' in script.parts
            or script == pathlib.Path('/tmp/testfile')):
        raise ValueError('generated script must be a separate path under /tmp')
    source = script.read_bytes()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_char_p]
    libc.mount.restype = ctypes.c_int
    def mount(source, target, kind, flags, data):
        if libc.mount(source, target, kind, flags, data) != 0:
            raise OSError(ctypes.get_errno(), 'fixture mount failed')
    mount(None, b'/', None, (1 << 18) | (1 << 14), None)  # recursive private
    mount(b'tmpfs', b'/tmp', b'tmpfs', 2 | 4, b'size=16m,mode=1777')
    # All writes happen after both isolation operations succeeded.
    pathlib.Path('/tmp/testfile').write_bytes(b'\0' * 5)
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_bytes(source)
    os.chdir(script.parent)
    os.execvp(argv[0], argv)
except (OSError, ValueError) as error:
    print('NTCP_PACKETDRILL_FIXTURE_UNSUPPORTED:', error, flush=True)
    sys.exit(125)
"""


def fixture_command(argv, runner, plugin):
    # /tmp is deliberately hidden. Do not silently run a different executable.
    for path in (runner, plugin, Path(sys.executable)):
        if Path(path).resolve().is_relative_to('/tmp'):
            raise ValueError('isolated fixture cannot access runtime artifacts under /tmp')
    return [*argv[:4], '--mount', '--propagation', 'private',
            sys.executable, '-I', '-c', FIXTURE_CHILD,
            os.readlink('/proc/self/ns/mnt'), *argv[4:]]


RESOURCE_SCRIPT = 'user_timeout/user-timeout-probe.pkt'
RESOURCE_SETUP = b'`../../common/defaults.sh`\n'
RESOURCE_EVENT = b'   +0 `tc qdisc delete dev tun0 root 2>/dev/null ; tc qdisc add dev tun0 root pfifo limit 0`\n'
RESOURCE_CONTROL = b'   +0 `ntcp-local-resource-reject-on`\n'
RESOURCE_SOURCE_SHA256 = 'fbbf50f3e1d2facf9835267513fe709665db245d1f2234f98dd448d8be59d564'


TCP_INFO_FIELDS = {'tcpi_ca_state', 'tcpi_probes', 'tcpi_backoff', 'tcpi_unacked', 'tcpi_sacked',
                   'tcpi_lost', 'tcpi_retrans', 'tcpi_reordering',
                   'tcpi_snd_cwnd', 'tcpi_snd_ssthresh', 'tcpi_rtt',
                   'tcpi_notsent_bytes', 'tcpi_last_data_recv', 'tcpi_busy_time',
                   'tcpi_rwnd_limited', 'tcpi_sndbuf_limited', 'tcpi_delivered',
                   'tcpi_options', 'tcpi_snd_wscale', 'tcpi_rcv_wscale'}


TCP_INFO_OPTION_BITS = {'TCPI_OPT_TIMESTAMPS': 1, 'TCPI_OPT_SACK': 2,
                        'TCPI_OPT_WSCALE': 4, 'TCPI_OPT_ECN': 8,
                        'TCPI_OPT_SYN_DATA': 32}


TCP_INFO_SYMBOLS = {'TCP_CA_Open', 'TCP_CA_Disorder', 'TCP_CA_CWR',
                    'TCP_CA_Recovery', 'TCP_CA_Loss'} | TCP_INFO_OPTION_BITS.keys()


def tcp_info_option_mask(node):
    # Deliberately only literal/symbol OR masks, not arbitrary computation.
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value if 0 <= node.value <= 47 and node.value & ~47 == 0 else None
    if isinstance(node, ast.Name):
        return TCP_INFO_OPTION_BITS.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left, right = tcp_info_option_mask(node.left), tcp_info_option_mask(node.right)
        if left is not None and right is not None:
            return left | right
    return None


def tcp_info_only(text):
    # Fail closed: only simple assertions over audited fields/constants. No
    # calls, imports, assignments, dynamic lookup or exception suppression.
    snippets = re.findall(r'%\{(.*?)\}%', text, re.S)
    if not snippets or text.count('%{') != len(snippets) or text.count('}%') != len(snippets):
        return False
    allowed = (ast.Module, ast.Assert, ast.Compare, ast.Name, ast.Load,
               ast.Constant, ast.BinOp, ast.UnaryOp, ast.BoolOp,
               ast.cmpop, ast.operator, ast.unaryop, ast.boolop)
    for snippet in snippets:
        try:
            tree = ast.parse(snippet.strip() + "\n\n")
        except SyntaxError:
            return False
        if not tree.body or any(not isinstance(node, ast.Assert) for node in tree.body):
            return False
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == 'tcpi_options':
                parent = parents[node]
                if isinstance(parent, ast.Assert) and parent.msg is node:
                    continue  # Diagnostic value only; condition must still mask options.
                if not isinstance(parent, ast.BinOp) or not isinstance(parent.op, ast.BitAnd):
                    return False
                mask = parent.right if parent.left is node else parent.left
                if tcp_info_option_mask(mask) is None:
                    return False
            if not isinstance(node, allowed):
                return False
            if isinstance(node, ast.Name) and node.id not in TCP_INFO_FIELDS | TCP_INFO_SYMBOLS:
                return False
    return True


def runner_provenance(runner):
    provenance = json.loads(runner.with_suffix('.provenance.json').read_bytes())
    expected = {
        'source_revision': PIN['revision'],
        'patch_sha256': hashlib.sha256((HERE / 'code-sockopt.patch').read_bytes()).hexdigest(),
        'build_helper_sha256': hashlib.sha256((HERE / 'build_runner.py').read_bytes()).hexdigest(),
        'executable_sha256': hashlib.sha256(runner.read_bytes()).hexdigest(),
    }
    if provenance != expected:
        raise ValueError('patched runner provenance differs from audited build')
    return provenance


def preflight(text, embedded_tcp_info=False, resource_control=False):
    # Conservative safety/capability screening, NOT a second packetdrill parser.
    # Upstream --dry_run remains the authority for script syntax.
    # Inspect raw text conservatively, including comments: do not accidentally
    # strip a command concealed by comment-like characters inside a string.
    reasons = []
    shell_text = text
    if resource_control and text.count(RESOURCE_CONTROL.decode()) == 1:
        shell_text = text.replace(RESOURCE_CONTROL.decode(), '', 1)
    if '`' in shell_text:
        reasons.append('shell setup/assertions target Linux, not the ntcp backend')
    if '%{' in text or '}%' in text:
        if embedded_tcp_info:
            if not tcp_info_only(text):
                reasons.append('embedded code is not limited to audited TCP_INFO assertions')
            unknown = set(re.findall(r'\btcpi_\w+\b', text)) - TCP_INFO_FIELDS
            if unknown:
                reasons.append('embedded code requires unsupported TCP_INFO fields: '
                               + ', '.join(sorted(unknown)))
        else:
            reasons.append('embedded code requires a hash-audited TCP_INFO mapping')
    allowed = {'local_ip', 'remote_ip', 'tolerance_usecs', 'tcp_ts_tick_usecs',
               'strict_segments', 'ip_version', 'mss', 'tcp_ts_ecr_scaled'}
    for option in re.findall(r'^\s*--([\w_-]+)', text, re.M):
        if option not in allowed:
            reasons.append(f'script option --{option} is outside the supported profile')
    return sorted(set(reasons))


def adapt_source(directory, relative, manifest, so_flags):
    """Replace only audited setup; never rewrite assertions or fixture paths."""
    if manifest['upstream_revision'] != PIN['revision']:
        raise ValueError('adaptation revision differs from upstream pin')
    if relative not in manifest['scripts']:
        raise ValueError('script is not adaptation-allowlisted')
    entry = manifest['scripts'][relative]
    if so_flags != entry['adapter_flags']:
        raise ValueError('adapter flags differ from audited mapping')
    if so_flags != upstream_flags(relative):
        raise ValueError('options differ from exact per-case audit')
    metadata = profile_metadata(so_flags)
    if entry['mapping']['ntcp_settings'] != metadata:
        raise ValueError('settings differ from resolved upstream configuration')
    if entry['mapping'].get('option_reasons') != UPSTREAM_OPTION_AUDIT.get(relative, {}):
        raise ValueError('option reasons differ from exact per-case audit')
    source = (directory / relative).read_bytes()
    setup = (directory / entry['setup_path']).read_bytes()
    for label, data, expected in (
        ('source', source, entry['source_sha256']),
        ('setup', setup, entry['setup_sha256']),
    ):
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'{label} hash differs from audited adaptation')
    for extra in entry.get('additional_setup_files', []):
        data = (directory / extra['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != extra['sha256']:
            raise ValueError(f"setup {extra['path']} hash differs from audited adaptation")
    if relative == RESOURCE_SCRIPT and not entry.get('blocked_reasons'):
        expected_commands = [RESOURCE_SETUP.rstrip(b'\n'),
                             RESOURCE_EVENT[RESOURCE_EVENT.index(b'`'):].rstrip(b'\n')]
        expected_audit = [(c.decode(), hashlib.sha256(c).hexdigest()) for c in expected_commands]
        if (hashlib.sha256(source).hexdigest() != RESOURCE_SOURCE_SHA256
                or entry['command_line'].encode() != RESOURCE_SETUP
                or entry['replacement_line'].encode() != b'// ntcp setup mapped by adaptations.json; Linux defaults not reproduced.\n'
                or entry.get('command_sha256') != hashlib.sha256(RESOURCE_SETUP).hexdigest()
                or entry.get('expected_command_count') != 2
                or re.findall(rb'`[^`]*`', source) != expected_commands
                or [(c['command'], c['sha256']) for c in entry.get('audited_shell_commands', [])] != expected_audit
                or entry.get('resource_control') is not True
                or entry.get('resource_event_sha256') != hashlib.sha256(RESOURCE_EVENT).hexdigest()
                or source.count(RESOURCE_EVENT) != 1):
            raise ValueError('expected exact audited resource setup and timed command')
        generated = source.replace(RESOURCE_SETUP, entry['replacement_line'].encode(), 1).replace(RESOURCE_EVENT, RESOURCE_CONTROL, 1)
        reasons = preflight(generated.decode(), True, resource_control=True)
        if reasons:
            raise ValueError('; '.join(reasons))
        return generated, {**entry, 'generated_sha256': hashlib.sha256(generated).hexdigest()}
    if entry.get('blocked_reasons'):
        # Keep unavailable shell/configuration and embedded assertions untouched.
        # The caller reports the audit but must never execute this source.
        return source, dict(entry)
    command = entry['command_line'].encode()
    replacement = entry['replacement_line'].encode()
    setup_commands = {
        'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt': (
            b'`../common/defaults.sh\n'
            b' ../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0`\n'),
        'nagle/https_client.pkt': (
            b'`../common/defaults.sh\nethtool -K tun0 tso off gso off\n'
            b'../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0`\n'),
        'notsent_lowat/notsent-lowat-sysctl.pkt': (
            b'`../../common/defaults.sh\nsysctl -q net.ipv4.tcp_notsent_lowat=4000`\n'),
        **NON_TFO_SETUP_COMMANDS,
        **{name: SLOW_START_ACK_SETUP for name in SLOW_START_ACK_SCRIPTS},
    }
    for name in FASTOPEN_CLIENT_SCRIPTS | ADAPTIVE_ACK_SCRIPTS | FASTOPEN_PMTUD_SCRIPTS:
        setup_commands[name] = (
            b'`../../common/defaults.sh\n'
            b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0`\n')
    for name in LINUX_COOKIE_SCRIPTS:
        setup_commands[name] = b'`../../../common/defaults.sh`\n'
    if LINUX_COOKIE_OPTION in so_flags.split(',') and relative not in LINUX_COOKIE_SCRIPTS:
        raise ValueError('Linux cookie setup is limited to audited explicit listeners')
    if FASTOPEN_PMTUD_OPTION in so_flags.split(',') and relative not in FASTOPEN_PMTUD_SCRIPTS:
        raise ValueError('Fast Open PMTUD setup is limited to two audited ICMP cases')
    if ADAPTIVE_ACK_OPTION in so_flags.split(',') and relative not in ADAPTIVE_ACK_SCRIPTS:
        raise ValueError('Adaptive ACK setup is limited to three audited blocking clients')
    if relative in setup_commands:
        expected = setup_commands[relative]
        commands = [command.rstrip(b'\n')]
        replacements = [(command, replacement)]
        if (relative in FASTOPEN_CLIENT_SCRIPTS | ADAPTIVE_ACK_SCRIPTS | FASTOPEN_PMTUD_SCRIPTS
                or relative in {'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt', 'nagle/https_client.pkt',
                                'fastopen/server/basic-non-tfo-listener.pkt',
                                'fastopen/server/icmp-baseline.pkt'}):
            restore = b'`/tmp/sysctl_restore_${PPID}.sh`\n'
            restored = b'// ntcp profile is process-local; no host sysctls to restore.\n'
            if (entry.get('restore_line', '').encode() != restore
                    or entry.get('restore_sha256') != hashlib.sha256(restore).hexdigest()
                    or entry.get('restore_replacement_line', '').encode() != restored
                    or not any(extra['path'] == 'common/set_sysctls.py'
                               for extra in entry.get('additional_setup_files', []))):
                raise ValueError('expected exact audited restore and setup helper')
            commands.append(restore.rstrip(b'\n'))
            replacements.append((restore, restored))
        expected_replacement = b'// ntcp setup mapped by adaptations.json; Linux defaults not reproduced.\n'
        if (relative in FASTOPEN_PMTUD_SCRIPTS | ADAPTIVE_ACK_SCRIPTS | FASTOPEN_CLIENT_SCRIPTS | SLOW_START_ACK_SCRIPTS
                or relative in NON_TFO_SETUP_COMMANDS and expected.count(b'\n') == 2):
            expected_replacement += b'\n'  # Keep the audited two-line setup's line numbers.
        if (command != expected or so_flags != upstream_flags(relative)
                or entry['variant'] != 'ipv4' or entry['setup_path'] != 'common/defaults.sh'
                or replacement != expected_replacement
                or entry.get('command_sha256') != hashlib.sha256(command).hexdigest()
                or entry['expected_command_count'] != len(commands)
                or re.findall(rb'`[^`]*`', source) != commands
                or [(c['command'].encode(), c['sha256']) for c in entry['audited_shell_commands']]
                   != [(c, hashlib.sha256(c).hexdigest()) for c in commands]):
            raise ValueError('expected exact audited setup and commands')
        generated = source
        for old, new in replacements:
            if source.count(old) != 1 or not (source.startswith(old) or b'\n' + old in source):
                raise ValueError('expected one complete setup/restore line')
            generated = generated.replace(old, new, 1)
        reasons = preflight(generated.decode(), entry.get('embedded_tcp_info') is True)
        if reasons:
            raise ValueError('; '.join(reasons))
        return generated, {**entry, 'generated_sha256': hashlib.sha256(generated).hexdigest()}
    ecn_command = (b'`../common/defaults.sh\n'
                   b'sysctl -q net.ipv4.tcp_ecn=1  # fully enabled\n`\n')
    ecn_mapped = (command == ecn_command
                  and so_flags == upstream_flags(relative) and 'ecn' in so_flags.split(',')
                  and entry['mapping']['ntcp_settings'].get('ecn') is True
                  and entry.get('command_sha256') == hashlib.sha256(command).hexdigest())
    passive_ecn_command = (b'`../common/defaults.sh\n'
                           b'sysctl -q net.ipv4.tcp_ecn=2    # server agrees to ECN if client proposes it\n`\n')
    passive_ecn_mapped = (
        relative == 'cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt'
        and command == passive_ecn_command
        and so_flags == upstream_flags(relative) and 'ecn' in so_flags.split(',')
        and entry['mapping']['ntcp_settings'].get('ecn') is True
        and entry['mapping'].get('ecn_scope') == 'passive listener in this exact script only'
        and entry.get('command_sha256') == hashlib.sha256(command).hexdigest())
    fixture_mapped = (relative == 'sendfile/sendfile-simple.pkt'
                      and command == SENDFILE_SETUP
                      and entry.get('fixture') == SENDFILE_FIXTURE
                      and so_flags == upstream_flags(relative)
                      and entry.get('command_sha256') == hashlib.sha256(command).hexdigest())
    if entry.get('fixture') is not None and not fixture_mapped:
        raise ValueError('fixture is not the exact audited sendfile setup')
    # Only exact defaults, ECN enablement or the bounded fixture, not a shell scrubber.
    if (entry['variant'] != 'ipv4' or entry['setup_path'] != 'common/defaults.sh'
            or not (command in (b'`../common/defaults.sh`\n',
                                b'`../common/defaults.sh\n`\n',
                                b'`../../common/defaults.sh`\n',
                                b'`../../common/defaults.sh\n`\n') or ecn_mapped or passive_ecn_mapped or fixture_mapped)
            or replacement != b'// ntcp setup mapped by adaptations.json; Linux defaults not reproduced.\n'
            or entry['expected_command_count'] != 1
            or source.count(command) != 1
            or not (source.startswith(command) or b'\n' + command in source)
            or source.count(b'`') != 2):
        raise ValueError('expected exactly one audited setup command and replacement')
    generated = source.replace(command, replacement, 1)
    reasons = preflight(generated.decode(), entry.get('embedded_tcp_info') is True)
    if reasons:
        raise ValueError('; '.join(reasons))
    return generated, {**entry, 'generated_sha256': hashlib.sha256(generated).hexdigest()}


def invoke(argv, cwd, timeout):
    # Kill the whole process group on timeout; packetdrill has worker threads and
    # may spawn helper processes. Never leave an external test running behind CI.
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, stdout=output,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as error:
            return None, False, str(error)
        expired = False
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            os.killpg(proc.pid, signal.SIGKILL)
            code = proc.wait()
        # Preserve complete diagnostic output; report consumers retain raw logs.
        output.seek(0)
        log = output.read().decode(errors='replace')
        return code, expired, log


def check_plugin_hash(plugin, expected):
    if hashlib.sha256(plugin.read_bytes()).hexdigest() != expected:
        raise ValueError('packetdrill plugin changed after backend verification')


def verify_backend(plugin, timeout):
    # An interposer must never be loaded into this runner's own Python process.
    digest = hashlib.sha256(plugin.read_bytes()).hexdigest()
    helper = ('import ctypes, sys; '
              'library = ctypes.CDLL(sys.argv[1]); '
              'identity = library.ntcp_packetdrill_backend; '
              'identity.argtypes = []; identity.restype = ctypes.c_char_p; '
              'print(identity().decode("ascii"))')
    code, expired, log = invoke([sys.executable, '-I', '-c', helper, str(plugin)],
                                plugin.parent, min(timeout, 5))
    if expired or code != 0 or log.strip() != 'ntcp-socket':
        raise ValueError('packetdrill plugin backend verification failed '
                         f'(expected ntcp-socket, returncode={code}, timeout={expired}): '
                         + log.strip())
    check_plugin_hash(plugin, digest)
    return 'ntcp-socket', digest


def outcome(code, expired, log):
    if expired:
        return 'timeout'
    if 'NTCP_PACKETDRILL_FAILURE:' in log or code is not None and code < 0:
        return 'failed'
    if 'NTCP_PACKETDRILL_UNSUPPORTED:' in log:
        return 'unsupported'
    if code is None:
        return 'environment_error'
    if code == 0:
        return 'passed'
    if any(message in log for message in (
        'unshare: unshare failed', 'mlockall:', 'mlockall failed',
        'error while loading shared libraries', 'cannot open shared object file',
    )):
        return 'environment_error'
    return 'failed'


def check_checkout(checkout):
    actual = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'],
                                     text=True).strip()
    if actual != PIN['revision']:
        raise ValueError(f'packetdrill revision {actual} differs from pin {PIN["revision"]}')
    if subprocess.run(['git', '-C', str(checkout), 'diff', '--quiet', 'HEAD', '--',
                       'gtests/net'], check=False).returncode != 0:
        raise ValueError('packetdrill checkout has modified tracked runner/tests')
    return actual


def variants(script, upstream):
    if not upstream:
        return [('native-ipv4', [])]
    # Match the filename selection and argument sets of the pinned run_all.py.
    return [(name, args) for name, args in PIN['variants'].items()
            if not (script.name.endswith('v6.pkt') and name != 'ipv6')
            and not (script.name.endswith('v4.pkt') and name == 'ipv6')]


def select_cases(scripts, directory, suite, selected_variants=None, selected_scripts=None):
    known_variants = ({'ipv4'} if suite == 'ntcp-ported' else set(PIN['variants'])
                      if suite in ('upstream-raw', 'upstream') else {'native-ipv4'})
    for variant in selected_variants or []:
        if variant not in known_variants:
            raise ValueError(f'--variant {variant!r} is invalid for suite {suite}')
    names = {str(script.relative_to(directory)) for script in scripts}
    for script in selected_scripts or []:
        if script not in names:
            raise ValueError(f'--script {script!r} is not an exact eligible relative path')
    selected, excluded = [], []
    for script in scripts:
        relative = str(script.relative_to(directory))
        available = ([('ipv4', PIN['variants']['ipv4'])] if suite == 'ntcp-ported'
                     else variants(script, suite in ('upstream-raw', 'upstream')))
        for variant, flags in available:
            reasons = []
            if selected_scripts is not None and relative not in selected_scripts:
                reasons.append('excluded by --script selection')
            if selected_variants is not None and variant not in selected_variants:
                reasons.append('excluded by --variant selection')
            if not reasons and suite == 'upstream' and relative in PORTED_SCRIPTS:
                reasons.append(PORTED_EXCLUSION)
            if reasons:
                exclusion = {'script': relative, 'variant': variant,
                             'suite': suite, 'reasons': reasons}
                if PORTED_EXCLUSION in reasons:
                    exclusion['ported_to'] = 'ntcp-ported'
                excluded.append(exclusion)
            else:
                selected.append((script, variant, flags))
    if not selected and not any(PORTED_EXCLUSION in row['reasons'] for row in excluded):
        raise ValueError('selection matches no eligible packetdrill cases')
    return selected, excluded


UPSTREAM_BASELINE_REASON = 'Common upstream baseline: actual CUBIC with HyStart++ and fast convergence, no enforced pacing (PacingConfig=None and prr_pacing=false), IW10, 8 MiB receive storage, timestamps/SACK, RACK/TLP, RFC9937 PRR without pacing, read-window update coalescing (core default, including prompt zero/subscale reopening), synchronized local abort RST|ACK (the core bare-RST default remains separately scoped), actual admitted software-segmentation group terminal flush hints (bounded by backend capacity, queued data and half the effective cwnd), with original retry hints and no fixed packet-count batches, adaptive ACK (40ms initial timeout, 200ms maximum; audited immediate-ack overrides to fixed0), 200ms RTO floor, one preallocated connection and a bounded32MiB budget. No Linux autotuning, skb accounting, qdisc or full defaults equivalence.'


UPSTREAM_OPTIONS = {
    'no-timestamps', 'ecn', 'adaptive-ack', 'lowat4000', 'linux-cookie', 'pmtud1500',
    'budget128m', 'budget224m', 'prealloc3', 'immediate-ack', 'peer-ack-delay200ms',
    'abort-with-ack', 'coalesce-read-window', 'legacy-prr',
    'reno', 'paced', 'receive64k',
}


def profile_metadata(so_flags):
    tokens = so_flags.split(',')
    local = [token[6:] for token in tokens if token.startswith('local=')]
    policies = [token for token in tokens if not token.startswith('local=')]
    profiles = set(policies) & {'baseline', 'sack', 'pipeline', 'pipeline-paced',
                                'pipeline-gso', 'pipeline-paced-gso', 'upstream'}
    profile = next(iter(profiles)) if len(profiles) == 1 else None
    options = set(policies) - profiles
    import ipaddress
    try:
        valid_local = len(local) == 1 and isinstance(ipaddress.ip_address(local[0]), ipaddress.IPv4Address)
    except ValueError:
        valid_local = False
    known = (valid_local and profile is not None and len(tokens) == len(set(tokens))
             and (not options or profile == 'upstream' and options <= UPSTREAM_OPTIONS)
             and not {'budget128m', 'budget224m'} <= options
             and not {'immediate-ack', 'adaptive-ack'} <= options)
    upstream = profile == 'upstream'
    # Configuration/capture boundary only, never a claim of Linux fq/TSO timing equivalence.
    metadata = {
        'profile': profile,
        'transport_clock': 'monotonic Instant elapsed microseconds',
        'prr_pacing': ('paced' in options if upstream else True),
        'transmit_batch_clock': 'monotonic sample per selection/accept',
        'egress_pipeline': 'shared production scheduler',
        'general_pacing': ('paced' in options if upstream else profile in {'pipeline-paced', 'pipeline-paced-gso'}),
        'software_gso': upstream or profile in {'pipeline-gso', 'pipeline-paced-gso'},
        'capture_boundary': 'individual raw IPv4 TCP wire segments',
        'capture_clock': 'realtime epoch microseconds at backend submission',
        'hardware_tso': False, 'gro': False,
    }
    if not known:
        return {key: value if key == 'profile' else None for key, value in metadata.items()}
    if upstream:
        metadata.update(
            options=sorted(options), sack=True, timestamps='no-timestamps' not in options,
            initial_window='Iw10', rack=True, prr='LegacyInitialCredit' if 'legacy-prr' in options else 'Rfc9937',
            tlp=True, rto_min_us=200000, preallocate_connections=3 if 'prealloc3' in options else 1,
            ecn='ecn' in options, mss=1460,
            receive_capacity=65535 if 'receive64k' in options else 8388608,
            window_scale=0 if 'receive64k' in options else 8,
            endpoint_max_buffer_bytes=(224 if 'budget224m' in options else 128 if 'budget128m' in options else 32) * 1024 * 1024,
            congestion_control='Reno' if 'reno' in options else 'Cubic',
            cubic_hystart=True, cubic_fast_convergence=True,
            delayed_ack_us=0 if 'immediate-ack' in options else 200000,
            adaptive_ack='immediate-ack' not in options,
            initial_ack_timeout_us=40000,
            abort_with_ack=True,
            coalesce_read_window_updates=True,
            peer_max_ack_delay_us=200000 if 'peer-ack-delay200ms' in options else 499999,
            output_push_batch_segments=0,
            output_group_flush=True,
            output_push_batch_retransmissions=False,
            global_notsent_lowat=4000 if 'lowat4000' in options else 4294967295,
            socket_notsent_lowat=0, fast_open_client_default=False, fast_open_listener_default=False,
            fast_open_cache='fresh runtime', fast_open_cookie_policy='hmac-sha256',
            pacing_config={'rate_gain_percent': 125, 'max_bytes_per_second': None, 'max_burst_segments': 2} if 'paced' in options else None)
        if 'linux-cookie' in options:
            metadata.update(LINUX_COOKIE_SETTINGS)
        if 'pmtud1500' in options:
            metadata.update(FASTOPEN_PMTUD_SETTINGS)
        if 'adaptive-ack' in options:
            metadata.update(ADAPTIVE_ACK_SETTINGS)
    return metadata


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--runner', type=Path,
                        help='explicit patched executable produced by build_runner.py')
    parser.add_argument('--plugin', type=Path,
                        default=ROOT / 'target/debug/libntcp_packetdrill.so')
    parser.add_argument('--suite', choices=['smoke', 'sack', 'upstream-raw', 'upstream', 'ntcp-ported'], default='smoke')
    parser.add_argument('--variant', action='append',
                        choices=['native-ipv4', *PIN['variants']],
                        help='select a suite variant (repeatable; default: all eligible variants)')
    parser.add_argument('--script', action='append',
                        help='select an exact suite-relative script path (repeatable)')
    parser.add_argument('--report', type=Path,
                        default=ROOT / 'workbench/packetdrill/report.json')
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--so-flags')
    args = parser.parse_args()
    if args.so_flags is None and args.suite not in ('upstream', 'ntcp-ported'):
        args.so_flags = ('sack,local=192.0.2.1' if args.suite == 'sack' else
                         'baseline,local=192.0.2.1' if args.suite == 'smoke' else
                         'baseline,local=192.168.0.1')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout must be finite and positive')
    checkout = args.checkout.resolve()
    plugin = args.plugin.resolve()
    try:
        revision = check_checkout(checkout)
    except (ValueError, subprocess.SubprocessError, OSError) as error:
        parser.error(str(error))
    runner = args.runner.resolve() if args.runner else checkout / PIN['runner']
    try:
        provenance = runner_provenance(runner) if args.runner else None
    except (ValueError, OSError) as error:
        parser.error(str(error))

    def check_runner():
        try:
            if provenance is not None and runner_provenance(runner) != provenance:
                raise ValueError('patched runner changed during execution')
        except (ValueError, OSError) as error:
            parser.error(str(error))

    def invoke_runner(argv, cwd, timeout):
        check_runner()
        result = invoke(argv, cwd, timeout)
        check_runner()
        return result
    if not runner.is_file() or not os.access(runner, os.X_OK):
        parser.error(f'build the pinned external runner first: {runner}')
    if not plugin.is_file():
        parser.error(f'build ntcp-packetdrill first: {plugin}')
    try:
        socket_backend, plugin_sha256 = verify_backend(plugin, args.timeout)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    manifest_bytes = ((HERE / 'adaptations.json').read_bytes()
                      if args.suite in ('upstream', 'ntcp-ported') else None)
    manifest = json.loads(manifest_bytes) if manifest_bytes is not None else None
    expectation_manifest = None
    expectation_manifest_sha256 = None
    if args.suite == 'ntcp-ported':
        try:
            expectation_manifest, expectation_manifest_sha256 = load_expectations(
                HERE, PIN['revision'], manifest)
        except (ValueError, OSError, TypeError, KeyError) as error:
            parser.error(str(error))
    upstream = args.suite in ('upstream-raw', 'upstream', 'ntcp-ported')
    directory = (checkout / PIN['tcp_tests'] if upstream else
                 HERE / ('sack-tests' if args.suite == 'sack' else 'tests'))
    upstream_scripts = []
    if upstream:
        tracked = subprocess.check_output(
            ['git', '-C', str(checkout), 'ls-files', '-z', '--', PIN['tcp_tests']],
            text=True,
        ).split('\0')
        upstream_scripts = sorted(checkout / path for path in tracked if path.endswith('.pkt'))
        scripts = (sorted(directory / path for path in manifest['scripts']
                          if args.suite != 'ntcp-ported' or path in PORTED_SCRIPTS)
                   if manifest is not None else upstream_scripts)
        if any(script not in upstream_scripts for script in scripts):
            parser.error('adaptation allowlist contains an untracked upstream script')
    else:
        scripts = sorted(directory.rglob('*.pkt'))
    if not scripts:
        parser.error(f'no .pkt tests found in {directory}')
    results = []
    try:
        cases, excluded = select_cases(scripts, directory, args.suite,
                                       args.variant, args.script)
    except ValueError as error:
        parser.error(str(error))
    selected_script_files = len({script for script, _, _ in cases})
    for row in excluded:
        if row.get('ported_to') == 'ntcp-ported':
            print(f'excluded: {row["script"]} ({row["variant"]}, {args.suite}): {PORTED_EXCLUSION}', flush=True)
    with tempfile.TemporaryDirectory(prefix='ntcp-packetdrill-') as temporary:
        for script, variant, flags in cases:
            source = script.read_bytes()
            text = source.decode()
            row = {'script': str(script.relative_to(directory)), 'variant': variant,
                   'suite': args.suite, 'adapted': False,
                   'expectation_kind': 'upstream' if upstream else 'native',
                   'sha256': hashlib.sha256(source).hexdigest(),
                   'effective_flags': {'adapter': args.so_flags, 'packetdrill': flags},
                   'syntax_returncode': None, 'behavior_executed': False,
                   'stage': 'adaptation' if manifest is not None else 'syntax'}
            so_flags = args.so_flags
            if manifest is not None and so_flags is None:
                so_flags = manifest['scripts'][row['script']]['adapter_flags']
            row['effective_flags']['adapter'] = so_flags
            row['effective_flags'].update(profile_metadata(so_flags))
            execution_script = script
            if manifest is not None:
                try:
                    generated, audit = adapt_source(directory, row['script'], manifest,
                                                    so_flags)
                    if expectation_manifest is not None:
                        generated, audit = apply_expectations(
                            HERE, row['script'], generated, audit, expectation_manifest)
                    if 'expectation_adjustment' in audit:
                        row['expectation_kind'] = 'ntcp-accounting'
                        reasons = preflight(generated.decode(), audit.get('embedded_tcp_info') is True)
                        if reasons:
                            raise ValueError('accounting fixture preflight: ' + '; '.join(reasons))
                    row['adaptation'] = audit
                    if audit.get('blocked_reasons'):
                        row.update(status='unsupported', reasons=audit['blocked_reasons'])
                    elif variant != 'ipv4':
                        row.update(status='unsupported', reasons=['adaptation supports IPv4 only'])
                    else:
                        execution_script = Path(temporary) / script.name
                        execution_script.write_bytes(generated)
                        text = generated.decode()
                        row['adapted'] = True
                except (ValueError, OSError) as error:
                    row.update(status='adaptation_rejected', reasons=[str(error)])
            if 'status' not in row:
                row['stage'] = 'syntax'
                code, expired, log = invoke_runner(
                    [str(runner), '--dry_run', *flags, str(execution_script)],
                    execution_script.parent, args.timeout)
                row['syntax_returncode'] = code
                row['syntax_log'] = log
                if code != 0 or expired:
                    row.update(status='syntax_error' if code is not None and not expired
                               else 'environment_error', log=log)
                else:
                    row['stage'] = 'preflight'
                    embedded_tcp_info = (row['adapted'] and
                                         row['adaptation'].get('embedded_tcp_info') is True)
                    reasons = preflight(text, embedded_tcp_info, resource_control=(row['adapted'] and row['adaptation'].get('resource_control') is True))
                    if variant not in ('native-ipv4', 'ipv4'):
                        reasons.append('the adapter implements IPv4 only')
                    if reasons:
                        row.update(status='unsupported', reasons=reasons)
                    else:
                        # Namespace isolation is required, never fall back to host.
                        # Teardown and direct libc calls must share the plugin's socket registry.
                        preload = ['env', 'PYTHONOPTIMIZE=0', f'LD_PRELOAD={plugin}']
                        row['effective_flags']['preload'] = str(plugin)
                        code_flags = []
                        if provenance is not None:
                            if embedded_tcp_info and tcp_info_only(text):
                                code_flags = ['--code_sockopt=TCP_INFO_PREFIX']
                            elif so_flags.split(',')[0] == LINUX_COOKIE_OPTION:
                                code_flags = ['--code_sockopt=TCP_INFO']
                        row['effective_flags']['packetdrill'] = [*flags, *code_flags]
                        argv = ['unshare', '--user', '--map-root-user', '--net',
                                *preload, str(runner), f'--so_filename={plugin}',
                                f'--so_flags={so_flags}', *flags, *code_flags, str(execution_script)]
                        fixture = row.get('adaptation', {}).get('fixture')
                        if fixture:
                            try:
                                argv = fixture_command(argv, runner, plugin)
                            except (ValueError, OSError) as error:
                                row.update(status='unsupported', stage='environment',
                                           reasons=[str(error)])
                                results.append(row)
                                print(f'unsupported: {row["script"]} ({variant}, {args.suite})', flush=True)
                                continue
                            row['effective_flags']['fixture'] = fixture
                        try:
                            check_plugin_hash(plugin, plugin_sha256)
                            code, expired, log = invoke_runner(argv, execution_script.parent, args.timeout)
                            check_plugin_hash(plugin, plugin_sha256)
                        except (ValueError, OSError) as error:
                            parser.error(str(error))
                        status = outcome(code, expired, log)
                        fixture_unavailable = fixture and (
                            FIXTURE_UNSUPPORTED in log or log.startswith('unshare:')
                            or status == 'environment_error')
                        if fixture_unavailable:
                            status = 'unsupported'
                            row['reasons'] = ['isolated fixture unavailable: ' + log.strip()]
                        row.update(status=status, returncode=code,
                                   stage='environment' if status == 'environment_error' or fixture_unavailable else 'behavior',
                                   behavior_executed=status != 'environment_error' and not fixture_unavailable, log=log)
            results.append(row)
            expectation_label = (', ntcp-accounting'
                                 if row['expectation_kind'] == 'ntcp-accounting' else '')
            print(f'{row["status"]}: {row["script"]} ({variant}, {args.suite}{expectation_label})', flush=True)
    try:
        check_plugin_hash(plugin, plugin_sha256)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    check_runner()
    counts = dict(collections.Counter(row['status'] for row in results))
    report = {'upstream_revision': revision, 'suite': args.suite,
              'adapter_flags': args.so_flags, 'script_files': selected_script_files,
              'eligible_script_files': len(scripts),
              'eligible_total': len(cases) + len(excluded),
              'selected_total': len(cases), 'excluded_total': len(excluded),
              'selection': {'variants': args.variant, 'scripts': args.script},
              'excluded_cases': excluded,
              'syntax_valid': sum(row['syntax_returncode'] == 0 for row in results),
              'behavior_executed': sum(row['behavior_executed'] for row in results),
              'runner_path': str(runner),
              'runner_provenance': provenance,
              'runner_sha256': hashlib.sha256(runner.read_bytes()).hexdigest(),
              'plugin_path': str(plugin),
              'plugin_sha256': plugin_sha256,
              'socket_backend': socket_backend,
              'counts': counts,
              'expectations': ('ntcp' if args.suite == 'ntcp-ported' else
                               'upstream' if upstream else 'native'),
              'counts_by_expectation': {
                  kind: dict(collections.Counter(row['status'] for row in results
                                                 if row['expectation_kind'] == kind))
                  for kind in sorted({row['expectation_kind'] for row in results})},
              'total': len(results), 'results': results,
              'all_passed': bool(results) and len(results) == len(cases) and all(
                  row['status'] == 'passed' and row['behavior_executed']
                  for row in results)}
    if upstream:
        report['coverage'] = {'selected_script_files': selected_script_files,
                              'upstream_script_files': len(upstream_scripts),
                              'selection': ('ported_registry' if args.suite == 'ntcp-ported' else
                                            'adaptation_allowlist' if manifest is not None
                                            else 'all_tracked_upstream_scripts')}
        report['ported_exclusions'] = [row for row in excluded
                                       if PORTED_EXCLUSION in row['reasons']]
    if manifest is not None:
        report['adaptation_manifest_sha256'] = hashlib.sha256(manifest_bytes).hexdigest()
    if expectation_manifest_sha256 is not None:
        report['expectation_manifest_sha256'] = expectation_manifest_sha256
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(counts, sort_keys=True))
    # Unsupported/syntax-only checks are NEVER reported as a passing suite.
    return 0 if report['all_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
