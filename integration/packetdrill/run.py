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
IMPLICIT_TFO_LISTENER_SCRIPTS = {
    'fastopen/server/opt34/' + name + '.pkt'
    for name in ('basic-rw', 'basic-zero-payload', 'listener-closed-trigger-rst',
                 'reset-close-with-unread-data', 'reset-non-tfo-socket',
                 'unread-data-closed-trigger-rst')}
LINUX_COOKIE_SCRIPTS = {
    'fastopen/server/opt34/' + name + '.pkt'
    for name in ('fin-close-socket', 'reset-after-accept', 'reset-before-accept')} | IMPLICIT_TFO_LISTENER_SCRIPTS | {
    'fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt'}
def linux_key_words(text):
    # sysctl parses four hex u32 words, then cpu_to_le32; socket keys are raw.
    if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{8}){3}', text) is None:
        raise ValueError('invalid Linux TFO sysctl key words')
    return b''.join(int(word, 16).to_bytes(4, 'little') for word in text.split('-')).hex()


CUSTOM_TFO_KEY_WORDS = 'a0bf63f7-ed803d81-cd641d30-cebc4a90'
CUSTOM_TFO_KEY_OPTION = 'tfo-key=' + linux_key_words(CUSTOM_TFO_KEY_WORDS)
CUSTOM_TFO_SETUP = (b'`../../../common/defaults.sh\nsysctl -q \\\n'
                    b'  net.ipv4.tcp_fastopen=0x30403 \\\n'
                    b'  net.ipv4.tcp_fastopen_key=' + CUSTOM_TFO_KEY_WORDS.encode() + b'`\n')


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


SYN_DATA_ACK_SCRIPTS = {
    'fastopen/client/' + name + '.pkt'
    for name in ('syn-data-only-syn-acked', 'syn-data-partial-or-over-ack')}
SYN_DATA_ACK_SETUP = (b'`../../common/defaults.sh\n'
                      b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0 \\\n'
                      b'                             /proc/sys/net/ipv4/tcp_min_tso_segs=2`\n')


SETUP_COMMENT = b'// ntcp setup mapped by adaptations.json; Linux defaults not reproduced.\n'
SYSCTL_RESTORE = b'`/tmp/sysctl_restore_${PPID}.sh`\n'
PROFILE_RESTORED = b'// ntcp profile is process-local; no host sysctls to restore.\n'
ROUTE_RESTORED = b'// ntcp destination routes are local to this runtime.\n'
ROUTE_MAPPING = {
    'destination': '192.0.2.1', 'initial_mtu_cap': 640, 'initial_advertised_mss': 600,
    'initial_search_low': 552, 'updated_mtu_cap': 1500, 'future_advertised_mss': 1460,
    'initial_window': 'Common RFC6928 IW10; byte/window/queued-tail admission already permits this probe, without Linux-specific cwnd>=11 gate.',
    'scope': 'Runtime-owned destination transport policy; synthetic packet context does not configure host gateway/device. Strict scalar capture, no offload.',
    'locked_route': 'Administrative MTU ceiling; ordinary validated ICMP and DF policy retained. No claim of Linux route locking/discovery-disable equivalence.',
}


# Audited per-script controls: one entry per exact upstream source whose setup
# or timed shell commands map to local ntcp controls. adapt_audited_control
# verifies every field against the manifest entry before replacing anything.
#   kind                selects kind-specific handling: 'route' (IPv6-only
#                       variant setup), 'cookieless-server' (option audit) and
#                       'custom-tfo-key' (source addresses, Linux cookie keys)
#   family              audit label used only in rejection messages
#   variant             IP family of the source
#   source_sha256       exact upstream source identity
#   setup               exact setup command, replaced by 'initial' when given,
#                       otherwise by SETUP_COMMENT padded to the same line count
#   events              exact (upstream timed command, local control) line pairs
#   control             manifest flag enabling the local controls (None: no events)
#   event_sha256_key    manifest key holding the event digest(s)
#   restore             exact (restore command, replacement comment) lines
#   settings            required resolved profile settings
#   mapping             required manifest mapping values
#   addresses           packetdrill local/remote addresses for the source family;
#                       a custom TFO key source declares both as option lines
#                       and the manifest records them as packetdrill_addresses
#   refuses_blocked     True: reject an entry with blocked_reasons; otherwise
#                       adapt_source returns a blocked entry's source untouched
AUDITED_CONTROLS = {
    'mtu_probe/basic-v4.pkt': {
        'kind': 'route', 'family': 'route', 'variant': 'ipv4',
        'source_sha256': '0a1d1b8575030cd7db5ad33e0eac66d46863a448f251472ffac38243edc431d0',
        'setup': (b'`../common/defaults.sh\n ../common/set_sysctls.py \\\n'
                  b'\t/proc/sys/net/ipv4/tcp_mtu_probing=2 \\\n'
                  b'\t/proc/sys/net/ipv4/tcp_base_mss=512\n'
                  b' ip route change 192.0.2.1 via 192.168.0.2 dev tun0 advmss 600 mtu lock 640 initcwnd 11\n'
                  b' ethtool -K tun0 gso off tso off\n`\n'),
        'initial': b'0 `ntcp-local-route-set 192.0.2.1 640 600 552`\n\n\n\n\n\n\n',
        'events': [(b'   +0 `ip route change 192.0.2.1 via 192.168.0.2 dev tun0 advmss 1460 mtu lock 1500`\n',
                    b'   +0 `ntcp-local-route-set 192.0.2.1 1500 1460 552`\n')],
        'control': 'route_control', 'event_sha256_key': 'route_event_sha256',
        'restore': (SYSCTL_RESTORE, ROUTE_RESTORED),
        'mapping': {'destination_route': ROUTE_MAPPING},
    },
    'mtu_probe/basic-v6.pkt': {
        'kind': 'route', 'family': 'route', 'variant': 'ipv6',
        'source_sha256': 'd7061284181020bb8b6f6d3e979a14b753e4f1281605031471b0eca08314bb5c',
        'setup': (b'`../common/defaults.sh\n ../common/set_sysctls.py \\\n'
                  b'\t/proc/sys/net/ipv4/tcp_mtu_probing=2 \\\n'
                  b'\t/proc/sys/net/ipv4/tcp_base_mss=512\n'
                  b' ip -6 route change 2001:DB8::1 via fd3d:fa7b:d17d:8888::0 dev tun0 advmss 600 mtu lock 660 initcwnd 11\n'
                  b' ethtool -K tun0 gso off tso off\n`\n'),
        'initial': b'0 `ntcp-local-route-set 2001:db8::1 660 600 572`\n\n\n\n\n\n\n',
        'events': [(b'   +0 `ip -6 route change 2001:DB8::1 via fd3d:fa7b:d17d:8888::0 dev tun0 advmss 1480 mtu lock 1520`\n',
                    b'   +0 `ntcp-local-route-set 2001:db8::1 1520 1480 572`\n')],
        'control': 'route_control', 'event_sha256_key': 'route_event_sha256',
        'restore': (SYSCTL_RESTORE, ROUTE_RESTORED),
        'mapping': {'destination_route': {
            **ROUTE_MAPPING, 'destination': '2001:db8::1',
            'initial_mtu_cap': 660, 'initial_search_low': 572,
            'updated_mtu_cap': 1520, 'future_advertised_mss': 1480,
            'ipv6_minimum': 'Physical link>=1280 and received PTB<1280 rejection retained; explicit route and search values are transport packetization settings.'}},
        'addresses': {'local': 'fd::1', 'remote': '2001:db8::1'},
    },
    'md5/md5-only-on-client-ack.pkt': {
        'kind': 'listener-assertion', 'family': 'listener assertion', 'variant': 'ipv4',
        'source_sha256': 'fff237a75cdf9e0f403d673f80c99e7b7e3ffebefa75d63d240803472c0a2a17',
        'setup': b'`../../common/defaults.sh`\n',
        'events': [(b'   +0 `grep " 0A " /proc/net/tcp /proc/net/tcp6 | grep ":1F90"`\n',
                    b'   +0 `ntcp-local-assert-listener 8080`\n')],
        'control': 'listener_assertion_control', 'event_sha256_key': 'listener_assertion_event_sha256',
    },
    'fastopen/client/nonblocking-sendto-errnos.pkt': {
        'kind': 'tfo-permission', 'family': 'TFO permission', 'variant': 'ipv4',
        'source_sha256': 'e31c659677f65cee707518939e6e13b00a919975ea79446e261c54012f18795b',
        'setup': (b'`../../common/defaults.sh\n'
                  b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0\\\n'
                  b'\t\t\t     /proc/sys/net/ipv4/tcp_fastopen_blackhole_timeout_sec=0\\\n`\n'),
        'events': [(b'   +0 `sysctl -q net.ipv4.tcp_fastopen=0`\n', b'   +0 `ntcp-local-tfo-client-off`\n'),
                   (b'+.005 `sysctl -q net.ipv4.tcp_fastopen=1`\n', b'+.005 `ntcp-local-tfo-client-on`\n')],
        'control': 'tfo_permission_control', 'event_sha256_key': 'tfo_permission_event_sha256',
        'restore': (SYSCTL_RESTORE, PROFILE_RESTORED),
        'settings': {'timestamps': False, 'fast_open_client_enabled': True},
    },
    'fastopen/client/nonblocking-connect-bypass-errno.pkt': {
        'kind': 'tfo-permission', 'family': 'TFO permission', 'variant': 'ipv4',
        'source_sha256': 'fe165852a52c2163edb9d4b12d3687e8abb7c2b5c3111fc84ca5d71653461751',
        'setup': (b'`../../common/defaults.sh\n'
                  b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0\\\n'
                  b'\t\t\t     /proc/sys/net/ipv4/tcp_fastopen_blackhole_timeout_sec=0\\\n`\n'),
        'events': [(b'   +0 `sysctl -q net.ipv4.tcp_fastopen=0`\n', b'   +0 `ntcp-local-tfo-client-off`\n'),
                   (b' +.01 `sysctl -q net.ipv4.tcp_fastopen=1`\n', b' +.01 `ntcp-local-tfo-client-on`\n')],
        'control': 'tfo_permission_control', 'event_sha256_key': 'tfo_permission_event_sha256',
        'restore': (SYSCTL_RESTORE, PROFILE_RESTORED),
        'settings': {'timestamps': False, 'fast_open_client_enabled': True},
    },
    'fastopen/client/cookie-less-sendto.pkt': {
        'kind': 'cookieless-client', 'family': 'cookie-less client', 'variant': 'ipv4',
        'source_sha256': 'b2e6010d739c872f4effb5ebd65290c7808421bad2cffba13cf3317c425dec19',
        'setup': (b'`../../common/defaults.sh\n'
                  b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0 \\\n'
                  b'                             /proc/sys/net/ipv4/tcp_fastopen=5`\n'),
        'events': [(b' +.03 `sysctl -q net.ipv4.tcp_fastopen=1`\n',
                    b' +.03 `ntcp-local-tfo-client-require-cookie`\n')],
        'control': 'cookieless_client_control', 'event_sha256_key': 'cookieless_client_event_sha256',
        'restore': (SYSCTL_RESTORE, PROFILE_RESTORED),
        'settings': {'timestamps': False, 'fast_open_client_policy': 'ApplicationProtected'},
    },
    'fastopen/client/synack-data.pkt': {
        'kind': 'synack-timestamp', 'family': 'SYNACK timestamp', 'variant': 'ipv4',
        'source_sha256': '04060050a00a3f31eff9308ce67a9c232efc6bf402f921dfc40410ed69697c26',
        'setup': (b'`../../common/defaults.sh\n'
                  b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0`\n'),
        'events': [(b'   +0 `sysctl -q net.ipv4.tcp_timestamps=1`\n', b'   +0 `ntcp-local-timestamps-on`\n')],
        'control': 'timestamp_on_control', 'event_sha256_key': 'timestamp_event_sha256',
        'restore': (SYSCTL_RESTORE, PROFILE_RESTORED),
        'settings': {'timestamps': False},
    },
    'fastopen/client/nonblocking-sendto.pkt': {
        'kind': 'cache-flush', 'family': 'cache-flush', 'variant': 'ipv4',
        'source_sha256': 'd72c1847f685d9ea14a7518c508c8b61c427d661c71c48bc506e9bbc81e29f36',
        'setup': (b'`../../common/defaults.sh\n'
                  b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0`\n'),
        'events': [(b'+.001 `sysctl -q net.ipv4.tcp_timestamps=1\n'
                    b'       sysctl -q net.ipv4.tcp_fastopen_cookies=0 net.ipv4.tcp_fastopen_cookies=10 &> /dev/null ||\\\n'
                    b'       ip tcp_metrics flush all &> /dev/null`\n',
                    b'+.001 `ntcp-local-timestamps-on-clear-tfo-cache`\n'
                    b'// Clear learned client cache in this process.\n'
                    b'// Existing connections and server policy remain in place.\n')],
        'control': 'cache_flush_control', 'event_sha256_key': 'cache_flush_event_sha256',
        'restore': (SYSCTL_RESTORE, PROFILE_RESTORED),
        'settings': {'timestamps': False},
    },
    'fastopen/client/syn-data-mss.pkt': {
        'kind': 'timestamp', 'family': 'timestamp', 'variant': 'ipv4',
        'source_sha256': '4f7824b6627baed6f812a60882a31d5a273ac3070359348d3280e12541279fbb',
        'setup': b'`../../common/defaults.sh`\n',
        'events': [(b' +.07 `sysctl -q net.ipv4.tcp_timestamps=0`\n', b' +.07 `ntcp-local-timestamps-off`\n')],
        'control': 'timestamp_control', 'event_sha256_key': 'timestamp_event_sha256',
        'settings': {'timestamps': True},
    },
    'zerocopy/fastopen-client.pkt': {
        'kind': 'timestamp', 'family': 'timestamp', 'variant': 'ipv4',
        'source_sha256': 'e0fa374f4ba5713f7a131e94e808f2bd59e7b2884305af4502debc9d80eb7680',
        'setup': b'`../../common/defaults.sh`\n',
        'events': [(b' +.07 `sysctl -q net.ipv4.tcp_timestamps=0`\n', b' +.07 `ntcp-local-timestamps-off`\n')],
        'control': 'timestamp_control', 'event_sha256_key': 'timestamp_event_sha256',
        'settings': {'timestamps': True},
    },
    'user_timeout/user-timeout-probe.pkt': {
        'kind': 'resource', 'family': 'resource', 'variant': 'ipv4',
        'source_sha256': 'fbbf50f3e1d2facf9835267513fe709665db245d1f2234f98dd448d8be59d564',
        'setup': b'`../../common/defaults.sh`\n',
        'events': [(b'   +0 `tc qdisc delete dev tun0 root 2>/dev/null ; tc qdisc add dev tun0 root pfifo limit 0`\n',
                    b'   +0 `ntcp-local-resource-reject-on`\n')],
        'control': 'resource_control', 'event_sha256_key': 'resource_event_sha256',
    },
    'fastopen/server/basic-cookie-not-reqd.pkt': {
        'kind': 'cookieless-server', 'family': 'cookieless server', 'variant': 'ipv4',
        'source_sha256': '2039dc9526b6f58746892cc5bed1a5561aa221deb60b4f98c94c29d5ee7e8fb4',
        'setup': (b'`../../common/defaults.sh\n'
                  b' ../../common/set_sysctls.py  /proc/sys/net/ipv4/tcp_fastopen=0x202`\n'),
        'events': [], 'control': None, 'refuses_blocked': True,
        'restore': (SYSCTL_RESTORE, PROFILE_RESTORED),
        'settings': {'fast_open_early_data_policy': 'ApplicationProtected',
                     'fast_open_client_default': False, 'fast_open_listener_default': False},
    },
    'fastopen/server/opt34/basic-cookie-not-reqd.pkt': {
        'kind': 'cookieless-server', 'family': 'cookieless server', 'variant': 'ipv4',
        'source_sha256': '18b465a3233d63fe44a93bac33f79dc611cebe648fde137f0aa18fcda423ec5b',
        'setup': b'`../../../common/defaults.sh\n sysctl -q net.ipv4.tcp_fastopen=0x202`\n',
        'events': [], 'control': None, 'refuses_blocked': True,
        'settings': {'fast_open_early_data_policy': 'ApplicationProtected',
                     'fast_open_client_default': False, 'fast_open_listener_default': False},
    },
    'zerocopy/fastopen-server.pkt': {
        'kind': 'cookieless-server', 'family': 'cookieless server', 'variant': 'ipv4',
        'source_sha256': '7c0780243e6adf4d2be3a577480ef93665b6ba4157204aa12a7408df058d4dfb',
        'setup': (b'`../../common/defaults.sh\n'
                  b' ../common/set_sysctls.py /proc/sys/net/ipv4/tcp_fastopen=0x207`\n'),
        'events': [], 'control': None, 'refuses_blocked': True,
        'restore': (SYSCTL_RESTORE, PROFILE_RESTORED),
        'settings': {'fast_open_early_data_policy': 'ApplicationProtected',
                     'fast_open_client_default': False, 'fast_open_listener_default': False},
    },
    'fastopen/server/opt34/simple1.pkt': {
        'kind': 'custom-tfo-key', 'family': 'custom TFO key', 'variant': 'ipv4',
        'source_sha256': '9e45042fd5b0a54e9945c29b1e68a56a371f269fc65764def26b7b1eef55fb97',
        'setup': CUSTOM_TFO_SETUP, 'events': [], 'control': None,
        'addresses': {'local': '192.168.0.2', 'remote': '10.248.0.2'},
    },
    'fastopen/server/opt34/simple2.pkt': {
        'kind': 'custom-tfo-key', 'family': 'custom TFO key', 'variant': 'ipv4',
        'source_sha256': '0f9820906d0cd370315843bf0dd906756b05cb22f98d6531a9523f3178844e49',
        'setup': CUSTOM_TFO_SETUP, 'events': [], 'control': None,
        'addresses': {'local': '192.168.0.2', 'remote': '10.248.0.3'},
    },
    'fastopen/server/opt34/simple3.pkt': {
        'kind': 'custom-tfo-key', 'family': 'custom TFO key', 'variant': 'ipv4',
        'source_sha256': '56c755f8291fe24914faa31fbf1187bfbef16257bb51a418a108c0f8c4fb226f',
        'setup': CUSTOM_TFO_SETUP, 'events': [], 'control': None,
        'addresses': {'local': '192.168.0.3', 'remote': '10.248.0.3'},
    },
}
CUSTOM_TFO_SCRIPTS = frozenset(name for name, control in AUDITED_CONTROLS.items()
                               if control['kind'] == 'custom-tfo-key')


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

for _name in IMPLICIT_TFO_LISTENER_SCRIPTS:
    UPSTREAM_OPTION_AUDIT[_name] = {
        'linux-cookie': 'Original defaults key and kind34 cookie require the existing feature-gated Linux SipHash policy.',
        'tfo-listen': 'defaults.sh tcp_fastopen=0x70403 enables listeners without TCP_FASTOPEN; enable the existing bounded TFO listener machinery for newly created sockets.',
    }
UPSTREAM_OPTION_AUDIT['fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt'] = {
    'linux-cookie': 'Original kind34 cookie and explicit TCP_FASTOPEN listener use the defaults key and existing Linux SipHash policy.',
}
for _name in SYN_DATA_ACK_SCRIPTS:
    UPSTREAM_OPTION_AUDIT[_name] = {
        'budget224m': 'Multi-connection trace retains socket storage; use the existing bounded seven-connection budget without changing buffer accounting.',
        'prealloc3': 'Reserve three charged connection pools before timed events, as for the existing multi-connection TFO cases.',
        'no-timestamps': 'Exact setup disables timestamps; tcp_min_tso_segs=2 uses the existing common minimum software group size. Packet and PRR expectations remain unchanged.',
    }
UPSTREAM_OPTION_AUDIT['fastopen/client/syn-data-mss.pkt'] = {
    'budget224m': 'Five client connections retain receive/send/scoreboard/RACK storage across the timed MSS and timestamp-default changes; use the existing bounded seven-connection budget without changing per-socket accounting.',
}
UPSTREAM_OPTION_AUDIT['zerocopy/fastopen-client.pkt'] = {
    'budget128m': 'Two client connections retain charged receive/send/scoreboard/RACK storage across warmup and TIME-WAIT; the existing bounded budget accommodates both without changing per-socket accounting.',
}
UPSTREAM_OPTION_AUDIT['fastopen/client/synack-data.pkt'] = {
    'no-timestamps': 'Original setup disables timestamps until the exact timed event enables negotiation for future connections; existing connections and TFO cache remain unchanged.',
    'budget224m': 'Six sequential client connections retain charged active and closing storage across the original trace; use the existing bounded seven-connection budget without changing per-socket accounting.',
}
UPSTREAM_OPTION_AUDIT['fastopen/client/nonblocking-sendto.pkt'] = {
    'no-timestamps': 'Original setup disables timestamps until the exact timed event enables future negotiation.',
    'budget224m': 'Seven sequential client connections retain charged warmup/TIME-WAIT and active storage across an explicit client-cache flush; the existing bounded budget preserves native per-socket accounting.',
}
UPSTREAM_OPTION_AUDIT['fastopen/client/nonblocking-sendto-errnos.pkt'] = {
    'budget224m': 'Original sequential client connections retain active and closing storage across the error/state sequence; the existing bounded budget preserves native per-socket accounting.',
    'no-timestamps': 'Exact initial setup disables timestamps throughout the original script.',
}
UPSTREAM_OPTION_AUDIT['fastopen/client/nonblocking-connect-bypass-errno.pkt'] = {
    'budget224m': 'Original sequential client connections retain active and closing storage across the error/state sequence; the existing bounded budget preserves native per-socket accounting.',
    'no-timestamps': 'Exact initial setup disables timestamps throughout the original script.',
}
UPSTREAM_OPTION_AUDIT['zerocopy/maxfrags.pkt'] = {
    'budget224m': 'Original SO_SNDBUF=2000000 needs the existing bounded budget for native doubled/clamped capacity and resize staging. Linux page-fragment accounting is not emulated.',
}


for _name in ('fastopen/server/opt34/basic-rw.pkt',
              'fastopen/server/opt34/basic-zero-payload.pkt',
              'fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt'):
    UPSTREAM_OPTION_AUDIT[_name]['early-response'] = 'Original authenticated TFO trace writes response data before final handshake ACK. Enable existing core early response under the configured IW policy; validation, quotas and all window limits still apply.'


UPSTREAM_OPTION_AUDIT['fastopen/client/syn-data-only-syn-acked.pkt'].pop('prealloc3')
UPSTREAM_OPTION_AUDIT['fastopen/client/syn-data-only-syn-acked.pkt']['prealloc4'] = 'The unchanged source creates four distinct client connections including retained warmup/TIME_WAIT storage; pre-touch four charged pools within budget224m before timed events.'


for _name in CUSTOM_TFO_SCRIPTS:
    UPSTREAM_OPTION_AUDIT[_name] = {
        'linux-cookie': 'Original custom master key and kind34 cookies use the existing feature-gated Linux SipHash policy.',
        CUSTOM_TFO_KEY_OPTION: 'Exact four sysctl hex words become16 raw key bytes, little-endian per word, before listener creation; reused listeners inherit the endpoint policy.',
        'tfo-listen': 'Exact tcp_fastopen=0x30403 includes implicit server listener enablement; use existing bounded authenticated listener machinery. No FOEXP or cookieless behavior is enabled.',
        'budget128m': 'The first accepted child retains TIME_WAIT storage while a new listener admits the second child; bounded128MiB budget preserves per-socket accounting.',
        'prealloc3': 'Pre-touch three charged connection pools before timed events; no unbounded allocation or timing tolerance changes.',
    }
UPSTREAM_OPTION_AUDIT['fastopen/server/opt34/simple3.pkt']['early-response'] = 'Original script writes15000 bytes before the final handshake ACK; enable existing authenticated early response without changing window or grouping policy.'


UPSTREAM_OPTION_AUDIT['mtu_probe/basic-v6.pkt'] = {
    'link-mtu=1520': 'Pinned synthetic IPv6 link MTU1520; physical minimum retained independently of administrative route660 and initial search572.',
    'no-gso': 'Original strict segment checking disables GSO/TSO; disable software aggregation without changing TCP packet assertions.',
}

UPSTREAM_OPTION_AUDIT['mtu_probe/basic-v4.pkt'] = {
    'pmtud1500': 'Actual1500-byte local interface bound; destination route cap and search-low are independently configured through the shared owner API.',
    'no-gso': 'Original disables GSO/TSO and uses strict segment checking; disable software aggregation, retaining individual wire packets.',
}


UPSTREAM_OPTION_AUDIT['fastopen/client/cookie-less-sendto.pkt'] = {
    'application-protected-tfo-client': 'Exact tcp_fastopen=5 explicitly selects option-omitted active-open data for protected services; retain conservative cold peer MSS, actual SYN accounting and negative-response evidence.',
    'no-timestamps': 'Exact initial setup disables timestamps throughout the source.',
    'budget224m': 'Five sequential connections retain charged active and closing pools; use the existing bounded seven-connection budget without changing per-socket accounting.',
}


for _name, _control in AUDITED_CONTROLS.items():
    if _control['kind'] == 'cookieless-server':
        UPSTREAM_OPTION_AUDIT[_name] = {
            'application-protected-tfo': 'Exact server bit0x200 selects explicit listener application-protected admission; skip cookie MAC verification/generation, retain endpoint/listener enablement, pending/reset-debt quota and TCP validation. Client no-cookie policy remains off.',
        }
UPSTREAM_OPTION_AUDIT['zerocopy/fastopen-server.pkt']['early-response'] = 'The original server sends1000 response bytes before final handshake ACK; enable existing bounded early response. The ordinary unregistered payload retains explicit COPIED completion.'

def variant_setup(relative, generated, so_flags, variant):
    """Map only the pinned runner's family parameters; body bytes stay exact."""
    control = AUDITED_CONTROLS.get(relative)
    if control is not None and control['kind'] == 'route' and control['variant'] == 'ipv6':
        if variant != 'ipv6' or so_flags != upstream_flags(relative):
            return so_flags, None, ['IPv6-only route source requires exact audited addressing']
        return so_flags, {'variant': variant, 'mapping': 'Original IPv6 local and route destination addresses',
                          'canonical_adapter_flags': so_flags, 'adapter_flags': so_flags,
                          'packetdrill_flags': execution_variant_flags(relative, variant),
                          'generated_sha256': hashlib.sha256(generated).hexdigest(),
                          'body_rewritten': False}, []
    if variant == 'ipv4':
        return so_flags, None, []
    if variant == 'ipv4-mapped-v6':
        if so_flags != upstream_flags(relative):
            return so_flags, None, ['mapped setup differs from exact audited mapping']
        return so_flags, {'variant': variant,
                          'mapping': 'IPv6 socket API with configured IPv4 transport',
                          'canonical_adapter_flags': so_flags, 'adapter_flags': so_flags,
                          'packetdrill_flags': execution_variant_flags(relative, variant),
                          'generated_sha256': hashlib.sha256(generated).hexdigest(),
                          'body_rewritten': False}, []
    if variant != 'ipv6':
        return so_flags, None, ['unknown IP execution variant']
    if so_flags != upstream_flags(relative) or 'local=192.168.0.1' not in so_flags.split(','):
        return so_flags, None, ['IPv6 mapping requires audited common local addressing']
    # Literal AF_INET addresses, route commands and IP-level socket controls
    # require a separate family audit; never rewrite those upstream assertions.
    body = re.sub(rb'//[^\n]*', b'', generated)
    # Recognize supported cross-family option aliases only in option argument
    # positions. This inspection view never replaces the executable script.
    shared_aliases = set()
    def shared_option(match):
        shared_aliases.add(match[2].decode() + '/IP_FREEBIND')
        return match[1] + b'FAMILY_SHARED_OPTION' + match[3] + b'FREEBIND' + match[4]
    inspected = re.sub(
        rb'(\b(?:set|get)sockopt\s*\(\s*[^,\n()]+,\s*)(SOL_IP|IPPROTO_IP)(\s*,\s*)IP_FREEBIND(\s*,)',
        shared_option, body)
    if re.search(rb'\b(?:IPPROTO_IP|SOL_IP|IP_TOS|IP_MTU_DISCOVER|IP_MTU|IP_FREEBIND|sockaddr_in)\b|\b(?:\d{1,3}\.){3}\d{1,3}\b', inspected):
        return so_flags, None, ['IPv6 mapping requires audit of explicit IPv4 address or socket control']
    if re.search(rb'\bicmp\b[^\n]*(?:\bfrag_needed\b|\bCODE\b)', body):
        return so_flags, None, ['pinned IPv6 runner cannot parse the original IPv4 ICMP error code']
    local = next(flag.split('=', 1)[1] for flag in PIN['variants']['ipv6']
                 if flag.startswith('--local_ip='))
    resolved = so_flags.replace(',local=192.168.0.1', ',local=' + local, 1)
    audit = {'variant': 'ipv6', 'mapping': 'pinned pure IPv6 runner parameters',
             'canonical_adapter_flags': so_flags, 'adapter_flags': resolved,
             'packetdrill_flags': PIN['variants']['ipv6'],
             'generated_sha256': hashlib.sha256(generated).hexdigest(),
             'body_rewritten': False}
    if shared_aliases:
        audit['shared_socket_option_aliases'] = sorted(shared_aliases)
    return resolved, audit, []


def execution_variant_flags(relative, variant):
    flags = list(PIN['variants'][variant])
    control = AUDITED_CONTROLS.get(relative)
    # Audited addresses apply to runs over the source's own IP family;
    # ipv4-mapped-v6 keeps IPv4 transport behind the IPv6 socket API.
    transport = 'ipv6' if variant == 'ipv6' else 'ipv4'
    if control is not None and 'addresses' in control and control['variant'] == transport:
        local, remote = control['addresses']['local'], control['addresses']['remote']
        flags = [f'--local_ip={local}' if token.startswith('--local_ip=')
                 else f'--remote_ip={remote}' if token.startswith('--remote_ip=')
                 else token for token in flags]
    return flags


def upstream_flags(relative):
    control = AUDITED_CONTROLS.get(relative)
    local = control['addresses']['local'] if control is not None and 'addresses' in control else '192.168.0.1'
    return "upstream,local=" + local + "".join("," + token for token in sorted(UPSTREAM_OPTION_AUDIT.get(relative, {})))


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


TCP_INFO_FIELDS = {'tcpi_state', 'tcpi_ca_state', 'tcpi_probes', 'tcpi_backoff', 'tcpi_unacked', 'tcpi_sacked',
                   'tcpi_lost', 'tcpi_retrans', 'tcpi_reordering',
                   'tcpi_snd_cwnd', 'tcpi_snd_ssthresh', 'tcpi_rtt', 'tcpi_min_rtt', 'tcpi_reord_seen',
                   'tcpi_notsent_bytes', 'tcpi_last_data_recv', 'tcpi_busy_time',
                   'tcpi_rwnd_limited', 'tcpi_sndbuf_limited', 'tcpi_delivered',
                   'tcpi_options', 'tcpi_snd_wscale', 'tcpi_rcv_wscale', 'tcpi_snd_mss', 'tcpi_rcv_mss', 'tcpi_advmss'}


TCP_INFO_OPTION_BITS = {'TCPI_OPT_TIMESTAMPS': 1, 'TCPI_OPT_SACK': 2,
                        'TCPI_OPT_WSCALE': 4, 'TCPI_OPT_ECN': 8,
                        'TCPI_OPT_SYN_DATA': 32}


TCP_INFO_SYMBOLS = {'TCP_CA_Open', 'TCP_CA_Disorder', 'TCP_CA_CWR',
                    'TCP_CA_Recovery', 'TCP_CA_Loss', 'TCP_ESTABLISHED',
                    'TCP_CLOSE', 'TCP_CLOSE_WAIT'} | TCP_INFO_OPTION_BITS.keys()


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


def enabled_controls(audit):
    """Names of the local controls an audited adaptation entry enables."""
    return tuple(key for key, value in audit.items()
                 if key.endswith('_control') and value is True)


def preflight(text, embedded_tcp_info=False, controls=()):
    # Conservative safety/capability screening, NOT a second packetdrill parser.
    # Upstream --dry_run remains the authority for script syntax.
    # Inspect raw text conservatively, including comments: do not accidentally
    # strip a command concealed by comment-like characters inside a string.
    reasons = []
    shell_text = text
    # Each enabled control exempts the local commands of one audited entry, and
    # only when every one of them occurs exactly once.
    exempted = set()
    for control in AUDITED_CONTROLS.values():
        name = control['control']
        if name is None or name not in controls or name in exempted:
            continue
        commands = [local.decode() for _, local in control['events']]
        if 'initial' in control:
            commands.append(control['initial'].decode())
        if all(text.count(command) == 1 for command in commands):
            for command in commands:
                shell_text = shell_text.replace(command, '', 1)
            exempted.add(name)
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


def adapt_audited_control(source, entry, metadata, control):
    """Verify one AUDITED_CONTROLS entry completely, then replace only its lines."""
    message = f"expected exact audited {control['family']} setup"
    if len(control['events']) == 1:
        message += ' and timed command'
    elif control['events']:
        message += ' and timed commands'
    setup = control['setup']
    # Keep the audited setup's line count so original line numbers survive.
    replacement = control.get('initial', SETUP_COMMENT + b'\n' * (setup.count(b'\n') - 1))
    replacements = [(setup, replacement), *control['events']]
    if 'restore' in control:
        replacements.append(control['restore'])
    # Shell commands in source order: setup, timed events, then restore.
    commands = [old[old.index(b'`'):].rstrip(b'\n') for old, _ in replacements]
    # A blocked entry reaches this point only when its table entry refuses it.
    if (entry.get('blocked_reasons')
            or hashlib.sha256(source).hexdigest() != control['source_sha256']
            or entry.get('variant') != control['variant']
            or entry.get('setup_path') != 'common/defaults.sh'
            or entry.get('command_line') != setup.decode()
            or entry.get('command_sha256') != hashlib.sha256(setup).hexdigest()
            or entry.get('replacement_line') != replacement.decode()
            or entry.get('expected_command_count') != len(commands)
            or re.findall(rb'`[^`]*`', source) != commands
            or [(c['command'], c['sha256']) for c in entry.get('audited_shell_commands', [])]
                != [(c.decode(), hashlib.sha256(c).hexdigest()) for c in commands]
            or any(metadata.get(key) != value for key, value in control.get('settings', {}).items())
            or any(entry['mapping'].get(key) != value for key, value in control.get('mapping', {}).items())
            or any(source.count(old) != 1 or not (source.startswith(old) or b'\n' + old in source)
                   for old, _ in replacements)):
        raise ValueError(message)
    if control['control'] is not None:
        digests = [hashlib.sha256(event).hexdigest() for event, _ in control['events']]
        # The manifest records a single timed event as one digest, several as a list.
        recorded = digests[0] if len(digests) == 1 else digests
        if entry.get(control['control']) is not True or entry.get(control['event_sha256_key']) != recorded:
            raise ValueError(message)
    if 'restore' in control:
        restore, restored = control['restore']
        # The setup helper writes the restore script that the source runs.
        if (entry.get('restore_line') != restore.decode()
                or entry.get('restore_sha256') != hashlib.sha256(restore).hexdigest()
                or entry.get('restore_replacement_line') != restored.decode()
                or not any(extra['path'] == 'common/set_sysctls.py'
                           for extra in entry.get('additional_setup_files', []))):
            raise ValueError(message)
    if control['kind'] == 'custom-tfo-key':
        # The source declares the audited addresses; the manifest records the same pair.
        addresses = control['addresses']
        address_lines = [f"--local_ip={addresses['local']}".encode(),
                         f"--remote_ip={addresses['remote']}".encode()]
        if (re.findall(rb'^--(?:local|remote)_ip=.*$', source, re.M) != address_lines
                or entry['mapping'].get('packetdrill_addresses') != addresses):
            raise ValueError(message)
    generated = source
    for old, new in replacements:
        generated = generated.replace(old, new, 1)
    controls = () if control['control'] is None else (control['control'],)
    reasons = preflight(generated.decode(), entry.get('embedded_tcp_info') is True, controls)
    if reasons:
        raise ValueError('; '.join(reasons))
    return generated, {**entry, 'generated_sha256': hashlib.sha256(generated).hexdigest()}


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
    control = AUDITED_CONTROLS.get(relative)
    refuses_blocked = control is not None and control.get('refuses_blocked', False)
    if entry.get('blocked_reasons') and not refuses_blocked:
        # Keep unavailable shell/configuration and embedded assertions untouched.
        # The caller reports the audit but must never execute this source.
        return source, dict(entry)
    if LINUX_COOKIE_OPTION in so_flags.split(',') and relative not in LINUX_COOKIE_SCRIPTS | CUSTOM_TFO_SCRIPTS:
        raise ValueError('Linux cookie setup is limited to audited explicit listeners')
    if FASTOPEN_PMTUD_OPTION in so_flags.split(',') and relative not in FASTOPEN_PMTUD_SCRIPTS | {'mtu_probe/basic-v4.pkt'}:
        raise ValueError('Fast Open PMTUD setup is limited to two audited ICMP cases')
    if ADAPTIVE_ACK_OPTION in so_flags.split(',') and relative not in ADAPTIVE_ACK_SCRIPTS:
        raise ValueError('Adaptive ACK setup is limited to three audited blocking clients')
    if control is not None:
        return adapt_audited_control(source, entry, metadata, control)
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
        **{name: SYN_DATA_ACK_SETUP for name in SYN_DATA_ACK_SCRIPTS},
    }
    for name in FASTOPEN_CLIENT_SCRIPTS | ADAPTIVE_ACK_SCRIPTS | FASTOPEN_PMTUD_SCRIPTS:
        setup_commands[name] = (
            b'`../../common/defaults.sh\n'
            b' ../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0`\n')
    for name in LINUX_COOKIE_SCRIPTS:
        setup_commands[name] = (b'`../../../common/defaults.sh`\n'
                                if name.startswith('fastopen/server/opt34/')
                                else b'`../../common/defaults.sh`\n')
    if relative in setup_commands:
        expected = setup_commands[relative]
        commands = [command.rstrip(b'\n')]
        replacements = [(command, replacement)]
        if (relative in FASTOPEN_CLIENT_SCRIPTS | ADAPTIVE_ACK_SCRIPTS | FASTOPEN_PMTUD_SCRIPTS | SYN_DATA_ACK_SCRIPTS
                or relative in {'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt', 'nagle/https_client.pkt',
                                'fastopen/server/basic-non-tfo-listener.pkt',
                                'fastopen/server/icmp-baseline.pkt'}):
            if (entry.get('restore_line', '').encode() != SYSCTL_RESTORE
                    or entry.get('restore_sha256') != hashlib.sha256(SYSCTL_RESTORE).hexdigest()
                    or entry.get('restore_replacement_line', '').encode() != PROFILE_RESTORED
                    or not any(extra['path'] == 'common/set_sysctls.py'
                               for extra in entry.get('additional_setup_files', []))):
                raise ValueError('expected exact audited restore and setup helper')
            commands.append(SYSCTL_RESTORE.rstrip(b'\n'))
            replacements.append((SYSCTL_RESTORE, PROFILE_RESTORED))
        expected_replacement = SETUP_COMMENT
        if (relative in FASTOPEN_PMTUD_SCRIPTS | ADAPTIVE_ACK_SCRIPTS | FASTOPEN_CLIENT_SCRIPTS | SLOW_START_ACK_SCRIPTS
                or relative in NON_TFO_SETUP_COMMANDS and expected.count(b'\n') == 2):
            expected_replacement += b'\n'  # Keep the audited two-line setup's line numbers.
        if relative in SYN_DATA_ACK_SCRIPTS:
            expected_replacement += b'\n' * (expected.count(b'\n') - 1)
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
            or replacement != SETUP_COMMENT
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
                if suite in ('upstream', 'ntcp-ported'):
                    flags = execution_variant_flags(relative, variant)
                selected.append((script, variant, flags))
    if not selected and not any(PORTED_EXCLUSION in row['reasons'] for row in excluded):
        raise ValueError('selection matches no eligible packetdrill cases')
    return selected, excluded


UPSTREAM_OPTIONS = {'application-protected-tfo', 'application-protected-tfo-client',
    'no-timestamps', 'ecn', 'adaptive-ack', 'lowat4000', 'linux-cookie', 'pmtud1500',
    'budget128m', 'budget224m', 'prealloc3', 'prealloc4', 'immediate-ack', 'peer-ack-delay200ms',
    'abort-with-ack', 'coalesce-read-window',
    'reno', 'paced', 'receive64k', 'tfo-listen', 'early-response', 'no-gso',
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
        address = ipaddress.ip_address(local[0]) if len(local) == 1 else None
        valid_local = address is not None and not (address.is_loopback or address.is_multicast or address.is_unspecified or (address.version == 6 and (address.ipv4_mapped is not None or address.is_link_local)))
    except ValueError:
        valid_local = False
    keys = [token[8:] for token in policies if token.startswith('tfo-key=')]
    key_tokens = {token for token in options if token.startswith('tfo-key=')}
    valid_key = (not keys or len(keys) == 1 and re.fullmatch(r'[0-9a-f]{32}', keys[0]) is not None
                 and 'linux-cookie' in options)
    mtu_tokens = {token for token in options if token.startswith('link-mtu=')}
    mtu_text = next(iter(mtu_tokens)).split('=', 1)[1] if len(mtu_tokens) == 1 else None
    valid_mtu = (not mtu_tokens or mtu_text is not None and re.fullmatch(r'[1-9][0-9]*', mtu_text) is not None
                 and (1280 if valid_local and address.version == 6 else 68) <= int(mtu_text) <= 65535
                 and 'pmtud1500' not in options)
    known = (valid_local and valid_key and valid_mtu and profile is not None and len(tokens) == len(set(tokens))
             and (not options or profile == 'upstream' and options - key_tokens - mtu_tokens <= UPSTREAM_OPTIONS)
             and not {'budget128m', 'budget224m'} <= options
             and not {'immediate-ack', 'adaptive-ack'} <= options
             and not {'prealloc3', 'prealloc4'} <= options)
    upstream = profile == 'upstream'
    # Configuration/capture boundary only, never a claim of Linux fq/TSO timing equivalence.
    metadata = {
        'profile': profile,
        'transport_clock': 'monotonic Instant elapsed microseconds',
        'prr_pacing': ('paced' in options if upstream else True),
        'transmit_batch_clock': 'monotonic sample per selection/accept',
        'egress_pipeline': 'shared production scheduler',
        'general_pacing': ('paced' in options if upstream else profile in {'pipeline-paced', 'pipeline-paced-gso'}),
        'software_gso': (upstream and 'no-gso' not in options) or profile in {'pipeline-gso', 'pipeline-paced-gso'},
        'capture_boundary': 'individual raw IPv6 TCP wire segments' if valid_local and address.version == 6 else 'individual raw IPv4 TCP wire segments',
        'capture_clock': 'realtime epoch microseconds at backend submission',
        'hardware_tso': False, 'gro': False, 'receive_tcp_segmentation_metadata': True,
    }
    if not known:
        return {key: value if key == 'profile' else None for key, value in metadata.items()}
    if upstream:
        metadata.update(
            options=sorted(options), fast_open_client_policy='ApplicationProtected' if 'application-protected-tfo-client' in options else 'RequireCookie', fast_open_early_data_policy='ApplicationProtected' if 'application-protected-tfo' in options else 'RequireCookie', fast_open_client_enabled=True, sack=True, timestamps='no-timestamps' not in options,
            initial_window='Iw10', fast_open_early_response='early-response' in options, rack=True, prr='Rfc9937',
            tlp=True, tlp_timer_margin_us=2000, rto_min_us=200000, preallocate_connections=4 if 'prealloc4' in options else 3 if 'prealloc3' in options else 1,
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
            output_group_flush=True,
            global_notsent_lowat=4000 if 'lowat4000' in options else 4294967295,
            socket_notsent_lowat=0, fast_open_client_default=False, fast_open_listener_default=False,
            fast_open_cache='fresh runtime', fast_open_cookie_policy='hmac-sha256',
            pacing_config={'rate_gain_percent': 125, 'max_bytes_per_second': None, 'max_burst_segments': 2, 'initial_window_burst': True} if 'paced' in options else None)
        if 'linux-cookie' in options:
            metadata.update(LINUX_COOKIE_SETTINGS)
            if keys:
                metadata['fast_open_key_hex'] = keys[0]
        if 'tfo-listen' in options:
            metadata.update(fast_open_listener_default=True,
                            implicit_listener_enablement=True,
                            fast_open_listener_limit=128)
        if mtu_tokens:
            metadata['pmtud_first_hop_mtu'] = int(mtu_text)
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
        if (args.suite == 'upstream'
                and set(directory / path for path in manifest['scripts']) != set(upstream_scripts)):
            parser.error('adaptation inventory must cover every tracked upstream TCP script')
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
                        row['expectation_kind'] = audit['expectation_adjustment'].get(
                            'expectation_kind', 'ntcp-accounting')
                        reasons = preflight(generated.decode(), audit.get('embedded_tcp_info') is True,
                                            enabled_controls(audit))
                        if reasons:
                            raise ValueError('accounting fixture preflight: ' + '; '.join(reasons))
                    row['adaptation'] = audit
                    if audit.get('blocked_reasons'):
                        row.update(status='unsupported', reasons=audit['blocked_reasons'])
                    else:
                        so_flags, variant_audit, reasons = variant_setup(row['script'], generated, so_flags, variant)
                        if reasons:
                            row.update(status='unsupported', reasons=reasons)
                        else:
                            if variant_audit is not None:
                                row['adaptation']['variant_setup'] = variant_audit
                            row['effective_flags']['adapter'] = so_flags
                            row['effective_flags'].update(profile_metadata(so_flags))
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
                    controls = enabled_controls(row['adaptation']) if row['adapted'] else ()
                    reasons = preflight(text, embedded_tcp_info, controls)
                    if variant in ('ipv6', 'ipv4-mapped-v6') and not row['adapted']:
                        reasons.append('IPv6 socket execution requires audited family setup')
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
            expectation_label = (', ' + row['expectation_kind']
                                 if args.suite == 'ntcp-ported' else '')
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
