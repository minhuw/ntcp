"""Hash-bound native expectations, separate from setup-only adaptations."""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re


# Ported cases have a single owner: the ntcp-ported suite. Keep selection
# independent of whether the derived fixture currently passes its hash audit.
PORTED_SCRIPTS = frozenset({
    'timestamping/partial.pkt',
    'tcp_info/tcp-info-sndbuf-limited.pkt',
    'epoll/epoll_out_edge.pkt',
    'epoll/epoll_out_edge_default_notsent_lowat.pkt',
    'epoll/epoll_out_edge_notsent_lowat.pkt',
    'notsent_lowat/notsent-lowat-default.pkt',
    'blocking/blocking-write.pkt',
    'fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt',
    'fastopen/server/opt34/simple3.pkt',
    'zerocopy/maxfrags.pkt',
    'mtu_probe/basic-v4.pkt',
})

# These source identities have an independently reviewed native setup. Their
# original setup remains blocked in adaptations.json and upstream accounting.
NATIVE_SETUP_SCRIPTS = frozenset({
    'epoll/epoll_out_edge.pkt',
    'epoll/epoll_out_edge_default_notsent_lowat.pkt',
    'epoll/epoll_out_edge_notsent_lowat.pkt',
    'notsent_lowat/notsent-lowat-default.pkt',
    'blocking/blocking-write.pkt',
})
PORTED_EXCLUSION = 'ported to ntcp-ported; excluded from upstream accounting'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def expectation_kind(entry):
    kind = entry.get('expectation_kind', 'ntcp-accounting')
    if kind not in ('ntcp-accounting', 'ntcp-transport-policy'):
        raise ValueError('unknown ported expectation kind')
    return kind


def validate_native_setup(name, entry, original):
    native = entry.get('native_setup')
    if name not in NATIVE_SETUP_SCRIPTS:
        if native is not None or original.get('blocked_reasons'):
            raise ValueError('accounting expectations cannot bypass unsupported setup')
        return False
    if (not isinstance(native, dict) or not original.get('blocked_reasons')
            or native.get('kind') != 'explicit-native-socket-options'
            or native.get('linux_setup_reproduced') is not False
            or native.get('adapter_flags') != original.get('adapter_flags')
            or native.get('source_command_sha256') != digest(original['command_line'].encode())
            or native.get('source_blocked_reasons') != original['blocked_reasons']
            or entry.get('input_generated_sha256') != original['source_sha256']
            or not native.get('rationale') or not native.get('socket_options')
            or entry.get('fixture') != 'ntcp-expectations/' + name):
        raise ValueError('native accounting setup differs from its source audit')
    return True


def load_expectations(here, revision, adaptations):
    data = (here / 'expectations.json').read_bytes()
    manifest = json.loads(data)
    if manifest.get('schema_version') != 1 or manifest.get('upstream_revision') != revision:
        raise ValueError('accounting expectations schema/revision differs from upstream pin')
    if not isinstance(manifest.get('scripts'), dict):
        raise ValueError('accounting expectations require a script mapping')
    if set(manifest['scripts']) != PORTED_SCRIPTS:
        raise ValueError('accounting expectations differ from the ntcp-ported registry')
    for name, entry in manifest['scripts'].items():
        if not isinstance(entry, dict):
            raise ValueError('accounting expectation must be an object')
        expectation_kind(entry)
        original = adaptations['scripts'].get(name)
        if original is None:
            raise ValueError('accounting expectations cannot enable an unselected case')
        validate_native_setup(name, entry, original)
        if entry.get('source_sha256') != original['source_sha256']:
            raise ValueError('accounting source hash differs from setup audit')
        for key in ('source_sha256', 'input_generated_sha256', 'fixture_sha256'):
            if not re.fullmatch('[0-9a-f]{64}', entry.get(key, '')):
                raise ValueError('accounting expectations require exact SHA256 values')
        path = PurePosixPath(entry.get('fixture', ''))
        if (path.is_absolute() or '..' in path.parts or len(path.parts) < 2
                or path.parts[0] != 'ntcp-expectations' or path.suffix != '.pkt'):
            raise ValueError('accounting fixture must be inside ntcp-expectations')
        if not entry.get('rationale') or not entry.get('changes') or not entry.get('invariants'):
            raise ValueError('accounting adjustment requires rationale, changes and invariants')
    return manifest, digest(data)


def apply_expectations(here, relative, generated, audit, manifest):
    entry = manifest['scripts'].get(relative)
    if entry is None:
        return generated, audit
    kind = expectation_kind(entry)
    native_setup = validate_native_setup(relative, entry, audit)
    if (audit['source_sha256'] != entry['source_sha256']
            or digest(generated) != entry['input_generated_sha256']):
        raise ValueError('accounting input differs from audited setup-only source')
    path = (here / entry['fixture']).resolve()
    root = (here / 'ntcp-expectations').resolve()
    if not root.is_relative_to(here.resolve()) or not path.is_relative_to(root):
        raise ValueError('accounting fixture escapes ntcp-expectations')
    replacement = path.read_bytes()
    if digest(replacement) != entry['fixture_sha256']:
        raise ValueError('accounting fixture hash differs from audited expectations')
    # The caller must check code/options before giving the returned body to
    # packetdrill, even in dry-run mode. Shell/NUL rejection is unconditional.
    screened = replacement
    controls = entry.get('local_controls')
    if controls is not None:
        # Derived fixtures may retain exact, already translated local controls.
        # This grants no new commands: source adaptation and final preflight
        # independently gate the capability. Event lines/hashes cannot change.
        lines = [line for line in generated.splitlines(keepends=True) if b'`' in line]
        expected = {'capability': 'route_control', 'lines': [
            {'line': line.decode(), 'sha256': digest(line)} for line in lines]}
        if (kind != 'ntcp-transport-policy' or audit.get('route_control') is not True
                or controls != expected or not lines
                or any(not re.fullmatch(rb'[ \t]*(?:0|\+0) `ntcp-local-route-set [0-9. ]+`\n', line)
                       for line in lines)
                or [line for line in replacement.splitlines(keepends=True) if b'`' in line] != lines):
            raise ValueError('ported local controls differ from audited setup')
        for line in lines:
            if screened.count(line) != 1:
                raise ValueError('ported local controls must occur exactly once')
            screened = screened.replace(line, b'', 1)
    if b'`' in screened or b'\x00' in replacement:
        raise ValueError('accounting fixtures cannot execute shell or contain NUL')
    result = copy.deepcopy(audit)
    result['expectation_input_sha256'] = digest(generated)
    result['upstream_setup_supported'] = not native_setup
    if native_setup:
        result['upstream_blocked_reasons'] = result.pop('blocked_reasons')
        result['native_setup'] = copy.deepcopy(entry['native_setup'])
    else:
        result['setup_generated_sha256'] = digest(generated)
    result['generated_sha256'] = digest(replacement)
    result['expectation_adjustment'] = copy.deepcopy(entry)
    result['upstream_assertions_preserved'] = False
    result['mapping']['assertions_preserved'] = False
    subject = ('transport-policy' if kind == 'ntcp-transport-policy' else 'host-accounting')
    result['mapping']['scope'] = (
        f'{relative}; reviewed ntcp {subject} workload, packet and assertion expectations; '
        'common transport profile retained; explicit socket setup recorded')
    result['mapping']['claim'] = (
        f'Documented ntcp {subject} expectations; adjusted upstream assertions. '
        'Count separately from cases preserving original upstream assertions.')
    result['upstream_setup_mapping'] = copy.deepcopy(audit['mapping'])
    result['mapping']['reasons'] = [
        ('Original Linux setup remains unsupported; this port uses the common profile and explicit native socket options in a shell-free fixture.'
         if native_setup else
         'Transport configuration is unchanged from upstream_setup_mapping, which records the setup-only input audit.'),
        f'The reviewed {subject} fixture changes workload, packet and assertion expectations; original assertions are not preserved.',
        entry['rationale'],
    ]
    return replacement, result
