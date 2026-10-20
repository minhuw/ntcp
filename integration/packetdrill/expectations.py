"""Hash-bound host-accounting fixtures, separate from setup-only adaptations."""
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
})
PORTED_EXCLUSION = 'ported to ntcp-ported; excluded from upstream accounting'


def digest(data):
    return hashlib.sha256(data).hexdigest()


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
        original = adaptations['scripts'].get(name)
        if original is None or original.get('blocked_reasons'):
            raise ValueError('accounting expectations cannot enable an unselected/unsupported case')
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
    if audit.get('blocked_reasons'):
        raise ValueError('accounting expectations cannot bypass unsupported setup')
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
    if b'`' in replacement or b'\x00' in replacement:
        raise ValueError('accounting fixtures cannot execute shell or contain NUL')
    result = copy.deepcopy(audit)
    result['setup_generated_sha256'] = digest(generated)
    result['generated_sha256'] = digest(replacement)
    result['expectation_adjustment'] = copy.deepcopy(entry)
    result['upstream_assertions_preserved'] = False
    result['mapping']['assertions_preserved'] = False
    result['mapping']['scope'] = (
        f'{relative}; reviewed ntcp accounting workload, packet and assertion expectations; '
        'transport configuration retained')
    result['mapping']['claim'] = (
        'Documented ntcp host-accounting expectations; adjusted upstream assertions. '
        'Count separately from cases preserving original upstream assertions.')
    result['upstream_setup_mapping'] = copy.deepcopy(audit['mapping'])
    result['mapping']['reasons'] = [
        'Transport configuration is unchanged from upstream_setup_mapping, which records the setup-only input audit.',
        'The reviewed accounting fixture changes workload, packet and assertion expectations after setup adaptation; original assertions are not preserved.',
        entry['rationale'],
    ]
    return replacement, result
