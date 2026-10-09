"""Private config fixtures; directory must be a harness-owned TemporaryDirectory."""
import tempfile


def config_env(directory, **settings):
    # The enclosing directory outlives every child, including namespace children.
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', prefix='socket-',
                                     suffix='.conf', dir=directory, delete=False) as config:
        for key, value in settings.items():
            config.write(f'{key}={value}\n')
    return {'NTCP_SOCKET_CONFIG': config.name}
