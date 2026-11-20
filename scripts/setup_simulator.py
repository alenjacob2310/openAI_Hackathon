"""Create missing local demo credentials without displaying or replacing existing values."""
from __future__ import annotations

import os
import argparse
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import dotenv_values, set_key

SECRET_KEYS = ('MESH_SERVICE_PASSWORD', 'JWT_SECRET_8001', 'JWT_SECRET_8002', 'JWT_SECRET_8003')


def configure_simulator(env_path: Path = ROOT / '.env', *, enable_actions: bool = False) -> list[str]:
    """Preserve configured secrets. Append only values absent from both file and environment."""
    existing = dotenv_values(env_path) if env_path.exists() else {}
    missing = [key for key in SECRET_KEYS if not (os.getenv(key) or existing.get(key))]
    if enable_actions:
        env_path.touch(mode=0o600, exist_ok=True)
        set_key(str(env_path), 'SOC_ENABLE_SIMULATION_ACTIONS', 'true')
        env_path.chmod(0o600)
    if not missing:
        return []
    content = env_path.read_text(encoding='utf-8') if env_path.exists() else ''
    if content and not content.endswith('\n'):
        content += '\n'
    content += '\n# Optional localhost simulator — generated locally; never commit this file.\n'
    content += ''.join(f'{key}={secrets.token_urlsafe(36)}\n' for key in missing)
    # File is ignored by Git and created with owner-only permissions.
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as file:
        file.write(content)
    env_path.chmod(0o600)
    return missing


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enable-actions', action='store_true', help='Explicitly enable containment actions against the localhost demo nodes only.')
    args = parser.parse_args()
    created = configure_simulator(enable_actions=args.enable_actions)
    print('Created missing simulator settings: ' + ', '.join(created) if created else 'Simulator credentials already configured; existing values preserved.')
    if args.enable_actions:
        print('Local demo simulation actions enabled. Restart the Streamlit app to reload settings.')
    print('No secret values are displayed. Start nodes: python -m network.run_nodes')
