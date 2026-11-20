"""Per-node JWT secret load/rotate helpers backed by the project .env file."""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"

load_dotenv(ENV_PATH)


def secret_env_key(port: int) -> str:
    return f"JWT_SECRET_{port}"


def load_secret(port: int) -> str:
    load_dotenv(ENV_PATH, override=False)
    key = secret_env_key(port)
    value = os.getenv(key)
    if not value:
        raise RuntimeError(f"Missing {key} in .env")
    return value


def _upsert_env_value(key: str, value: str) -> None:
    text = ENV_PATH.read_text(encoding="utf-8") if ENV_PATH.exists() else ""
    pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
    line = f"{key}={value}"
    if pattern.search(text):
        text = pattern.sub(line, text)
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        text += line + "\n"
    ENV_PATH.write_text(text, encoding="utf-8")
    os.environ[key] = value


def rotate_secret(port: int) -> str:
    """Generate a new JWT secret for a node and persist it to .env."""
    new_secret = f"soc-node-{port}-{secrets.token_urlsafe(24)}"
    _upsert_env_value(secret_env_key(port), new_secret)
    return new_secret


def mesh_credentials() -> tuple[str, str]:
    load_dotenv(ENV_PATH, override=False)
    user = os.getenv("MESH_SERVICE_USER", "mesh-service")
    password = os.getenv("MESH_SERVICE_PASSWORD", "")
    if not password:
        raise RuntimeError("Simulator credentials missing. Run python scripts/setup_simulator.py, then python -m network.run_nodes locally.")
    return user, password


def simulator_config_status() -> dict[str, object]:
    """Readiness only; never expose credential values to the UI."""
    load_dotenv(ENV_PATH, override=False)
    required = ('MESH_SERVICE_PASSWORD', *(secret_env_key(port) for port in (8001, 8002, 8003)))
    missing = [key for key in required if not os.getenv(key)]
    return {'configured': not missing, 'missing': missing}


def simulation_actions_enabled() -> bool:
    """Explicit local demo opt-in; environment values retain precedence."""
    load_dotenv(ENV_PATH, override=False)
    return os.getenv('SOC_ENABLE_SIMULATION_ACTIONS', 'false').strip().lower() == 'true'
