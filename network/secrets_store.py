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
    load_dotenv(ENV_PATH, override=True)
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
    load_dotenv(ENV_PATH, override=True)
    user = os.getenv("MESH_SERVICE_USER", "mesh-service")
    password = os.getenv("MESH_SERVICE_PASSWORD", "")
    if not password:
        raise RuntimeError("Set MESH_SERVICE_PASSWORD in .env for the optional simulator")
    return user, password
