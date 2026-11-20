"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
PLAYBOOKS_DIR = DATA_DIR / "playbooks"
CVES_PATH = DATA_DIR / "cves" / "cve_feed.json"
ALERTS_DIR = DATA_DIR / "alerts"
CHROMA_DIR = ROOT_DIR / "chroma_db"
TICKETS_DIR = ROOT_DIR / "tickets"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

COLLECTION_NAME = "soc_runbooks_cves"
RETRIEVER_K = 6
