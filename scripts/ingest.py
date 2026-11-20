"""CLI helper to (re)build the ChromaDB index from playbooks + CVE feed."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.vector_store import build_vector_store, index_stats


def main() -> None:
    force = "--force" in sys.argv
    print("Building ChromaDB index…")
    build_vector_store(force_rebuild=force)
    print(index_stats())


if __name__ == "__main__":
    main()
