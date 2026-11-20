"""Launch three FastAPI mesh nodes on ports 8001, 8002, and 8003."""

from __future__ import annotations

import multiprocessing
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network import NODE_PORTS
from network.secrets_store import simulator_config_status


def _start(port: int) -> None:
    # Ensure child process can import project packages
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    os.chdir(ROOT)
    from network.node import run_node

    run_node(port)


def main() -> None:
    readiness = simulator_config_status()
    if not readiness['configured']:
        raise SystemExit('Simulator settings missing: ' + ', '.join(readiness['missing']) + '. Run python scripts/setup_simulator.py first.')
    procs: list[multiprocessing.Process] = []
    for port in NODE_PORTS:
        p = multiprocessing.Process(target=_start, args=(port,), name=f"node-{port}")
        p.start()
        procs.append(p)
        print(f"Started node on http://127.0.0.1:{port} (pid={p.pid})", flush=True)

    print("All nodes up. Press Ctrl+C to stop.", flush=True)
    try:
        while True:
            alive = [p for p in procs if p.is_alive()]
            if len(alive) < len(procs):
                print("A node exited unexpectedly — shutting down.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping nodes…")
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
        for p in procs:
            p.join(timeout=5)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
