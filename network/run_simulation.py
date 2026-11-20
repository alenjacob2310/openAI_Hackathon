"""
Run mesh traffic + attack scenario simulation against nodes 8001–8003.

Usage:
  # terminals: first start nodes, then:
  python -m network.run_simulation
  python -m network.run_simulation --scenario ddos
  python -m network.run_simulation --mesh-only
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network.mesh import mesh_loop
from network.scenarios.runner import run_all_scenarios, run_scenario

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


async def main_async(args: argparse.Namespace) -> None:
    stop = asyncio.Event()
    mesh_task = asyncio.create_task(
        mesh_loop(stop, min_interval=args.min_interval, max_interval=args.max_interval)
    )

    try:
        if args.mesh_only:
            print("Mesh-only mode — random POST between nodes (<1 min). Ctrl+C to stop.")
            await mesh_task
            return

        # Let a couple of mesh heartbeats happen first
        await asyncio.sleep(2)

        if args.scenario:
            result = await run_scenario(args.scenario)
            print(json.dumps(result, indent=2))
        else:
            results = await run_all_scenarios()
            print(json.dumps(results, indent=2))

        if args.keep_mesh:
            print("Scenarios finished — mesh continues. Ctrl+C to stop.")
            await mesh_task
        else:
            stop.set()
            await asyncio.wait_for(mesh_task, timeout=5)
    except KeyboardInterrupt:
        stop.set()
        await asyncio.sleep(0.2)
    finally:
        stop.set()
        if not mesh_task.done():
            mesh_task.cancel()
            try:
                await mesh_task
            except asyncio.CancelledError:
                pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SOC mesh attack simulation")
    p.add_argument(
        "--scenario",
        choices=["ddos", "phishing", "ransomware", "credential_stuffing"],
        help="Run a single scenario (default: all)",
    )
    p.add_argument("--mesh-only", action="store_true", help="Only run inter-node mesh traffic")
    p.add_argument("--keep-mesh", action="store_true", help="Keep mesh running after scenarios")
    p.add_argument("--min-interval", type=float, default=5.0, help="Min seconds between mesh POSTs")
    p.add_argument("--max-interval", type=float, default=55.0, help="Max seconds between mesh POSTs (<60)")
    return p


def main() -> None:
    args = build_parser().parse_args()
    if args.max_interval >= 60:
        raise SystemExit("--max-interval must be < 60 so pairwise calls stay within 1 minute")
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
