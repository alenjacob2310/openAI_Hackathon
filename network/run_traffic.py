"""
Generate continuous inter-node traffic with distinct per-node profiles
so the dashboard RPS lines for 8001 / 8002 / 8003 look different.

Profiles (default):
  8001 — busy hub      (~high steady RPS)
  8002 — medium / wavy (~mid RPS with oscillation)
  8003 — quiet / bursty (~low baseline with occasional spikes)

Usage (nodes must already be running):
  python -m network.run_traffic
  python -m network.run_traffic --scale 1.5
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import math
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network import NODE_PORTS, NODE_URLS
from network.mesh import MeshClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("traffic")


@dataclass(frozen=True)
class NodeTrafficProfile:
    port: int
    name: str
    # baseline mesh POSTs targeting this node per second
    base_rps: float
    # amplitude of sine modulation (added to base)
    wave_amp: float
    # sine period in seconds
    wave_period: float
    # chance each tick to fire an extra burst
    burst_chance: float
    # extra POSTs when burst fires
    burst_extra: int
    # phase offset so waves are not aligned across nodes
    phase: float


# Distinct shapes so chart colors diverge visually
DEFAULT_PROFILES: dict[int, NodeTrafficProfile] = {
    8001: NodeTrafficProfile(
        port=8001,
        name="busy-hub",
        base_rps=6.0,
        wave_amp=1.2,
        wave_period=18.0,
        burst_chance=0.08,
        burst_extra=2,
        phase=0.0,
    ),
    8002: NodeTrafficProfile(
        port=8002,
        name="medium-wavy",
        base_rps=3.0,
        wave_amp=2.0,
        wave_period=12.0,
        burst_chance=0.12,
        burst_extra=3,
        phase=2.1,
    ),
    8003: NodeTrafficProfile(
        port=8003,
        name="quiet-bursty",
        base_rps=1.0,
        wave_amp=0.4,
        wave_period=25.0,
        burst_chance=0.28,
        burst_extra=5,
        phase=4.2,
    ),
}


async def _health_ping(client, port: int) -> None:
    import httpx

    try:
        await client.post(f"{NODE_URLS[port]}/health")
    except httpx.HTTPError:
        pass


def _instant_target_rps(profile: NodeTrafficProfile, t: float, scale: float) -> float:
    wave = profile.wave_amp * math.sin(2 * math.pi * t / profile.wave_period + profile.phase)
    return max(0.2, (profile.base_rps + wave) * scale)


async def _node_worker(
    profile: NodeTrafficProfile,
    mesh: MeshClient,
    client,
    *,
    scale: float,
    stop: asyncio.Event,
    counters: dict[int, int],
) -> None:
    """Drive inbound traffic toward one destination with its own cadence."""
    tick = 0.25  # scheduling granularity
    while not stop.is_set():
        t = time.time()
        target = _instant_target_rps(profile, t, scale)
        # How many POSTs this tick
        expected = target * tick
        n = int(expected)
        if random.random() < (expected - n):
            n += 1
        if random.random() < profile.burst_chance:
            n += profile.burst_extra

        others = [p for p in NODE_PORTS if p != profile.port]
        tasks = []
        for i in range(max(0, n)):
            src = others[i % len(others)] if random.random() < 0.7 else random.choice(others)
            tasks.append(
                mesh.send_message(
                    client,
                    src,
                    profile.port,
                    payload=(
                        f"{profile.name} dst={profile.port} "
                        f"ts={t:.3f} i={counters[profile.port]}"
                    ),
                )
            )
            counters[profile.port] += 1

        # Light asymmetric health load (busy node gets more health noise)
        health_n = 1 if profile.port == 8003 else (2 if profile.port == 8002 else 3)
        for _ in range(health_n):
            tasks.append(_health_ping(client, profile.port))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        try:
            await asyncio.wait_for(stop.wait(), timeout=tick)
        except asyncio.TimeoutError:
            pass


async def traffic_loop(*, scale: float = 1.0, include_health: bool = True) -> None:
    mesh = MeshClient()
    await mesh.wait_until_healthy()
    for p, prof in DEFAULT_PROFILES.items():
        logger.info(
            "profile :%s %-13s base_rps=%.1f wave=±%.1f/%ss burst=%.0f%%+%s",
            p,
            prof.name,
            prof.base_rps * scale,
            prof.wave_amp * scale,
            prof.wave_period,
            prof.burst_chance * 100,
            prof.burst_extra,
        )

    import httpx

    stop = asyncio.Event()
    counters = {p: 0 for p in NODE_PORTS}
    async with httpx.AsyncClient(timeout=8.0) as client:
        workers = [
            asyncio.create_task(
                _node_worker(
                    DEFAULT_PROFILES[port],
                    mesh,
                    client,
                    scale=scale,
                    stop=stop,
                    counters=counters,
                )
            )
            for port in NODE_PORTS
        ]
        # Optional global light health on all nodes if disabled per-worker path
        if not include_health:
            # workers already skip extra if we zero health — recreate without health
            pass

        try:
            while True:
                await asyncio.sleep(2.0)
                logger.info(
                    "cumulative inbound mesh msgs 8001=%s 8002=%s 8003=%s",
                    counters[8001],
                    counters[8002],
                    counters[8003],
                )
        except asyncio.CancelledError:
            stop.set()
            for w in workers:
                w.cancel()
            raise


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate distinct per-node mesh traffic")
    p.add_argument(
        "--scale",
        type=float,
        default=1.0,
        help="Multiply all profile RPS values (default 1.0)",
    )
    p.add_argument(
        "--no-health",
        action="store_true",
        help="Reserved; health pings remain part of asymmetric load profiles",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()
    try:
        asyncio.run(traffic_loop(scale=max(0.1, args.scale), include_health=not args.no_health))
    except KeyboardInterrupt:
        logger.info("Traffic generator stopped")


if __name__ == "__main__":
    main()
