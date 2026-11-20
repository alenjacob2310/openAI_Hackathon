"""Random inter-node POST traffic — at most one pairwise exchange within 1 minute."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any

import httpx

from network import NODE_PORTS, NODE_URLS
from network.secrets_store import mesh_credentials

logger = logging.getLogger("mesh")


class MeshClient:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._tokens: dict[int, str] = {}
        self.user, self.password = mesh_credentials()

    async def get_token(self, client: httpx.AsyncClient, port: int, force: bool = False) -> str:
        if not force and port in self._tokens:
            return self._tokens[port]
        url = f"{NODE_URLS[port]}/auth/token"
        resp = await client.post(
            url,
            json={"username": self.user, "password": self.password},
        )
        resp.raise_for_status()
        token = resp.json()["access_token"]
        self._tokens[port] = token
        return token

    def invalidate_token(self, port: int) -> None:
        self._tokens.pop(port, None)

    async def send_message(
        self,
        client: httpx.AsyncClient,
        src: int,
        dst: int,
        payload: str = "heartbeat",
        scenario_tag: str | None = None,
    ) -> dict[str, Any]:
        token = await self.get_token(client, dst)
        headers = {"Authorization": f"Bearer {token}"}
        body = {"from_port": src, "payload": payload, "scenario_tag": scenario_tag}
        resp = await client.post(f"{NODE_URLS[dst]}/mesh/message", json=body, headers=headers)
        if resp.status_code == 401:
            # Secret may have rotated — refresh token once
            self.invalidate_token(dst)
            token = await self.get_token(client, dst, force=True)
            headers = {"Authorization": f"Bearer {token}"}
            resp = await client.post(f"{NODE_URLS[dst]}/mesh/message", json=body, headers=headers)
        data: dict[str, Any]
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            data = {"raw": resp.text}
        data["_http_status"] = resp.status_code
        data["_src"] = src
        data["_dst"] = dst
        return data

    async def wait_until_healthy(self, retries: int = 30) -> None:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for _ in range(retries):
                ok = True
                for port in NODE_PORTS:
                    try:
                        r = await client.post(f"{NODE_URLS[port]}/health")
                        if r.status_code >= 400:
                            ok = False
                    except httpx.HTTPError:
                        ok = False
                if ok:
                    return
                await asyncio.sleep(0.5)
        raise RuntimeError("Mesh nodes did not become healthy in time")


async def mesh_loop(
    stop_event: asyncio.Event,
    min_interval: float = 5.0,
    max_interval: float = 55.0,
) -> None:
    """
    Continuously pick two distinct nodes at random and POST between them.
    Interval is always < 60s (default 5–55s).
    """
    client_wrap = MeshClient()
    await client_wrap.wait_until_healthy()
    logger.info("Mesh loop started — random pairwise POST within 1 minute windows")

    async with httpx.AsyncClient(timeout=10.0) as client:
        while not stop_event.is_set():
            src, dst = random.sample(list(NODE_PORTS), 2)
            try:
                result = await client_wrap.send_message(
                    client,
                    src,
                    dst,
                    payload=f"heartbeat ts={time.time():.0f}",
                )
                logger.info(
                    "mesh %s -> %s status=%s accepted=%s",
                    src,
                    dst,
                    result.get("_http_status"),
                    result.get("accepted"),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("mesh %s -> %s failed: %s", src, dst, exc)

            delay = random.uniform(min_interval, max_interval)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
