"""FastAPI node factory — one process per port (8001/8002/8003).

Nodes collect telemetry and enforce agent-applied containment.
Detection + remediation decisions are owned by the LangGraph monitor agent.
"""

from __future__ import annotations

import os
import re
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field

from network.admin_actions import apply_action
from network.auth import (
    NodeAuthState,
    bootstrap_auth_state,
    create_token,
    make_auth_dependency,
)
from network.metrics import NodeMetrics
from network.secrets_store import mesh_credentials

PHISHING_URL_RE = re.compile(
    r"https?://(?:evil|phish|secure-login-update|owa-auth-reset)[^\s\"']+",
    re.IGNORECASE,
)
RANSOMWARE_MARKERS = (
    "encrypt_files",
    "delete_shadow_copies",
    "vssadmin",
    ".locked",
    "ransom_note",
)


class TokenRequest(BaseModel):
    username: str
    password: str


class MeshMessage(BaseModel):
    from_port: int
    payload: str = "heartbeat"
    scenario_tag: str | None = None


class PhishingPayload(BaseModel):
    subject: str = "Password expiry"
    body: str
    urls: list[str] = Field(default_factory=list)


class RansomwarePayload(BaseModel):
    host: str = "FIN-WS-042"
    actions: list[str] = Field(default_factory=list)
    note: str = ""


class StuffingAttempt(BaseModel):
    username: str
    password: str
    client_ip: str = "203.0.113.50"


class DDoSPulse(BaseModel):
    client_ip: str = "198.51.100.24"
    burst_size: int = 1


class RemediateBody(BaseModel):
    action: str
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    rate_limit_rps: float | None = None
    scenario: str = "unknown"
    reason: str = "langgraph_agent"


def create_app(port: int) -> FastAPI:
    app = FastAPI(title=f"SOC Mesh Node {port}", version="1.1.0")
    auth_state: NodeAuthState = bootstrap_auth_state(port)
    metrics = NodeMetrics(port=port)
    require_jwt = make_auth_dependency(auth_state)
    mesh_user, mesh_password = mesh_credentials()

    async def require_operator(claims: dict[str, Any] = Depends(require_jwt)):
        if claims.get("role") not in {"service", "admin"}:
            raise HTTPException(status_code=403, detail="Operator role required")
        return claims

    # Signal thresholds (telemetry only — no auto-remediation)
    DDOS_RPS_THRESHOLD = 25.0
    STUFFING_FAIL_THRESHOLD = 20

    app.state.auth = auth_state
    app.state.metrics = metrics
    app.state.port = port

    def _client_ip(request: Request, override: str | None = None) -> str:
        if override:
            return override
        return request.client.host if request.client else "unknown"

    def _enforce_guards(request: Request, client_ip: str | None = None) -> None:
        """Enforce containment already applied by the LangGraph agent."""
        ip = _client_ip(request, client_ip)
        if metrics.isolated:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Node isolated after LangGraph ransomware containment",
            )
        if ip in metrics.blocked_ips:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"IP blocked: {ip}")
        metrics.record_request(ip)
        if metrics.current_rps() > metrics.rate_limit_rps:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "signal": "rate_limit",
                    "rps": metrics.current_rps(),
                    "note": "Awaiting / handled by LangGraph monitor agent",
                },
            )

    def _raise_signal(scenario: str, message: str, extra: dict[str, Any] | None = None) -> None:
        metrics.raise_incident(
            scenario=scenario,
            severity="high",
            message=message,
            metrics=extra or {},
            remediated=False,
            remediation="",
        )

    @app.middleware("http")
    async def isolation_middleware(request: Request, call_next):
        path = request.url.path
        if metrics.isolated and path not in {
            "/metrics",
            "/auth/token",
            "/health",
            "/admin/lift-isolation",
            "/admin/online",
            "/admin/isolate",
            "/admin/shutdown",
            "/admin/rotate-jwt",
            "/admin/remediate",
            "/docs",
            "/openapi.json",
        }:
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=503,
                content={"detail": "Node isolated after LangGraph ransomware containment"},
            )
        return await call_next(request)

    @app.post("/health")
    async def health(request: Request) -> dict[str, Any]:
        metrics.record_request(_client_ip(request))
        return {
            "status": "ok" if not metrics.isolated else "isolated",
            "port": port,
            "key_version": auth_state.key_version,
            "remediation_owner": "langgraph_agent",
        }

    @app.post("/auth/token")
    async def issue_token(body: TokenRequest, request: Request) -> dict[str, Any]:
        ip = _client_ip(request)
        if ip in metrics.blocked_ips:
            raise HTTPException(status_code=403, detail="IP blocked")
        metrics.record_request(ip)

        valid = body.username == mesh_user and body.password == mesh_password
        demo_ok = os.getenv("SOC_ENABLE_DEMO_LOGIN", "false").lower() == "true" and body.password == f"{body.username}-correct"

        if not (valid or demo_ok):
            metrics.record_auth_failure(body.username)
            fails = len(metrics.auth_failures)
            if fails >= STUFFING_FAIL_THRESHOLD:
                _raise_signal(
                    "credential_stuffing",
                    "Auth failure flood signal (pending LangGraph remediation)",
                    {
                        "failures": fails,
                        "ip": ip,
                        "users_sample": list(metrics.auth_attempts_by_user.keys())[-10:],
                    },
                )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        metrics.record_auth_success(body.username)
        token = create_token(
            auth_state,
            subject=body.username,
            claims={"role": "service" if valid else "user"},
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "key_version": auth_state.key_version,
            "expires_in": 300,
        }

    @app.post("/mesh/message")
    async def mesh_message(
        body: MeshMessage,
        request: Request,
        claims: dict[str, Any] = Depends(require_jwt),
    ) -> dict[str, Any]:
        _enforce_guards(request)
        metrics.record_mesh()

        found_urls = PHISHING_URL_RE.findall(body.payload)
        if found_urls or body.scenario_tag == "phishing":
            urls = found_urls or ["https://evil-secure-login.net/owa/auth"]
            for u in urls:
                metrics.record_phishing(u)
            _raise_signal(
                "phishing",
                "Phishing URL signal in mesh payload (pending LangGraph remediation)",
                {"urls": urls, "from_port": body.from_port},
            )
            return {
                "accepted": False,
                "signal": "phishing",
                "urls": urls,
                "from": body.from_port,
                "pending_agent": True,
                "claims_sub": claims.get("sub"),
            }

        lowered = body.payload.lower()
        if body.scenario_tag == "ransomware" or any(m in lowered for m in RANSOMWARE_MARKERS):
            metrics.record_ransomware(body.payload[:200])
            _raise_signal(
                "ransomware",
                "Ransomware TTP signal (pending LangGraph remediation)",
                {"payload": body.payload[:200]},
            )
            return {
                "accepted": False,
                "signal": "ransomware",
                "pending_agent": True,
            }

        return {
            "accepted": True,
            "to": port,
            "from": body.from_port,
            "echo": body.payload[:120],
            "key_version": auth_state.key_version,
            "sub": claims.get("sub"),
        }

    @app.post("/secure/echo")
    async def secure_echo(
        request: Request,
        payload: dict[str, Any],
        claims: dict[str, Any] = Depends(require_jwt),
    ) -> dict[str, Any]:
        _enforce_guards(request)
        return {"echo": payload, "sub": claims.get("sub"), "port": port}

    # -------- Scenario injection (signals only) --------

    @app.post("/scenario/ddos")
    async def scenario_ddos(body: DDoSPulse, request: Request) -> dict[str, Any]:
        ip = body.client_ip
        signal = False
        for _ in range(max(1, body.burst_size)):
            if ip in metrics.blocked_ips:
                raise HTTPException(
                    status_code=403,
                    detail={"signal": "ddos", "detail": "IP already blocked by agent", "ip": ip},
                )
            metrics.record_request(ip)
            if metrics.current_rps() >= DDOS_RPS_THRESHOLD or len(metrics.request_times) >= 30:
                signal = True
                _raise_signal(
                    "ddos",
                    "Volumetric request flood signal (pending LangGraph remediation)",
                    {"ip": ip, "rps": metrics.current_rps(), "window_reqs": len(metrics.request_times)},
                )
                break
        return {
            "status": "flood_applied",
            "rps_estimate": metrics.current_rps(),
            "signal": signal,
            "pending_agent": True,
            "attacker_ip": ip,
        }

    @app.post("/scenario/phishing")
    async def scenario_phishing(
        body: PhishingPayload,
        request: Request,
        claims: dict[str, Any] = Depends(require_jwt),
    ) -> dict[str, Any]:
        _enforce_guards(request)
        urls = list(body.urls)
        urls.extend(PHISHING_URL_RE.findall(body.body))
        urls = urls or ["https://evil-secure-login.net/owa/auth"]
        for u in urls:
            metrics.record_phishing(u)
        _raise_signal(
            "phishing",
            "Phishing + possible JWT harvest signal (pending LangGraph remediation)",
            {"urls": urls, "subject": body.subject},
        )
        return {
            "signal": "phishing",
            "urls": urls,
            "pending_agent": True,
            "analyst_subject": body.subject,
            "jwt_compromise_suspected": True,
        }

    @app.post("/scenario/ransomware")
    async def scenario_ransomware(
        body: RansomwarePayload,
        request: Request,
        claims: dict[str, Any] = Depends(require_jwt),
    ) -> dict[str, Any]:
        _enforce_guards(request)
        for action in body.actions or ["encrypt_files", "delete_shadow_copies"]:
            metrics.record_ransomware(f"{body.host}:{action}:{body.note}")
        _raise_signal(
            "ransomware",
            "Ransomware host encryption signal (pending LangGraph remediation)",
            {"host": body.host, "actions": body.actions},
        )
        return {
            "signal": "ransomware",
            "host": body.host,
            "pending_agent": True,
        }

    @app.post("/scenario/credential_stuffing")
    async def scenario_credential_stuffing(body: StuffingAttempt, request: Request) -> dict[str, Any]:
        ip = body.client_ip
        if ip in metrics.blocked_ips:
            raise HTTPException(status_code=403, detail="IP blocked")
        metrics.record_request(ip)
        metrics.record_auth_failure(body.username)
        fails = len(metrics.auth_failures)
        signal = fails >= STUFFING_FAIL_THRESHOLD
        if signal:
            _raise_signal(
                "credential_stuffing",
                "Credential stuffing signal (pending LangGraph remediation)",
                {
                    "failures": fails,
                    "ip": ip,
                    "users_sample": list(metrics.auth_attempts_by_user.keys())[-10:],
                },
            )
        return {
            "signal": signal,
            "failures_in_window": fails,
            "pending_agent": signal,
            "attacker_ip": ip,
            "accepted": False,
        }

    @app.get("/metrics")
    async def get_metrics() -> dict[str, Any]:
        snap = metrics.snapshot()
        snap["key_version"] = auth_state.key_version
        snap["remediation_owner"] = "langgraph_agent"
        # Open (unremediated) signals for the agent
        open_incidents = [
            e.__dict__
            for e in metrics.incidents
            if not e.remediated
        ][-20:]
        snap["open_incidents"] = open_incidents
        return snap

    @app.post("/admin/remediate")
    async def admin_remediate(
        body: RemediateBody,
        claims: dict[str, Any] = Depends(require_operator),
    ) -> dict[str, Any]:
        """LangGraph agent executes containment through this endpoint."""
        result = apply_action(
            metrics,
            auth_state,
            body.action,
            ips=body.ips,
            urls=body.urls,
            rate_limit_rps=body.rate_limit_rps,
            scenario=body.scenario,
            reason=body.reason or f"langgraph:{claims.get('sub', 'agent')}",
        )
        result["actor"] = claims.get("sub")
        return result

    @app.post("/admin/rotate-jwt")
    async def admin_rotate_jwt(claims: dict[str, Any] = Depends(require_operator)) -> dict[str, Any]:
        return apply_action(
            metrics,
            auth_state,
            "rotate_jwt",
            scenario="jwt_compromise",
            reason=f"admin:{claims.get('sub')}",
        )

    @app.post("/admin/lift-isolation")
    async def lift_isolation(claims: dict[str, Any] = Depends(require_operator)) -> dict[str, Any]:
        return apply_action(
            metrics,
            auth_state,
            "lift_isolation",
            scenario="recovery",
            reason="manual_lift",
        )

    @app.post("/admin/online")
    async def bring_online(claims: dict[str, Any] = Depends(require_operator)):
        return apply_action(metrics, auth_state, "lift_isolation", scenario="recovery", reason="operator_bring_online")

    @app.post("/admin/isolate")
    async def isolate_node_admin(claims: dict[str, Any] = Depends(require_operator)):
        return apply_action(metrics, auth_state, "isolate", scenario="manual", reason="operator_isolate")

    @app.post("/admin/shutdown")
    async def shutdown_node_admin(claims: dict[str, Any] = Depends(require_operator)):
        import asyncio
        async def exit_after_response():
            await asyncio.sleep(0.35)
            os._exit(0)
        asyncio.create_task(exit_after_response())
        return {"status": "shutting_down", "port": port}

    return app


def run_node(port: int) -> None:
    import uvicorn

    os.environ["MESH_NODE_PORT"] = str(port)
    uvicorn.run(create_app(port), host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    p = int(os.getenv("MESH_NODE_PORT", "8001"))
    run_node(p)
