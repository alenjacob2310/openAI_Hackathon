"""Remediation primitives invoked by the LangGraph monitor agent via admin APIs."""

from __future__ import annotations

from typing import Any

from network.auth import NodeAuthState, create_token
from network.metrics import NodeMetrics
from network.secrets_store import rotate_secret


def apply_action(
    metrics: NodeMetrics,
    auth: NodeAuthState,
    action: str,
    *,
    ips: list[str] | None = None,
    urls: list[str] | None = None,
    rate_limit_rps: float | None = None,
    scenario: str = "unknown",
    reason: str = "langgraph_agent",
) -> dict[str, Any]:
    """Execute one containment action on a live node."""
    ips = ips or []
    urls = urls or []
    action = action.strip().lower()
    result: dict[str, Any] = {"action": action, "port": auth.port, "scenario": scenario}

    if action == "block_ip":
        for ip in ips:
            metrics.blocked_ips.add(ip)
        detail = f"Blocked IPs {ips} ({reason})"
        metrics.raise_incident(
            scenario=scenario,
            severity="high",
            message="LangGraph agent blocked attacker IPs",
            metrics={"ips": ips},
            remediated=True,
            remediation=detail,
        )
        result.update({"status": "ok", "detail": detail, "blocked_ips": sorted(metrics.blocked_ips)})

    elif action == "quarantine_url":
        for url in urls:
            metrics.quarantined_urls.add(url)
        detail = f"Quarantined URLs {urls} ({reason})"
        metrics.raise_incident(
            scenario=scenario,
            severity="high",
            message="LangGraph agent quarantined phishing URLs",
            metrics={"urls": urls},
            remediated=True,
            remediation=detail,
        )
        result.update(
            {
                "status": "ok",
                "detail": detail,
                "quarantined_urls": sorted(metrics.quarantined_urls),
            }
        )

    elif action == "isolate":
        metrics.isolated = True
        detail = f"Node isolated ({reason})"
        metrics.raise_incident(
            scenario=scenario,
            severity="critical",
            message="LangGraph agent isolated node",
            metrics={"isolated": True},
            remediated=True,
            remediation=detail,
        )
        result.update({"status": "ok", "detail": detail, "isolated": True})

    elif action == "lift_isolation":
        metrics.isolated = False
        result.update({"status": "ok", "detail": "Isolation lifted", "isolated": False})

    elif action == "rotate_jwt":
        new_secret = rotate_secret(auth.port)
        auth.refresh_secret(new_secret)
        token = create_token(auth, subject="mesh-service", claims={"role": "service", "step_up_mfa": True})
        detail = f"JWT secret rotated to key_version={auth.key_version} ({reason})"
        metrics.raise_incident(
            scenario=scenario or "jwt_compromise",
            severity="critical",
            message="LangGraph agent rotated JWT secret after suspected compromise",
            metrics={"key_version": auth.key_version},
            remediated=True,
            remediation=detail,
        )
        result.update(
            {
                "status": "ok",
                "detail": detail,
                "key_version": auth.key_version,
                "new_token": token,
            }
        )

    elif action == "set_rate_limit":
        if rate_limit_rps is None:
            rate_limit_rps = max(5.0, metrics.rate_limit_rps * 0.25)
        metrics.rate_limit_rps = float(rate_limit_rps)
        detail = f"rate_limit_rps set to {metrics.rate_limit_rps:.1f} ({reason})"
        metrics.raise_incident(
            scenario=scenario,
            severity="high",
            message="LangGraph agent tightened rate limit",
            metrics={"rate_limit_rps": metrics.rate_limit_rps},
            remediated=True,
            remediation=detail,
        )
        result.update({"status": "ok", "detail": detail, "rate_limit_rps": metrics.rate_limit_rps})

    else:
        result.update({"status": "error", "detail": f"Unknown action: {action}"})

    return result
