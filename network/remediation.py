"""Automated containment actions for each simulated attack scenario."""

from __future__ import annotations

from typing import Any

from network.auth import NodeAuthState, create_token
from network.metrics import NodeMetrics
from network.secrets_store import rotate_secret


def remediate_ddos(metrics: NodeMetrics, attacker_ips: list[str]) -> dict[str, Any]:
    for ip in attacker_ips:
        metrics.blocked_ips.add(ip)
    # Tighten rate limit during attack
    metrics.rate_limit_rps = max(5.0, metrics.rate_limit_rps * 0.25)
    action = (
        f"Blocked IPs {attacker_ips}; lowered rate_limit_rps to {metrics.rate_limit_rps:.1f}"
    )
    metrics.raise_incident(
        scenario="ddos",
        severity="critical",
        message="Volumetric/request flood detected",
        metrics={"rps": metrics.current_rps(), "blocked": attacker_ips},
        remediated=True,
        remediation=action,
    )
    return {"status": "contained", "action": action}


def remediate_phishing(
    metrics: NodeMetrics,
    urls: list[str],
    auth: NodeAuthState | None = None,
) -> dict[str, Any]:
    for url in urls:
        metrics.quarantined_urls.add(url)
    rotated = None
    new_token = None
    # Treat phishing that may have leaked tokens as JWT compromise
    if auth is not None:
        new_secret = rotate_secret(auth.port)
        auth.refresh_secret(new_secret)
        rotated = True
        new_token = create_token(auth, subject="mesh-service", claims={"role": "service"})
    action = (
        f"Quarantined URLs {urls}"
        + ("; rotated JWT secret and issued fresh token" if rotated else "")
    )
    metrics.raise_incident(
        scenario="phishing",
        severity="high",
        message="Phishing / credential-harvest indicators detected",
        metrics={"urls": urls, "jwt_rotated": bool(rotated)},
        remediated=True,
        remediation=action,
    )
    return {
        "status": "contained",
        "action": action,
        "jwt_rotated": bool(rotated),
        "key_version": auth.key_version if auth else None,
        "new_token": new_token,
    }


def remediate_ransomware(metrics: NodeMetrics, auth: NodeAuthState) -> dict[str, Any]:
    metrics.isolated = True
    new_secret = rotate_secret(auth.port)
    auth.refresh_secret(new_secret)
    new_token = create_token(auth, subject="incident-responder", claims={"role": "admin"})
    action = (
        "Node network-isolated; JWT secret rotated; forensic hold simulated; "
        f"key_version={auth.key_version}"
    )
    metrics.raise_incident(
        scenario="ransomware",
        severity="critical",
        message="Ransomware encryption / shadow-copy deletion signals detected",
        metrics={"signals": len(metrics.ransomware_signals), "isolated": True},
        remediated=True,
        remediation=action,
    )
    return {
        "status": "contained",
        "action": action,
        "isolated": True,
        "key_version": auth.key_version,
        "new_token": new_token,
    }


def remediate_credential_stuffing(
    metrics: NodeMetrics,
    auth: NodeAuthState,
    usernames: list[str],
    attacker_ips: list[str],
) -> dict[str, Any]:
    for ip in attacker_ips:
        metrics.blocked_ips.add(ip)
    new_secret = rotate_secret(auth.port)
    auth.refresh_secret(new_secret)
    new_token = create_token(auth, subject="mesh-service", claims={"role": "service", "step_up_mfa": True})
    action = (
        f"Blocked stuffing IPs {attacker_ips}; forced step-up MFA flag; "
        f"rotated JWT secret for compromised auth plane; locked users {usernames[:5]}"
    )
    metrics.raise_incident(
        scenario="credential_stuffing",
        severity="high",
        message="Distributed credential stuffing detected",
        metrics={
            "auth_failures": len(metrics.auth_failures),
            "users": usernames[:10],
            "ips": attacker_ips,
        },
        remediated=True,
        remediation=action,
    )
    return {
        "status": "contained",
        "action": action,
        "key_version": auth.key_version,
        "new_token": new_token,
        "step_up_mfa": True,
    }


def remediate_jwt_compromise(metrics: NodeMetrics, auth: NodeAuthState, reason: str) -> dict[str, Any]:
    new_secret = rotate_secret(auth.port)
    auth.refresh_secret(new_secret)
    new_token = create_token(auth, subject="mesh-service", claims={"role": "service"})
    action = f"JWT compromise ({reason}): secret rotated, key_version={auth.key_version}"
    metrics.raise_incident(
        scenario="jwt_compromise",
        severity="critical",
        message=reason,
        metrics={"key_version": auth.key_version},
        remediated=True,
        remediation=action,
    )
    return {
        "status": "contained",
        "action": action,
        "key_version": auth.key_version,
        "new_token": new_token,
    }
