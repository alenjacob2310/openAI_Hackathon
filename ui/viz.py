"""HTML visualizations for the three-node mesh and agent architecture."""

from __future__ import annotations

from typing import Any


AGENT_STEP_ORDER = ("collect", "detect", "retrieve", "plan", "execute", "summarize")

# Map Agent node / trace names → diagram keys
AGENT_STEP_ALIASES = {
    "collect": "collect",
    "collect_telemetry": "collect",
    "detect": "detect",
    "detect_incident": "detect",
    "retrieve": "retrieve",
    "retrieve_sop": "retrieve",
    "plan": "plan",
    "plan_remediation": "plan",
    "execute": "execute",
    "execute_remediation": "execute",
    "summarize": "summarize",
    "summary": "summarize",
}

# Which elements light up for each active step
STEP_HIGHLIGHTS = {
    "collect": {"vdb": False},
    "detect": {"vdb": False},
    "retrieve": {"vdb": True},
    "plan": {"vdb": True},
    "execute": {"vdb": False},
    "summarize": {"vdb": False},
}


def normalize_agent_step(step: str | None) -> str | None:
    if not step:
        return None
    key = step.strip().lower()
    if key in AGENT_STEP_ALIASES:
        return AGENT_STEP_ALIASES[key]
    for alias, canon in AGENT_STEP_ALIASES.items():
        if alias in key or canon in key:
            return canon
    return None


def completed_steps_before(active: str | None) -> set[str]:
    if not active or active not in AGENT_STEP_ORDER:
        return set()
    idx = AGENT_STEP_ORDER.index(active)
    return set(AGENT_STEP_ORDER[:idx])


def agent_architecture_svg(
    active_step: str | None = None,
    completed_steps: set[str] | list[str] | None = None,
    status_label: str | None = None,
) -> str:
    """Agent monitor + tools + VDB, with live step highlighting."""
    active = normalize_agent_step(active_step)
    completed = set(completed_steps or [])
    completed |= completed_steps_before(active)
    # If we finished summarize, mark everything done
    if active == "summarize" or "summarize" in completed:
        completed |= set(AGENT_STEP_ORDER)
    highlights = STEP_HIGHLIGHTS.get(active or "", {"vdb": False})

    steps = [
        ("collect", 55, 52, "Collect"),
        ("detect", 145, 52, "Detect"),
        ("retrieve", 235, 52, "Retrieve"),
        ("plan", 325, 52, "Plan"),
        ("execute", 415, 52, "Execute"),
        ("summarize", 505, 52, "Summarize"),
    ]

    def node_style(key: str) -> tuple[str, str, str, float]:
        # fill, stroke, glow filter id, stroke_width
        if key == active:
            return "#1f6b4a", "#8dffc3", "url(#glow-active)", 2.6
        if key in completed:
            return "#1a4a3a", "#5dcf9a", "", 1.8
        return "#16344c", "#5a7a92", "", 1.4

    boxes = []
    for key, x, y, label in steps:
        fill, stroke, filt, sw = node_style(key)
        filt_attr = f' filter="{filt}"' if filt else ""
        pulse = ""
        if key == active:
            pulse = (
                f'<circle cx="{x}" cy="{y}" r="28" fill="none" stroke="#8dffc3" '
                f'stroke-width="2" opacity="0.7">'
                f'<animate attributeName="r" values="26;36;26" dur="1.1s" repeatCount="indefinite"/>'
                f'<animate attributeName="opacity" values="0.7;0.15;0.7" dur="1.1s" repeatCount="indefinite"/>'
                f"</circle>"
            )
        boxes.append(
            f"{pulse}"
            f'<rect x="{x - 40}" y="{y - 20}" width="80" height="40" rx="8" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{filt_attr}/>'
            f'<text x="{x}" y="{y + 5}" text-anchor="middle" fill="{stroke}" '
            f'font-size="11" font-family="Segoe UI, sans-serif" font-weight="700">{label}</text>'
        )

    arrows = []
    for i in range(len(steps) - 1):
        a_key = steps[i][0]
        x1 = steps[i][1] + 40
        x2 = steps[i + 1][1] - 40
        y = steps[i][2]
        lit = a_key in completed or a_key == active
        stroke = "#5dcf9a" if lit else "#3a7ca5"
        width = 2.6 if lit else 1.8
        arrows.append(
            f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{stroke}" '
            f'stroke-width="{width}" marker-end="url(#arrow)"/>'
        )

    vdb_on = bool(highlights.get("vdb"))
    vdb_fill = "#1f6b4a" if vdb_on else "#1a3a28"
    vdb_stroke = "#8dffc3" if vdb_on else "#5dcf9a"
    vdb_sw = 2.4 if vdb_on else 1.6
    vdb = (
        f'<rect x="200" y="120" width="180" height="48" rx="10" fill="{vdb_fill}" '
        f'stroke="{vdb_stroke}" stroke-width="{vdb_sw}"/>'
        f'<text x="290" y="141" text-anchor="middle" fill="{vdb_stroke}" font-size="13" '
        f'font-family="Segoe UI, sans-serif" font-weight="700">ChromaDB VDB</text>'
        f'<text x="290" y="157" text-anchor="middle" fill="#9eb8cb" font-size="10" '
        f'font-family="Segoe UI, sans-serif">SOPs · CVE intel</text>'
    )
    link_stroke = "#8dffc3" if vdb_on else "#5dcf9a"
    link_w = 2.2 if vdb_on else 1.4
    vdb_link = (
        f'<line x1="235" y1="72" x2="290" y2="120" stroke="{link_stroke}" '
        f'stroke-width="{link_w}" stroke-dasharray="4 3"/>'
        f'<line x1="325" y1="72" x2="290" y2="120" stroke="{link_stroke}" '
        f'stroke-width="{link_w}" stroke-dasharray="4 3"/>'
    )

    label = status_label or (
        f"active: {active}" if active else "idle — waiting for agent"
    )
    return f"""
    <div class="arch-svg-wrap">
      <svg viewBox="0 0 560 185" width="100%" height="185" role="img" aria-label="Agent architecture">
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#3a7ca5"/>
          </marker>
          <filter id="glow-active" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3.5" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>
        <text x="12" y="18" fill="#8eb6d0" font-size="11" font-family="Segoe UI, sans-serif">
          Agent monitor · {label}
        </text>
        {''.join(arrows)}
        {''.join(boxes)}
        {vdb_link}
        {vdb}
      </svg>
    </div>
    """


def mesh_svg(metrics: dict[int, dict[str, Any]], last_hop: tuple[int, int] | None = None) -> str:
    """Render a simple SVG triangle of nodes 8001 / 8002 / 8003."""
    positions = {
        8001: (160, 70),
        8002: (420, 70),
        8003: (290, 220),
    }
    edges = [(8001, 8002), (8002, 8003), (8003, 8001)]

    def color_for(port: int) -> tuple[str, str]:
        m = metrics.get(port) or {}
        if not m.get("online"):
            return "#5a3a3a", "#ff8a8a"
        if m.get("isolated"):
            return "#6a3a12", "#ffb347"
        if m.get("blocked_ips"):
            return "#1a4a3a", "#7dffb5"
        return "#1a4d6e", "#9fd0ff"

    lines = []
    for a, b in edges:
        x1, y1 = positions[a]
        x2, y2 = positions[b]
        active = last_hop in {(a, b), (b, a)}
        stroke = "#5ad0ff" if active else "#2f5f7a"
        width = 3.5 if active else 1.8
        lines.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{stroke}" stroke-width="{width}" stroke-linecap="round" />'
        )
        if active:
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2
            lines.append(
                f'<circle cx="{mx}" cy="{my}" r="5" fill="#5ad0ff">'
                f'<animate attributeName="r" values="4;7;4" dur="1.2s" repeatCount="indefinite"/>'
                f"</circle>"
            )

    nodes = []
    for port, (x, y) in positions.items():
        fill, text = color_for(port)
        m = metrics.get(port) or {}
        rps = m.get("rps_estimate", "—")
        kv = m.get("key_version", "—")
        label = "OFF" if not m.get("online") else ("ISO" if m.get("isolated") else "OK")
        nodes.append(
            f'<circle cx="{x}" cy="{y}" r="34" fill="{fill}" stroke="{text}" stroke-width="2"/>'
            f'<text x="{x}" y="{y - 4}" text-anchor="middle" fill="{text}" '
            f'font-size="13" font-family="Segoe UI, sans-serif" font-weight="700">{port}</text>'
            f'<text x="{x}" y="{y + 14}" text-anchor="middle" fill="#cfe6f5" '
            f'font-size="10" font-family="Segoe UI, sans-serif">{label} · {rps} rps · kv{kv}</text>'
        )

    hop = f"{last_hop[0]} → {last_hop[1]}" if last_hop else "idle"
    return f"""
    <div class="mesh-svg-wrap">
      <svg viewBox="0 0 580 290" width="100%" height="280" role="img" aria-label="Mesh topology">
        {''.join(lines)}
        {''.join(nodes)}
        <text x="12" y="20" fill="#9eb8cb" font-size="12" font-family="Segoe UI, sans-serif">
          Mesh topology · last hop: {hop}
        </text>
      </svg>
    </div>
    """


def node_card_html(port: int, metrics: dict[str, Any]) -> str:
    online = metrics.get("online")
    isolated = metrics.get("isolated")
    cls = "node-card"
    if not online:
        cls += " offline"
        status = '<span class="status-bad">offline</span>'
    elif isolated:
        cls += " isolated"
        status = '<span class="status-iso">isolated</span>'
    else:
        status = '<span class="status-ok">online</span>'

    blocked = ", ".join(metrics.get("blocked_ips") or []) or "—"
    urls = ", ".join((metrics.get("quarantined_urls") or [])[:2]) or "—"
    return f"""
    <div class="{cls}">
      <p class="port">:{port}</p>
      <div>{status}</div>
      <div class="mono" style="margin-top:0.45rem">
        reqs={metrics.get('total_requests', '—')} ·
        mesh={metrics.get('mesh_messages', '—')} ·
        rps={metrics.get('rps_estimate', '—')}<br/>
        kv={metrics.get('key_version', '—')} ·
        remediations={metrics.get('remediations', 0)}<br/>
        blocked: {blocked}<br/>
        quarantine: {urls}
      </div>
    </div>
    """
