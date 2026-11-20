"""HTML visualizations for the three-node mesh."""

from __future__ import annotations

from typing import Any


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
