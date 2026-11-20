"""Shared SOC Copilot design system. All interpolated content is escaped."""
from html import escape
import streamlit as st

CSS = """
<style>
:root { --soc-muted: #91a1b7; --soc-line: #263242; --soc-accent: #5de4cf; }
.stApp { background: #0c1118; }
.block-container { max-width: 1510px; padding: 2.1rem 2.5rem 3rem; }
[data-testid="stSidebar"] { background: #101720; border-right: 1px solid #25303e; }
[data-testid="stSidebar"] [data-testid="stSidebarNav"] { padding-top: .5rem; }
h1,h2,h3 { letter-spacing: -.035em; }
h1 { font-size: 2rem !important; font-weight: 650 !important; }
h2 { font-size: 1.35rem !important; }
h3 { font-size: 1.06rem !important; }
.st-key-workspace_top { padding-bottom: .3rem; }
.soc-eyebrow { color: #5de4cf; text-transform: uppercase; font-size: .68rem; font-weight: 700; letter-spacing: .16em; margin-bottom: .65rem; }
.soc-title { color: #eff5fc; font-size: 2.25rem; line-height: 1.15; font-weight: 650; letter-spacing: -.055em; margin: 0 0 .55rem; }
.soc-subtitle { color: #91a1b7; font-size: .9rem; line-height: 1.65; margin-bottom: 1.4rem; }
.soc-brand { display:flex; gap:.75rem; align-items:center; margin: .4rem 0 1.7rem; color: #f0f5fb; }
.soc-brand-mark { width:38px; height:42px; background:#173b3c; color:#5de4cf; clip-path:polygon(50% 0,95% 16%,87% 72%,50% 100%,13% 72%,5% 16%); display:grid;place-items:center;font-weight:800;font-size:1.1rem; }
.soc-brand-name { font-size:1.2rem; font-weight:700; letter-spacing:-.035em; }
.soc-brand-sub { color:#8293ab; font-size:.65rem;letter-spacing:.1em;text-transform:uppercase; }
.soc-status { display: inline-flex; gap:.5rem; align-items:center; padding:.4rem .7rem; border:1px solid #2a3c46; border-radius:999px; font-size:.72rem; color:#c0d4dd; background:#14222a; }
.soc-status-dot { height:6px; width:6px; background:#5de4cf; border-radius:50%; box-shadow:0 0 9px #5de4cf60; }
.soc-stat { padding:1.05rem 1.2rem; background:#121a24; border:1px solid #263242; border-radius:12px; min-height:112px; margin-bottom:1.5rem; }
.soc-stat-label { color:#9aabc0; font-size:.72rem; letter-spacing:.01em; }
.soc-stat-value { color:#edf3fc; font-size:1.9rem; font-weight:600; letter-spacing:-.045em; line-height:1.6; }
.soc-stat-foot { color:#778ba5; font-size:.67rem; }
.soc-context { background:#101c24; border:1px solid #29413e; border-left:3px solid #5de4cf; border-radius:9px; padding:.9rem 1rem; margin:.5rem 0 1rem; }
.soc-context-title { font-size:.85rem; font-weight:650; color:#e0ebf7; margin:.4rem 0; }
.soc-context-meta { color:#8fa1b7; font-size:.7rem; overflow-wrap:anywhere; }
.soc-tag { display:inline-block; color:#a9bdcf; background:#1d2a39; border:1px solid #2a3e52; border-radius:5px; padding:.18rem .45rem; font-size:.63rem; margin-right:.4rem; }
.soc-tag.high { color:#ffc292;background:#35271f;border-color:#5d3e28; }
.soc-tag.critical { color:#ffb0b9;background:#35212a;border-color:#653340; }
.soc-empty { border:1px dashed #324152; border-radius:12px; padding:2.6rem 1.8rem; text-align:center; margin:1rem 0; background:radial-gradient(ellipse at 50% 0, #172e32 0%, #121a24 70%); }
.soc-empty-icon { margin:0 auto 1rem; width:52px;height:52px;border:1px solid #3c6768;border-radius:16px;display:grid;place-items:center;color:#5de4cf;font-size:1.5rem; }
.soc-empty h3 { font-size:1.35rem !important; color:#e5edf9; }
.soc-empty p { color:#94a5ba;font-size:.83rem;line-height:1.8;max-width:380px;margin:.5rem auto; }
.soc-footer { border-top:1px solid #263242; color:#75879d;font-size:.68rem;margin-top:1.5rem;padding-top:1rem; }
[data-testid="stVerticalBlockBorderWrapper"] > div { border-color:#263242 !important; border-radius:12px !important; }
[data-testid="stTabs"] [role="tablist"] { gap:1.1rem; border-bottom:1px solid #263242; }
[data-testid="stTabs"] [role="tab"] { font-size:.8rem; }
[data-testid="stTabs"] [aria-selected="true"] { color:#5de4cf; }
[data-testid="stTextArea"] textarea { font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.75rem;line-height:1.65; background:#0d141d; }
[data-testid="stMetricValue"] { font-size:1.35rem; }
[data-testid="stButton"] button { border-radius:7px; min-height:2.6rem; font-size:.8rem; }
[data-testid="stButton"] button[kind="primary"] { color:#092323; font-weight:650; }
[data-testid="stCheckbox"] label p { font-size:.82rem;line-height:1.7;white-space:normal !important;display:block; }
[data-testid="stAlert"] { font-size:.82rem; }
.soc-banner { border-bottom:1px solid #263242;padding:1rem 0;margin-bottom:1rem; }
.soc-banner p { color:#91a1b7; }
.node-card { background:#141c26;border:1px solid #263242;border-radius:12px;padding:1rem;color:#e7edf5; }
.node-card.offline { opacity:.6; }
.node-card.isolated { border-color:#e9a26c; }
.node-card .status-ok { color:#5de4cf; }
.node-card .status-bad { color:#ff9bab; }
.node-card .status-iso { color:#ffc292; }
.mesh-svg-wrap { background:#121a24;border:1px solid #263242;border-radius:12px;padding:.5rem; }
.pill { display:inline-block;border-radius:6px;font-size:.7rem;padding:.15rem .45rem;margin-right:.35rem; }
.pill-info { background:#1d2a39;color:#bad0eb; }
.pill-ok { background:#173b32;color:#8ce9c7; }
.pill-warn { background:#35271f;color:#ffc292; }
.pill-crit { background:#35212a;color:#ffb0b9; }
.timeline-item { border-left:2px solid #3c626c;padding:.3rem 0 .6rem .8rem;margin-bottom:.4rem; }
.mono { font-family:ui-monospace,Consolas,monospace;font-size:.8rem; }
@media(max-width:850px) { .block-container { padding:1.2rem 1rem 2rem; } .soc-title { font-size:1.8rem; } .soc-stat { min-height:98px;padding:.8rem; } }
@media(max-width:640px) {
[data-testid="stHorizontalBlock"]:has(.soc-stat) { flex-wrap:wrap;gap:.6rem; }
[data-testid="stHorizontalBlock"]:has(.soc-stat) > [data-testid="stColumn"] { min-width:calc(50% - .6rem) !important;width:calc(50% - .6rem) !important;flex:1 1 calc(50% - .6rem) !important; }
.soc-stat { min-height:95px;margin-bottom:.2rem; }
.soc-stat-foot { display:none; }
}
</style>
"""


def inject_styles() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def banner(title: str, subtitle: str) -> None:
    st.markdown(f'<div class="soc-banner"><h1>{escape(title)}</h1><p>{escape(subtitle)}</p></div>', unsafe_allow_html=True)


def brand() -> None:
    st.markdown('<div class="soc-brand"><div class="soc-brand-mark">S</div><div><div class="soc-brand-name">SOC Copilot<span style="color:#5de4cf">.</span></div><div class="soc-brand-sub">Incident response workspace</div></div></div>', unsafe_allow_html=True)


def stat_card(label: str, value: str, foot: str) -> None:
    st.markdown(f'<div class="soc-stat"><div class="soc-stat-label">{escape(label)}</div><div class="soc-stat-value">{escape(str(value))}</div><div class="soc-stat-foot">{escape(foot)}</div></div>', unsafe_allow_html=True)
