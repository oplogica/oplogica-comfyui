"""Oplogica decision card renderer.

Renders a decision record as a dark-theme card image (default 1200x675,
LinkedIn-native 16:9). Pure PIL: works inside ComfyUI and standalone.
"""

from __future__ import annotations

import os

try:
    from .oplogica_core import short_hash
except ImportError:
    from oplogica_core import short_hash

BG = "#0B0F14"
PANEL = "#111722"
LINE = "#1F2937"
TEXT_MAIN = "#F1F5F9"
TEXT_SOFT = "#94A3B8"
TEXT_DIM = "#64748B"
ACCENT = "#38BDF8"

VERDICT_STYLE = {
    "APPROVED": {"fg": "#10B981", "bg": "#062A21"},
    "BLOCKED": {"fg": "#EF4444", "bg": "#2A0B0B"},
    "PENDING": {"fg": "#F59E0B", "bg": "#2A1A07"},
}

RISK_COLOR = {
    "low": "#10B981", "medium": "#F59E0B",
    "high": "#F97316", "critical": "#EF4444",
}

_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "DejaVuSans.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "C:\\Windows\\Fonts\\arial.ttf",
    "arial.ttf",
]
_FONT_BOLD_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "DejaVuSans-Bold.ttf",
    "C:\\Windows\\Fonts\\arialbd.ttf",
    "arialbd.ttf",
]
_FONT_MONO_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "DejaVuSansMono.ttf",
    "C:\\Windows\\Fonts\\consola.ttf",
]


def _font(size, candidates):
    from PIL import ImageFont
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def render_card(record: dict, width: int = 1200, height: int = 675):
    """Render a decision record to a PIL Image."""
    from PIL import Image, ImageDraw

    scale = width / 1200.0
    s = lambda v: max(1, int(round(v * scale)))

    f_brand = _font(s(34), _FONT_BOLD_CANDIDATES)
    f_h1 = _font(s(27), _FONT_BOLD_CANDIDATES)
    f_verdict = _font(s(42), _FONT_BOLD_CANDIDATES)
    f_label = _font(s(13), _FONT_BOLD_CANDIDATES)
    f_body = _font(s(17), _FONT_CANDIDATES)
    f_small = _font(s(13), _FONT_CANDIDATES)
    f_mono = _font(s(15), _FONT_MONO_CANDIDATES)

    verdict = record.get("verdict", {}).get("status", "PENDING")
    style = VERDICT_STYLE.get(verdict, VERDICT_STYLE["PENDING"])

    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)

    # Top verdict accent bar
    d.rectangle([0, 0, width, s(8)], fill=style["fg"])

    m = s(56)
    y = s(36)

    # Header
    d.text((m, y), "OPLOGICA", font=f_brand, fill=TEXT_MAIN)
    bw = d.textlength("OPLOGICA", font=f_brand)
    d.text((m + bw + s(12), y), "VERIFY", font=f_brand, fill=ACCENT)

    rid = record.get("record_id", "")[:8]
    header_r = f"DECISION RECORD  {rid}"
    rw = d.textlength(header_r, font=f_label)
    d.text((width - m - rw, y + s(6)), header_r, font=f_label, fill=TEXT_DIM)
    ts = record.get("created_at", "")
    tw = d.textlength(ts, font=f_small)
    d.text((width - m - tw, y + s(26)), ts, font=f_small, fill=TEXT_DIM)

    y += s(64)
    d.line([m, y, width - m, y], fill=LINE, width=1)
    y += s(26)

    # Verdict pill, right side
    pill_w, pill_h = s(300), s(86)
    px = width - m - pill_w
    py = y
    d.rounded_rectangle([px, py, px + pill_w, py + pill_h], radius=s(14),
                        fill=style["bg"], outline=style["fg"], width=s(2))
    vw = d.textlength(verdict, font=f_verdict)
    d.text((px + (pill_w - vw) / 2, py + s(18)), verdict,
           font=f_verdict, fill=style["fg"])

    reasons = record.get("verdict", {}).get("reasons", [])
    ry = py + pill_h + s(12)
    for r in reasons[:3]:
        line = f"x {r}"
        d.text((px, ry), line[:40], font=f_small, fill=style["fg"])
        ry += s(20)

    # Left column: TASK
    task = record.get("task", {})
    col_w = width - m * 2 - pill_w - s(40)

    d.text((m, y), "TASK", font=f_label, fill=TEXT_DIM)
    y += s(24)
    d.text((m, y), str(task.get("action_type", "?")), font=f_h1, fill=TEXT_MAIN)
    y += s(40)
    actor_line = f"actor  {task.get('actor', '?')}  ({task.get('actor_type', '?')})"
    d.text((m, y), actor_line, font=f_body, fill=TEXT_SOFT)
    y += s(28)
    amt = task.get("amount")
    if amt is not None:
        amount_line = f"{float(amt):,.2f} {task.get('currency', '')}"
        d.text((m, y), amount_line, font=f_h1, fill=TEXT_MAIN)
        risk = str(task.get("risk_hint", "")).lower()
        rk = RISK_COLOR.get(risk, TEXT_DIM)
        aw = d.textlength(amount_line, font=f_h1)
        d.text((m + aw + s(18), y + s(8)), f"risk: {risk}", font=f_body, fill=rk)
        y += s(44)

    d.line([m, y, m + col_w, y], fill=LINE, width=1)
    y += s(18)

    # EVIDENCE
    ev = record.get("evidence", {})
    stats = ev.get("stats", {})
    d.text((m, y), "EVIDENCE", font=f_label, fill=TEXT_DIM)
    y += s(22)
    ev_line = (f"{stats.get('unique_count', 0)} item(s)   "
               f"merkle {short_hash(ev.get('merkle_root', ''))}")
    d.text((m, y), ev_line, font=f_mono, fill=ACCENT)
    y += s(24)
    issues = []
    if stats.get("missing_source_count"):
        issues.append(f"{stats['missing_source_count']} missing source")
    if stats.get("incomplete_count"):
        issues.append(f"{stats['incomplete_count']} incomplete")
    if stats.get("duplicates_removed"):
        issues.append(f"{stats['duplicates_removed']} duplicate(s) removed")
    if issues:
        d.text((m, y), " | ".join(issues), font=f_small, fill="#F59E0B")
        y += s(22)
    out_sec = record.get("output")
    wf_sec = record.get("workflow")
    bind_bits = []
    if out_sec:
        bind_bits.append(f"output {short_hash(out_sec.get('output_hash', ''))}")
    if wf_sec and wf_sec.get("graph_hash"):
        tag = "" if wf_sec.get("match", True) else " (CHANGED)"
        bind_bits.append(f"graph {short_hash(wf_sec['graph_hash'])}{tag}")
    if bind_bits:
        d.text((m, y), "   ".join(bind_bits), font=f_mono, fill=TEXT_SOFT)
        y += s(22)
    y += s(8)

    # CHECKS
    pol = record.get("checks", {}).get("policy", {})
    checks = pol.get("checks", [])
    n_pass = sum(1 for c in checks if c.get("passed"))
    d.text((m, y), "CHECKS", font=f_label, fill=TEXT_DIM)
    y += s(22)
    pol_ok = pol.get("passed", False)
    check_line = (f"policy {pol.get('policy_id', '?')} v{pol.get('policy_version', '?')}"
                  f"   {n_pass}/{len(checks)} rules passed")
    d.text((m, y), check_line, font=f_body,
           fill="#10B981" if pol_ok else "#EF4444")
    y += s(32)

    # APPROVAL
    approvals = record.get("approvals", [])
    ap = approvals[0] if approvals else {}
    d.text((m, y), "HUMAN APPROVAL", font=f_label, fill=TEXT_DIM)
    y += s(22)
    eff = ap.get("effective_decision", "PENDING")
    ap_color = VERDICT_STYLE.get(
        eff if eff in VERDICT_STYLE else
        ("BLOCKED" if eff == "REJECTED" else "PENDING"))["fg"]
    approver = ap.get("approver") or "(no approver identity)"
    d.text((m, y), f"{approver}   {eff}", font=f_body, fill=ap_color)
    y += s(26)
    bound_task = ap.get("bound_task_hash", "")
    if bound_task:
        d.text((m, y), f"bound task      {short_hash(bound_task)}",
               font=f_mono, fill=TEXT_SOFT)
        y += s(22)
    bound_evid = ap.get("bound_evidence_root", "")
    if bound_evid:
        d.text((m, y), f"bound evidence  {short_hash(bound_evid)}",
               font=f_mono, fill=TEXT_SOFT)
        y += s(22)
    mode = ap.get("binding_mode", "")
    if mode:
        mode_color = TEXT_SOFT if mode == "strict" else "#F59E0B"
        d.text((m, y), f"binding mode    {mode}", font=f_mono,
               fill=mode_color)

    # Chain footer block
    cy = height - s(118)
    d.line([m, cy, width - m, cy], fill=LINE, width=1)
    cy += s(16)
    prev = record.get("chain", {}).get("prev_record_hash", "")
    rh = record.get("integrity", {}).get("record_hash", "")
    d.text((m, cy), "CHAIN", font=f_label, fill=TEXT_DIM)
    chain_line = f"prev {short_hash(prev)}  >>  record {short_hash(rh)}"
    d.text((m + s(80), cy), chain_line, font=f_mono, fill=TEXT_MAIN)
    sig = record.get("integrity", {}).get("signature")
    sig_line = (f"HMAC-SHA256 key {sig.get('key_id')}"
                if sig else "unsigned (no HMAC key configured)")
    cy += s(28)
    d.text((m + s(80), cy), sig_line, font=f_small,
           fill=TEXT_SOFT if sig else TEXT_DIM)

    # Footer
    fy = height - s(40)
    d.text((m, fy), "Tamper-evident record. Integrity is not truth.",
           font=f_small, fill=TEXT_DIM)
    brand = "oplogica.com"
    bw2 = d.textlength(brand, font=f_small)
    d.text((width - m - bw2, fy), brand, font=f_small, fill=TEXT_DIM)

    return img


def save_card(record: dict, out_dir: str, prefix: str = "oplogica_card",
              width: int = 1200, height: int = 675) -> str:
    os.makedirs(out_dir, exist_ok=True)
    img = render_card(record, width, height)
    rid = record.get("record_id", "rec")[:8]
    path = os.path.join(out_dir, f"{prefix}_{rid}.png")
    img.save(path)
    return path
