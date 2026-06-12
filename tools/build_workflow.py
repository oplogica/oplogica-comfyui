#!/usr/bin/env python3
"""
Programmatic workflow generator for the Oplogica payment demo.

Why programmatic instead of hand-authored JSON:
ComfyUI workflow files encode widget values positionally (widgets_values) and
connections by slot index. Hand-authored files silently break when a node
definition changes. This script introspects nodes.py at build time, so the
generated JSON always matches the actual node definitions.

Usage:
    python3 tools/build_workflow.py

Output:
    workflows/oplogica_payment_demo.json   (ComfyUI workflow format 0.4)
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import nodes as opl_nodes  # noqa: E402
from oplogica_core import PACK_VERSION  # noqa: E402

WIDGET_TYPES = {"STRING", "INT", "FLOAT", "BOOLEAN"}


def split_inputs(cls):
    """Return (connection_inputs, widget_inputs) in declaration order.

    connection_inputs: list of (name, type_string)
    widget_inputs:     list of (name, type_or_combo, default)
    """
    it = cls.INPUT_TYPES()
    conns = []
    widgets = []
    for section in ("required", "optional"):
        for name, spec in it.get(section, {}).items():
            t = spec[0]
            cfg = spec[1] if len(spec) > 1 else {}
            if isinstance(t, list):
                # Combo widget.
                widgets.append((name, t, cfg.get("default", t[0])))
            elif t in WIDGET_TYPES and not (isinstance(cfg, dict) and cfg.get("forceInput")):
                widgets.append((name, t, cfg.get("default", "")))
            else:
                # Custom Oplogica type, IMAGE, or forceInput STRING: a connection.
                type_str = t if isinstance(t, str) else "COMBO"
                conns.append((name, type_str))
    return conns, widgets


class WorkflowBuilder:
    def __init__(self):
        self.nodes = []
        self.links = []
        self.groups = []
        self._link_id = 0

    def add_opl_node(self, node_id, class_name, pos, size, order, overrides=None):
        cls = opl_nodes.NODE_CLASS_MAPPINGS[class_name]
        conns, widgets = split_inputs(cls)
        overrides = overrides or {}

        widgets_values = []
        for name, _t, default in widgets:
            widgets_values.append(overrides.get(name, default))

        inputs = [{"name": n, "type": t, "link": None} for n, t in conns]
        outputs = []
        ret_types = cls.RETURN_TYPES
        ret_names = getattr(cls, "RETURN_NAMES", ret_types)
        for i, (t, n) in enumerate(zip(ret_types, ret_names)):
            outputs.append({"name": n, "type": t, "links": [], "slot_index": i})

        self.nodes.append({
            "id": node_id,
            "type": class_name,
            "pos": list(pos),
            "size": list(size),
            "flags": {},
            "order": order,
            "mode": 0,
            "inputs": inputs,
            "outputs": outputs,
            "properties": {"Node name for S&R": class_name},
            "widgets_values": widgets_values,
        })
        return node_id

    def add_core_preview_image(self, node_id, pos, size, order):
        self.nodes.append({
            "id": node_id,
            "type": "PreviewImage",
            "pos": list(pos),
            "size": list(size),
            "flags": {},
            "order": order,
            "mode": 0,
            "inputs": [{"name": "images", "type": "IMAGE", "link": None}],
            "outputs": [],
            "properties": {"Node name for S&R": "PreviewImage"},
            "widgets_values": [],
        })
        return node_id

    def _node(self, node_id):
        for n in self.nodes:
            if n["id"] == node_id:
                return n
        raise KeyError(node_id)

    def link(self, from_id, from_slot, to_id, to_input_name):
        src = self._node(from_id)
        dst = self._node(to_id)
        out = src["outputs"][from_slot]

        to_slot = None
        for i, inp in enumerate(dst["inputs"]):
            if inp["name"] == to_input_name:
                to_slot = i
                break
        if to_slot is None:
            raise ValueError(
                "Input '%s' not found on node %s (%s)"
                % (to_input_name, to_id, dst["type"])
            )

        in_type = dst["inputs"][to_slot]["type"]
        if out["type"] != in_type:
            raise TypeError(
                "Type mismatch: %s.%s (%s) cannot feed %s.%s (%s)"
                % (src["type"], out["name"], out["type"],
                   dst["type"], to_input_name, in_type)
            )

        self._link_id += 1
        lid = self._link_id
        out["links"].append(lid)
        dst["inputs"][to_slot]["link"] = lid
        self.links.append([lid, from_id, from_slot, to_id, to_slot, out["type"]])
        return lid

    def group(self, title, bounding, color):
        self.groups.append({
            "title": title,
            "bounding": list(bounding),
            "color": color,
            "font_size": 24,
            "locked": False,
        })

    def to_json(self):
        return {
            "last_node_id": max(n["id"] for n in self.nodes),
            "last_link_id": self._link_id,
            "nodes": self.nodes,
            "links": self.links,
            "groups": self.groups,
            "config": {},
            "extra": {
                "oplogica": {
                    "pack_version": PACK_VERSION,
                    "scenario": "vendor_payment_demo",
                }
            },
            "version": 0.4,
        }


def build():
    b = WorkflowBuilder()

    # Layer 1: Input.
    b.add_opl_node(1, "OplTaskInput", (60, 140), (420, 360), 0)
    b.add_opl_node(2, "OplEvidenceItem", (60, 560), (420, 330), 1, overrides={
        "claim": "Invoice INV-2291 issued by Acme Cloud for 1840.00 USD",
        "source_url": "https://billing.example.com/INV-2291",
        "content": "Acme Cloud invoice INV-2291. Amount due: 1840.00 USD. "
                   "Service period: May 2026. Status: open.",
    })
    b.add_opl_node(3, "OplEvidenceItem", (60, 940), (420, 330), 2, overrides={
        "claim": "Active services contract with Acme Cloud covers this invoice",
        "source_url": "https://contracts.example.com/ACME-2024-118",
        "content": "Master services agreement ACME-2024-118, active through "
                   "2026-12-31, monthly cloud infrastructure services.",
    })

    # Layer 2: Evidence.
    b.add_opl_node(4, "OplEvidenceCollector", (560, 560), (380, 210), 3)

    # Layer 4: Verification.
    b.add_opl_node(5, "OplPolicyCheck", (1020, 120), (460, 500), 4)

    # Layer 3: Approval. The shipped default is SAFE: decision PENDING,
    # empty approver, empty strict fields. The first queue is pass 1 of the
    # two-pass flow and seals BLOCKED / APPROVAL_PENDING by design. The gate
    # report prints the task hash and the evidence root for the reviewer to
    # copy into the strict fields for pass 2 (see README, two-pass flow).
    b.add_opl_node(6, "OplHumanApprovalGate", (1020, 680), (420, 380), 5)

    # Layer 5: Trust.
    b.add_opl_node(7, "OplDecisionSealer", (1540, 380), (420, 230), 6)

    # Layer 6: Action.
    b.add_opl_node(8, "OplAuditLedgerWriter", (2020, 160), (380, 170), 7)
    b.add_opl_node(9, "OplDecisionCardRenderer", (2020, 440), (380, 230), 8)
    b.add_core_preview_image(10, (2460, 420), (380, 340), 9)

    # Trust: validator runs after the writer (ordering via run_after).
    b.add_opl_node(11, "OplChainValidator", (2460, 120), (380, 170), 10)

    # Utility: show the approval report inline.
    b.add_opl_node(12, "OplTextDisplay", (1540, 700), (420, 250), 11)

    # Wiring.
    b.link(1, 0, 5, "task")            # task -> policy
    b.link(1, 0, 6, "task")            # task -> gate
    b.link(1, 0, 7, "task")            # task -> sealer
    b.link(2, 0, 4, "evidence_1")      # invoice evidence -> collector
    b.link(3, 0, 4, "evidence_2")      # contract evidence -> collector
    b.link(4, 0, 5, "bundle")          # bundle -> policy
    b.link(4, 0, 6, "bundle")          # bundle -> gate (binds approval to evidence)
    b.link(4, 0, 7, "bundle")          # bundle -> sealer
    b.link(5, 0, 7, "policy_result")   # policy -> sealer
    b.link(6, 0, 7, "approval")        # approval -> sealer
    b.link(7, 0, 8, "record")          # record -> ledger writer
    b.link(7, 0, 9, "record")          # record -> card renderer
    b.link(9, 0, 10, "images")         # card -> preview
    b.link(8, 2, 11, "run_after")      # writer record_hash -> validator ordering
    b.link(6, 2, 12, "text")           # gate report -> text display

    # Layer groups (visual bands matching the node colors).
    b.group("1 INPUT", (20, 60, 510, 1260), "#141a22")
    b.group("2 EVIDENCE", (540, 480, 420, 340), "#0b2231")
    b.group("3 APPROVAL", (1000, 620, 470, 440), "#2a1a07")
    b.group("4 VERIFICATION", (1000, 40, 500, 600), "#221038")
    b.group("5 TRUST", (1520, 300, 460, 340), "#062a21")
    b.group("6 ACTION", (2000, 80, 880, 720), "#1a1f29")

    return b.to_json()


def main():
    wf = build()
    out_dir = os.path.join(ROOT, "workflows")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "oplogica_payment_demo.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(wf, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("Wrote %s (%d nodes, %d links, %d groups)" % (
        out_path, len(wf["nodes"]), len(wf["links"]), len(wf["groups"])))


if __name__ == "__main__":
    main()
