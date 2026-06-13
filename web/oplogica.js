// Oplogica Visual Decision Operating System, frontend extension.
//
// Responsibilities:
//   1. Apply a distinct color family to each Oplogica layer (node header + body).
//   2. Populate the read-only text widget on "Oplogica · Text Display" after execution.
//
// Note: this file depends on the ComfyUI frontend extension API
// (app.registerExtension, beforeRegisterNodeDef, onExecuted). That API is
// stable in practice but not formally versioned. If a future ComfyUI release
// changes it, nodes keep working; only the colors and the inline text panel
// degrade gracefully.

import { app } from "../../scripts/app.js";
import { ComfyWidgets } from "../../scripts/widgets.js";

// Per-node palette: [header, body]. Headers are dark, saturated hues so
// the light title text stays clearly readable in dark mode; bodies are
// the same hue, darker. This map mirrors OPL_NODE_COLORS in nodes.py
// (the single source of truth; a test keeps the two in sync). No node
// may look disabled unless it is.
const OPLOGICA_NODE_COLORS = {
    "OplTaskInput":            ["#2F4368", "#161E2E"],
    "OplEvidenceItem":         ["#14467F", "#0C2440"],
    "OplGenerationContext":    ["#2F4368", "#161E2E"],
    "OplEvidenceCollector":    ["#14467F", "#0C2440"],
    "OplPolicyCheck":          ["#5B21B6", "#26104A"],
    "OplHumanApprovalGate":    ["#8C5400", "#3A2400"],
    "OplDecisionSealer":       ["#0B5A3C", "#06301F"],
    "OplOutputBinder":         ["#0B5A3C", "#06301F"],
    "OplGraphAttestor":        ["#0B5A3C", "#06301F"],
    "OplChainValidator":       ["#0A5C5C", "#052E2E"],
    "OplAuditLedgerWriter":    ["#3D4F66", "#1D2735"],
    "OplDecisionCardRenderer": ["#3A4150", "#1C202A"],
    "OplPassportExporter":     ["#3730A3", "#181563"],
    "OplTextDisplay":          ["#313D52", "#171D29"],
};

// Category fallback for any future Oplogica node not yet in the map.
const OPLOGICA_LAYER_COLORS = {
    "Oplogica/1 Input":        ["#2F4368", "#161E2E"],
    "Oplogica/2 Evidence":     ["#14467F", "#0C2440"],
    "Oplogica/3 Approval":     ["#8C5400", "#3A2400"],
    "Oplogica/4 Verification": ["#5B21B6", "#26104A"],
    "Oplogica/5 Trust":        ["#0B5A3C", "#06301F"],
    "Oplogica/6 Action":       ["#3D4F66", "#1D2735"],
    "Oplogica/Utility":        ["#313D52", "#171D29"],
};

function layerColorsFor(category) {
    if (!category) return null;
    for (const prefix of Object.keys(OPLOGICA_LAYER_COLORS)) {
        if (category.startsWith(prefix)) {
            return OPLOGICA_LAYER_COLORS[prefix];
        }
    }
    return null;
}

app.registerExtension({
    name: "oplogica.decision.os",

    async beforeRegisterNodeDef(nodeType, nodeData, appRef) {
        const colors = OPLOGICA_NODE_COLORS[nodeData?.name]
            || layerColorsFor(nodeData?.category);

        if (colors) {
            const [headerColor, bodyColor] = colors;
            const onNodeCreated = nodeType.prototype.onNodeCreated;
            nodeType.prototype.onNodeCreated = function () {
                const r = onNodeCreated ? onNodeCreated.apply(this, arguments) : undefined;
                this.color = headerColor;
                this.bgcolor = bodyColor;
                return r;
            };
        }

        // Inline text panel for the Text Display node.
        if (nodeData?.name === "OplTextDisplay") {
            const onExecuted = nodeType.prototype.onExecuted;
            nodeType.prototype.onExecuted = function (message) {
                if (onExecuted) onExecuted.apply(this, arguments);
                try {
                    const text = (message?.text ?? []).join("");
                    let w = this.widgets ? this.widgets.find((x) => x.name === "display") : null;
                    if (!w) {
                        w = ComfyWidgets["STRING"](
                            this,
                            "display",
                            ["STRING", { multiline: true }],
                            app
                        ).widget;
                        w.inputEl.readOnly = true;
                        w.inputEl.style.opacity = 0.85;
                        w.inputEl.style.fontFamily = "monospace";
                    }
                    w.value = text;
                    this.onResize?.(this.size);
                } catch (e) {
                    // Frontend API drift: fall back to console so the data is never lost.
                    console.log("[Oplogica] Text Display:", message?.text);
                }
            };
        }
    },
});
