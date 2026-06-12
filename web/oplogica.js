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

// Layer palette. Keys are category prefixes, values are [header, body].
const OPLOGICA_LAYER_COLORS = {
    "Oplogica/1 Input":        ["#475569", "#141a22"],
    "Oplogica/2 Evidence":     ["#0369A1", "#0b2231"],
    "Oplogica/3 Approval":     ["#B45309", "#2a1a07"],
    "Oplogica/4 Verification": ["#7C3AED", "#221038"],
    "Oplogica/5 Trust":        ["#059669", "#062a21"],
    "Oplogica/6 Action":       ["#6B7280", "#1a1f29"],
    "Oplogica/Utility":        ["#334155", "#10151c"],
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
        const colors = layerColorsFor(nodeData?.category);

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
