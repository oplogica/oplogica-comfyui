"""
Oplogica Visual Decision Operating System for ComfyUI.

Registers the Oplogica node pack and exposes the web extension directory
used for layer-based node coloring and the text display widget.

Pack version: 1.0.0
"""

try:
    from .nodes import NODE_CLASS_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS
except ImportError:
    # Imported outside a package context (pytest rootdir package setup,
    # standalone tooling). ComfyUI always imports this file as a package,
    # taking the relative branch above.
    from nodes import NODE_CLASS_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS

WEB_DIRECTORY = "./web"

__all__ = [
    "NODE_CLASS_MAPPINGS",
    "NODE_DISPLAY_NAME_MAPPINGS",
    "WEB_DIRECTORY",
]
