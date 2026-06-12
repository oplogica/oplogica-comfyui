"""Pytest configuration for the Oplogica ComfyUI extension.

The pack root is a Python package (ComfyUI requires __init__.py with
relative imports), so pytest's package collection imports this directory's
__init__.py at setup. Putting the pack root on sys.path here guarantees
that the absolute-import fallbacks in __init__.py and nodes.py resolve,
regardless of the directory pytest is invoked from.

Run either way:
    pytest tests/ -q
    python3 tests/test_oplogica.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
