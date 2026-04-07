"""
edi_compare_lib.py — passthrough to canonical shared library.

The canonical implementation lives at:
    ~/projects/shared/lib/edi_compare_lib.py

This file re-exports everything from there so callers importing from
this project directory get the single authoritative version.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared' / 'lib'))
from edi_compare_lib import *  # noqa: F401, F403
from edi_compare_lib import __version__, __release_date__  # noqa: F401
