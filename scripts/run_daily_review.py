#!/usr/bin/env python3
"""Compatibility entry point for the renamed intelligence refresh command."""

from __future__ import annotations

import warnings
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.refresh_intelligence import main


if __name__ == "__main__":
    warnings.warn(
        "scripts/run_daily_review.py is deprecated; use scripts/refresh_intelligence.py --refresh",
        DeprecationWarning,
        stacklevel=1,
    )
    main()
