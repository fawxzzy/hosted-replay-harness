#!/usr/bin/env python3
"""Validate one closed, sanitized Fitness replay receipt."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "fitness_full_chain_replay.py"


def load_adapter():
    spec = importlib.util.spec_from_file_location("fitness_full_chain_replay", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("adapter unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        return load_adapter().verify_receipt(args.input)
    except (OSError, RuntimeError, ValueError, UnicodeError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
