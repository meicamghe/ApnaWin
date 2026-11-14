"""Print a privacy-conscious static inventory of one APK; never extract or execute it."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Permit running directly from a source checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apnawin.services.apk_inventory import inspect_apk  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="path to the APK file")
    args = parser.parse_args()
    try:
        report = inspect_apk(args.apk)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
