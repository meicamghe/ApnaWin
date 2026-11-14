"""Decode selected APK manifest metadata with Android SDK apkanalyzer."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apnawin.services.apk_manifest import inspect_apk_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="path to the APK file")
    parser.add_argument(
        "--apkanalyzer",
        default="apkanalyzer",
        help="apkanalyzer executable or path (default: apkanalyzer on PATH)",
    )
    args = parser.parse_args()
    try:
        report = inspect_apk_manifest(args.apk, executable=args.apkanalyzer)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
