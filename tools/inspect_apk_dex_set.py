"""Inspect manifest and DEX linkage across all supplied APK splits."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apnawin.services.apk_dex_set import inspect_apk_dex_set  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apks", nargs="+", type=Path, help="base APK and any split APKs")
    parser.add_argument(
        "--apkanalyzer",
        default="apkanalyzer",
        help="apkanalyzer executable or path (default: apkanalyzer on PATH)",
    )
    args = parser.parse_args()
    try:
        report = inspect_apk_dex_set(args.apks, executable=args.apkanalyzer)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
