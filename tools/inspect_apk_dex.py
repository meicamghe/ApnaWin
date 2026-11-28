"""Inspect DEX metadata and native/process linkage in one or more APK splits."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apnawin.services.apk_dex import inspect_apk_dex  # noqa: E402
from apnawin.services.apk_dex_set import inspect_apk_dex_set  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "apks",
        nargs="+",
        type=Path,
        help="one APK, or a base APK followed by all config/feature split APKs",
    )
    parser.add_argument(
        "--apkanalyzer",
        default="apkanalyzer",
        help="apkanalyzer executable or path (default: apkanalyzer on PATH)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional JSON report path (defaults to standard output)",
    )
    args = parser.parse_args()
    try:
        if len(args.apks) == 1:
            report = inspect_apk_dex(args.apks[0], executable=args.apkanalyzer)
        else:
            report = inspect_apk_dex_set(args.apks, executable=args.apkanalyzer)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
