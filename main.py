from __future__ import annotations

import asyncio
import argparse
import json
import sys
import time
from pathlib import Path

from config import REPORT_DIR, ensure_runtime_dirs
from engine.scanner import AndroidVulnScanner


def print_banner() -> None:
    banner = """
    ========================================================
     Android TPL & Vulnerability Detection System (Scanner)
     -> Powered by LibHunter & PHunter Probes
    ========================================================
    """
    print(banner)


def save_final_report(apk_name: str, report_data: dict) -> Path:
    report_path = REPORT_DIR / f"{apk_name}_vuln_report.json"
    report_path.write_text(
        json.dumps(report_data, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    return report_path


async def analyze_apk_async(apk_path: str | Path, *, print_summary: bool = True) -> dict:
    ensure_runtime_dirs()
    print_banner()

    target_apk = Path(apk_path).expanduser().resolve()
    if not target_apk.exists():
        raise FileNotFoundError(f"APK file not found: {target_apk}")

    start_time = time.time()
    scanner = AndroidVulnScanner(target_apk)

    # 直接同步调用scan方法，避免asyncio.to_thread在子进程中出现问题
    try:
        final_report = scanner.scan()  # 同步调用
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Scan failed for APK {target_apk}: {e}")
        raise

    report_file = save_final_report(scanner.apk_info["name"], final_report)
    elapsed_time = time.time() - start_time

    if print_summary:
        print("\n" + "=" * 56)
        print(" [DONE] Scan Completed")
        print("=" * 56)
        print(f"  - Target APK: {scanner.apk_info['name']}")
        print(f"  - Libraries: {len(final_report.get('used_libraries', []))}")
        print(f"  - Vulnerabilities: {len(final_report.get('vulnerabilities', []))}")
        print(f"  - Elapsed: {elapsed_time:.2f}s")
        print(f"  - Report: {report_file}")
        print("=" * 56 + "\n")

    return {
        "apk_name": scanner.apk_info["name"],
        "report_path": str(report_file),
        "report_data": final_report,
        "elapsed_time": elapsed_time,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Android APK vulnerability scanner")
    parser.add_argument("--apk", required=True, help="Target APK file path")
    args = parser.parse_args()

    try:
        asyncio.run(analyze_apk_async(args.apk, print_summary=True))
        return 0
    except Exception as exc:
        print(f"[-] Scan failed: {exc}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
