from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

# Project root
BASE_DIR = Path(__file__).resolve().parent

# Input / output
INPUT_DIR = BASE_DIR / "inputs"
OUTPUT_DIR = BASE_DIR / "outputs"
LOG_DIR = OUTPUT_DIR / "logs"
RAW_DIR = OUTPUT_DIR / "raw"
REPORT_DIR = OUTPUT_DIR / "reports"

# Data
DATA_DIR = BASE_DIR / "data"
PATCH_DIR = DATA_DIR / "patches"
CVE_KB_PATH = DATA_DIR / "cve_kb.json"

# LibHunter global pickle cache directory (prewarm)
PICKLE_CACHE_DIR = DATA_DIR / "lib_pickle_cache"

# TPL feature directories
LIBHUNTER_TPLS_DEX = DATA_DIR / "tpl_dex"
LIBHUNTER_TPLS_JAR = DATA_DIR / "tpl_jar"

# LibHunter tool
LIBHUNTER_DIR = BASE_DIR / "LibHunter"
LIBHUNTER_SCRIPT = LIBHUNTER_DIR / "LibHunter.py"

if sys.platform == "win32":
    _LH_VENV_PYTHON = LIBHUNTER_DIR / ".venv" / "Scripts" / "python.exe"
else:
    _LH_VENV_PYTHON = LIBHUNTER_DIR / ".venv" / "bin" / "python"
PYTHON_BIN = _LH_VENV_PYTHON if _LH_VENV_PYTHON.exists() else Path(sys.executable)

# PHunter tool
PHUNTER_DIR = BASE_DIR / "PHunter"
PHUNTER_JAR = PHUNTER_DIR / "PHunter.jar"
ANDROID_JAR = PHUNTER_DIR / "android-31" / "android.jar"

# System tools
JAVA_BIN = Path(shutil.which("java") or "java")

# Timeout / thread settings
DEFAULT_PHUNTER_THREADS = 2
DEFAULT_LIBHUNTER_TIMEOUT = 20 * 60
DEFAULT_PHUNTER_TIMEOUT = 5 * 60

MAX_PHUNTER_CONCURRENT = int(os.getenv("MAX_PHUNTER_CONCURRENT", "1"))
LIB_SIMILAR_THRESHOLD = float(os.getenv("LH_LIB_THRESHOLD", "0.85"))
SUBPROCESS_HEARTBEAT_TIMEOUT = int(os.getenv("HEARTBEAT_TIMEOUT", "60"))
PHUNTER_HEARTBEAT_TIMEOUT = int(os.getenv("PHUNTER_HEARTBEAT_TIMEOUT", "300"))
_CPU_COUNT = os.cpu_count() or 1
LIBHUNTER_PROCESSES = int(os.getenv("LIBHUNTER_PROCESSES", str(max(1, _CPU_COUNT // 2))))
LIBHUNTER_HEARTBEAT_TIMEOUT = int(os.getenv("LIBHUNTER_HEARTBEAT_TIMEOUT", "600"))


def build_pythonpath() -> str:
    """Inject LibHunter root into PYTHONPATH for child process imports."""
    paths = [str(LIBHUNTER_DIR)]
    existing = os.environ.get("PYTHONPATH")
    if existing:
        paths.append(existing)
    return os.pathsep.join(paths)


def ensure_runtime_dirs() -> None:
    for path in (
        INPUT_DIR,
        OUTPUT_DIR,
        LOG_DIR,
        RAW_DIR,
        REPORT_DIR,
        DATA_DIR,
        PATCH_DIR,
        PICKLE_CACHE_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
