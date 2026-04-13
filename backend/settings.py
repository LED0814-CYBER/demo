from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional local helper
    load_dotenv = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOTENV_PATH = PROJECT_ROOT / ".env"

if load_dotenv is not None and DOTENV_PATH.exists():
    load_dotenv(DOTENV_PATH)


def _env_path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    if not raw:
        return default.resolve()

    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (PROJECT_ROOT / path)
    return path.resolve()


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return value.strip() if value else default


@dataclass(frozen=True)
class Settings:
    project_root: Path
    database_url: str
    redis_url: str
    celery_broker_url: str
    celery_result_backend: str
    storage_dir: Path
    upload_dir: Path
    report_dir: Path
    log_dir: Path
    phunter_cache_dir: Path
    libhunter_cache_dir: Path
    python_bin: str
    java_bin: str
    android_jar_path: Path
    phunter_jar_path: Path

    def ensure_runtime_dirs(self) -> None:
        for path in (
            self.storage_dir,
            self.upload_dir,
            self.report_dir,
            self.log_dir,
            self.phunter_cache_dir,
            self.libhunter_cache_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


_default_storage = PROJECT_ROOT / "storage"
_default_redis = _env_str("REDIS_URL", "redis://redis:6379/0")
_default_db_path = (_default_storage / "app.db").resolve()

default_settings = Settings(
    project_root=PROJECT_ROOT,
    database_url=_env_str("DATABASE_URL", f"sqlite:///{_default_db_path}"),
    redis_url=_default_redis,
    celery_broker_url=_env_str("CELERY_BROKER_URL", _default_redis),
    celery_result_backend=_env_str("CELERY_RESULT_BACKEND", _default_redis),
    storage_dir=_env_path("STORAGE_DIR", _default_storage),
    upload_dir=_env_path("UPLOAD_DIR", _default_storage / "uploads"),
    report_dir=_env_path("REPORT_DIR", _default_storage / "reports"),
    log_dir=_env_path("LOG_DIR", _default_storage / "logs"),
    phunter_cache_dir=_env_path("PHUNTER_CACHE_DIR", PROJECT_ROOT / "data" / "phunter_soot_cache"),
    libhunter_cache_dir=_env_path("LIBHUNTER_CACHE_DIR", PROJECT_ROOT / "data" / "lib_pickles_cache"),
    python_bin=_env_str("PYTHON_BIN", "python3"),
    java_bin=_env_str("JAVA_BIN", "java"),
    android_jar_path=_env_path("ANDROID_JAR_PATH", PROJECT_ROOT / "PHunter" / "android-31" / "android.jar"),
    phunter_jar_path=_env_path("PHUNTER_JAR_PATH", PROJECT_ROOT / "PHunter" / "PHunter.jar"),
)

settings = default_settings
settings.ensure_runtime_dirs()
