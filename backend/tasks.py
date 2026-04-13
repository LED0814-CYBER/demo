from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path

from backend.celery_app import celery_app
from backend.db import SessionLocal, init_db
from backend.models import AnalysisTask, VulnerabilityReport
from backend.settings import settings

init_db()
logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.utcnow()


def _load_report(report_path: Path) -> dict | None:
    if not report_path.exists() or not report_path.is_file():
        return None
    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _build_subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHON_BIN"] = settings.python_bin
    env["JAVA_BIN"] = settings.java_bin
    env["ANDROID_JAR_PATH"] = str(settings.android_jar_path)
    env["PHUNTER_JAR_PATH"] = str(settings.phunter_jar_path)
    env["PHUNTER_CACHE_DIR"] = str(settings.phunter_cache_dir)
    env["LIBHUNTER_CACHE_DIR"] = str(settings.libhunter_cache_dir)
    env["UPLOAD_DIR"] = str(settings.upload_dir)
    env["REPORT_DIR"] = str(settings.report_dir)
    env["LOG_DIR"] = str(settings.log_dir)
    env.setdefault("STORAGE_DIR", str(settings.storage_dir))
    return env


@celery_app.task(name="backend.tasks.run_analysis_task", bind=True)
def run_analysis_task(self, task_id: str, apk_path: str) -> dict:
    db = SessionLocal()
    try:
        task = db.get(AnalysisTask, task_id)
        if task is None:
            return {"status": "missing", "task_id": task_id}

        stdout_log = settings.log_dir / f"task_{task_id}.stdout.log"
        stderr_log = settings.log_dir / f"task_{task_id}.stderr.log"
        task.stdout_log_path = str(stdout_log)
        task.stderr_log_path = str(stderr_log)
        task.status = "running"
        task.started_at = _utcnow()
        db.commit()

        cmd = [settings.python_bin, "main.py", "--apk", apk_path]
        logger.info("Starting scan task %s with command: %s", task_id, " ".join(cmd))
        result = subprocess.run(
            cmd,
            cwd=str(settings.project_root),
            capture_output=True,
            text=True,
            env=_build_subprocess_env(),
            check=False,
        )

        stdout_log.write_text(result.stdout or "", encoding="utf-8")
        stderr_log.write_text(result.stderr or "", encoding="utf-8")
        logger.info("Finished scan task %s, returncode=%s", task_id, result.returncode)

        if result.returncode != 0:
            task.status = "failed"
            task.error_message = (
                f"Scanner exited with code {result.returncode}. "
                f"See logs: {stdout_log.name}, {stderr_log.name}"
            )
            task.finished_at = _utcnow()
            db.commit()
            return {
                "status": task.status,
                "task_id": task_id,
                "returncode": result.returncode,
            }

        report_path = settings.report_dir / f"{Path(apk_path).name}_vuln_report.json"
        if not report_path.exists():
            legacy_report = settings.project_root / "outputs" / "reports" / f"{Path(apk_path).name}_vuln_report.json"
            if legacy_report.exists():
                report_path = legacy_report

        report_json = _load_report(report_path)
        if report_json is None:
            task.status = "failed"
            task.error_message = f"Report not found or invalid JSON: {report_path}"
            task.finished_at = _utcnow()
            db.commit()
            return {"status": task.status, "task_id": task_id}

        task.status = "completed"
        task.report_path = str(report_path)
        task.error_message = None
        task.finished_at = _utcnow()

        report = task.report
        if report is None:
            report = VulnerabilityReport(task_id=task.id, report_path=str(report_path), report_json=report_json)
            db.add(report)
        else:
            report.report_path = str(report_path)
            report.report_json = report_json

        db.commit()
        return {
            "status": task.status,
            "task_id": task_id,
            "report_path": str(report_path),
            "vulnerability_count": len(report_json.get("vulnerabilities", [])),
        }
    except Exception as exc:
        task = db.get(AnalysisTask, task_id)
        if task is not None:
            task.status = "failed"
            task.error_message = str(exc)
            task.finished_at = _utcnow()
            db.commit()
        raise
    finally:
        db.close()
