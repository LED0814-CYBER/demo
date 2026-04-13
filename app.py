from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db import SessionLocal, get_db, init_db
from backend.models import AnalysisTask, User, VulnerabilityReport
from backend.settings import settings
from backend.tasks import run_analysis_task
from config import ensure_runtime_dirs


class AnalyzeRequest(BaseModel):
    filename: Optional[str] = None
    user_id: Optional[str] = None


class AnalyzeTaskCreateRequest(BaseModel):
    filename: str
    user_id: Optional[str] = None


app = FastAPI(title="APK Vulnerability Scanner API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_frontend_dist = Path(__file__).resolve().parent / "frontend" / "dist"


@app.on_event("startup")
def startup_event() -> None:
    ensure_runtime_dirs()
    settings.ensure_runtime_dirs()
    init_db()


def _sanitize_filename(filename: str) -> str:
    cleaned = Path(filename or "").name
    if not cleaned:
        raise HTTPException(status_code=400, detail="Empty filename")
    return cleaned


def _resolve_apk_path(filename: str) -> Path:
    safe_name = _sanitize_filename(filename)
    apk_path = (settings.upload_dir / safe_name).resolve()
    if apk_path.parent != settings.upload_dir.resolve():
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not apk_path.exists() or not apk_path.is_file():
        raise HTTPException(status_code=404, detail=f"APK not found: {safe_name}")
    return apk_path


def _serialize_task(task: AnalysisTask) -> dict:
    return {
        "task_id": task.id,
        "apk_name": task.apk_name,
        "apk_path": task.apk_path,
        "status": task.status,
        "celery_task_id": task.celery_task_id,
        "report_path": task.report_path,
        "stdout_log_path": task.stdout_log_path,
        "stderr_log_path": task.stderr_log_path,
        "error": task.error_message,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "finished_at": task.finished_at.isoformat() if task.finished_at else None,
    }


def _get_or_create_default_user(db: Session) -> User:
    user = db.scalar(select(User).where(User.username == "default"))
    if user is not None:
        return user
    user = User(username="default")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _enqueue_analysis(db: Session, apk_path: Path, user_id: str | None) -> AnalysisTask:
    if user_id:
        user = db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail=f"User not found: {user_id}")
    else:
        user = _get_or_create_default_user(db)

    task = AnalysisTask(
        user_id=user.id,
        apk_name=apk_path.name,
        apk_path=str(apk_path),
        status="queued",
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    try:
        async_result = run_analysis_task.delay(task.id, str(apk_path))
    except Exception as exc:
        task.status = "failed"
        task.error_message = f"Failed to submit Celery task: {exc}"
        db.commit()
        db.refresh(task)
        return task

    task.celery_task_id = async_result.id
    db.commit()
    db.refresh(task)
    return task


def _latest_completed_task(db: Session) -> AnalysisTask | None:
    stmt = (
        select(AnalysisTask)
        .where(AnalysisTask.status == "completed")
        .order_by(AnalysisTask.finished_at.desc())
    )
    return db.scalars(stmt).first()


def _read_json_file(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Report not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Invalid report JSON: {exc}") from exc


def _candidate_log_files(task: AnalysisTask) -> list[Path]:
    candidates: list[Path] = []
    for path_text in (task.stdout_log_path, task.stderr_log_path):
        if not path_text:
            continue
        path = Path(path_text)
        if path.exists() and path.is_file():
            candidates.append(path)

    apk_stem = Path(task.apk_name).stem
    for path in settings.log_dir.glob(f"*{apk_stem}*.log"):
        if path.is_file():
            candidates.append(path)

    unique: dict[str, Path] = {str(path.resolve()): path for path in candidates}
    return sorted(unique.values(), key=lambda p: p.name)


@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "database_url": settings.database_url,
        "broker": settings.celery_broker_url,
        "storage_dir": str(settings.storage_dir),
    }


@app.post("/api/upload")
async def upload_apk(file: UploadFile = File(...)) -> dict:
    filename = _sanitize_filename(file.filename or "")
    if Path(filename).suffix.lower() != ".apk":
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    destination = (settings.upload_dir / filename).resolve()
    if destination.parent != settings.upload_dir.resolve():
        raise HTTPException(status_code=400, detail="Invalid upload path")

    with destination.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)

    await file.close()
    return {
        "message": "Upload successful",
        "filename": filename,
        "path": str(destination),
        "size": destination.stat().st_size,
    }


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest, db: Session = Depends(get_db)) -> dict:
    if not request.filename:
        raise HTTPException(status_code=400, detail="filename is required")
    apk_path = _resolve_apk_path(request.filename)
    task = _enqueue_analysis(db, apk_path, request.user_id)
    return {
        "message": "Analysis queued",
        "task": _serialize_task(task),
    }


@app.post("/api/tasks")
async def create_task_with_upload(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict:
    upload_result = await upload_apk(file)
    task = _enqueue_analysis(db, Path(upload_result["path"]), None)
    return {"task": _serialize_task(task)}


@app.post("/api/tasks/by-file")
def create_task_by_filename(request: AnalyzeTaskCreateRequest, db: Session = Depends(get_db)) -> dict:
    apk_path = _resolve_apk_path(request.filename)
    task = _enqueue_analysis(db, apk_path, request.user_id)
    return {"task": _serialize_task(task)}


@app.get("/api/task/{task_id}")
@app.get("/api/tasks/{task_id}")
def get_task(task_id: str, db: Session = Depends(get_db)) -> dict:
    task = db.get(AnalysisTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task": _serialize_task(task)}


@app.get("/api/tasks/{task_id}/report")
def get_task_report(task_id: str, db: Session = Depends(get_db)) -> dict:
    task = db.get(AnalysisTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status != "completed":
        raise HTTPException(status_code=409, detail=f"Task not completed, current status: {task.status}")

    report = task.report
    if report and report.report_json is not None:
        return {
            "task_id": task.id,
            "report_path": report.report_path,
            "report": report.report_json,
        }

    report_path = Path(task.report_path) if task.report_path else None
    if not report_path:
        raise HTTPException(status_code=404, detail="Report path missing")

    report_json = _read_json_file(report_path)
    return {
        "task_id": task.id,
        "report_path": str(report_path),
        "report": report_json,
    }


@app.get("/api/report")
def get_report(
    task_id: Optional[str] = None,
    apk_name: Optional[str] = None,
    db: Session = Depends(get_db),
) -> dict:
    selected_task: AnalysisTask | None = None
    report_path: Path | None = None

    if task_id:
        selected_task = db.get(AnalysisTask, task_id)
        if selected_task is None:
            raise HTTPException(status_code=404, detail="Task not found")
        if not selected_task.report_path:
            raise HTTPException(status_code=404, detail="Report not ready")
        report_path = Path(selected_task.report_path)
    elif apk_name:
        safe_name = _sanitize_filename(apk_name)
        report_path = settings.report_dir / f"{safe_name}_vuln_report.json"
    else:
        selected_task = _latest_completed_task(db)
        if selected_task and selected_task.report_path:
            report_path = Path(selected_task.report_path)

    if report_path is None:
        raise HTTPException(status_code=404, detail="Report file not found")

    report_json = _read_json_file(report_path)

    existing = None
    if selected_task is not None:
        existing = selected_task.report
        if existing is None:
            existing = VulnerabilityReport(
                task_id=selected_task.id,
                report_path=str(report_path),
                report_json=report_json,
            )
            db.add(existing)
        else:
            existing.report_path = str(report_path)
            existing.report_json = report_json
        db.commit()

    return {
        "task_id": selected_task.id if selected_task else None,
        "report_path": str(report_path),
        "report": existing.report_json if existing else report_json,
    }


@app.websocket("/api/logs")
async def websocket_logs(websocket: WebSocket, task_id: Optional[str] = None) -> None:
    await websocket.accept()

    if not task_id:
        await websocket.send_json({"type": "error", "message": "task_id is required"})
        await websocket.close(code=1008)
        return

    offsets: dict[str, int] = {}
    finished_idle_rounds = 0

    try:
        while True:
            with SessionLocal() as db:
                task = db.get(AnalysisTask, task_id)

            if task is None:
                await websocket.send_json({"type": "error", "message": f"Task not found: {task_id}"})
                await websocket.close(code=1008)
                return

            if not offsets:
                await websocket.send_json(
                    {
                        "type": "meta",
                        "task_id": task.id,
                        "apk_name": task.apk_name,
                        "status": task.status,
                    }
                )

            had_new_data = False
            for log_file in _candidate_log_files(task):
                key = str(log_file)
                prev = offsets.get(key, 0)
                try:
                    current_size = log_file.stat().st_size
                except OSError:
                    continue

                if current_size < prev:
                    prev = 0

                if current_size == prev:
                    continue

                with log_file.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(prev)
                    chunk = handle.read()
                    offsets[key] = handle.tell()

                if not chunk:
                    continue

                had_new_data = True
                for line in chunk.splitlines():
                    await websocket.send_json(
                        {
                            "type": "log",
                            "task_id": task.id,
                            "file": log_file.name,
                            "message": line,
                        }
                    )

            if task.status in {"completed", "failed"}:
                if had_new_data:
                    finished_idle_rounds = 0
                else:
                    finished_idle_rounds += 1
                if finished_idle_rounds >= 2:
                    await websocket.send_json(
                        {
                            "type": "done",
                            "task_id": task.id,
                            "status": task.status,
                            "error": task.error_message,
                            "report_path": task.report_path,
                        }
                    )
                    break

            await asyncio.sleep(0.8)
    except WebSocketDisconnect:
        return


if _frontend_dist.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=_frontend_dist / "assets"),
        name="frontend-assets",
    )


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    if full_path.startswith("api"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    if not _frontend_dist.exists():
        return JSONResponse(
            {"detail": "Frontend not built. Run `npm run build` in ./frontend first."},
            status_code=503,
        )

    target = (_frontend_dist / full_path).resolve()
    if full_path and target.exists() and target.is_file() and target.parent == _frontend_dist:
        return FileResponse(target)

    index_file = _frontend_dist / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse({"detail": "Frontend entrypoint not found."}, status_code=503)
