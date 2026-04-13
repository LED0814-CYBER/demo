"""LibHunter / PHunter 工具调用：统一日志、工作目录与 subprocess 行为。"""
from __future__ import annotations

import hashlib
import os
import json
import re
import shlex
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional

from config import (
    BASE_DIR,
    CVE_KB_PATH,
    DEFAULT_LIBHUNTER_TIMEOUT,
    DEFAULT_PHUNTER_THREADS,
    DEFAULT_PHUNTER_TIMEOUT,
    ANDROID_JAR,
    JAVA_BIN,
    LIBHUNTER_DIR,
    LIBHUNTER_HEARTBEAT_TIMEOUT,    
    LIBHUNTER_PROCESSES,    
    LIBHUNTER_SCRIPT,
    LIBHUNTER_TPLS_DEX,
    LIBHUNTER_TPLS_JAR,
    LIB_SIMILAR_THRESHOLD,
    LOG_DIR,
    PHUNTER_DIR,
    PHUNTER_JAR,
    PICKLE_CACHE_DIR,
    PHUNTER_HEARTBEAT_TIMEOUT,  
    PHUNTER_PREWARM_TIMEOUT,
    PHUNTER_PREWARM_SOURCE_DEFAULT,
    PHUNTER_CACHE_DIR,
    PHUNTER_CACHE_MODE,
    PYTHON_BIN,
    RAW_DIR,
    SUBPROCESS_HEARTBEAT_TIMEOUT,
    build_pythonpath,
)
from utils.normalizer import normalize_libhunter_lib
from utils.runner import CommandResult, run_command

_DETECTION_PATTERN = re.compile(
    r"lib:\s*(?P<lib>[^\r\n]+)\s+similarity:\s*(?P<similarity>[0-9.]+)",
    re.IGNORECASE | re.MULTILINE,
)
_PATCH_METHODS_PATTERN = re.compile(
    r"patch-related\s+method\s+count\s*=\s*(\d+)",
    re.IGNORECASE,
)
_PRE_SIMILARITY_PATTERN = re.compile(
    r"pre\s+similarity\s*=\s*([0-9.]+)",
    re.IGNORECASE,
)
_POST_SIMILARITY_PATTERN = re.compile(
    r"post\s+similarity\s*=\s*([0-9.]+)",
    re.IGNORECASE,
)
_PHUNTER_RESOURCE_LIMIT_PATTERN = re.compile(
    r"(pthread_create\s+failed|unable\s+to\s+create\s+native\s+thread|EAGAIN|process/resource\s+limits\s+reached)",
    re.IGNORECASE,
)   
_PHUNTER_FATAL_PATTERN = re.compile(
    r"(failed\s+to\s+parse\s+command-line\s+arguments|the\s+analysis\s+has\s+failed)",
    re.IGNORECASE,
)
_LIBHUNTER_NOISY_TERMINAL_PATTERNS = (
    re.compile(r"Multiple exit nodes found !", re.IGNORECASE),
    re.compile(r"Unknown instruction\s*:\s*.+invalid_instruction", re.IGNORECASE),
    re.compile(r"Error loading/building lib .*unpack requires a buffer of 4 bytes", re.IGNORECASE),
)
_STAGE_TOKEN_PATTERN = re.compile(r"(^|[^a-z0-9])(pre|post)([^a-z0-9]|$)", re.IGNORECASE)

TPL_CVES_ROOT = BASE_DIR / "TPL-CVEs"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content or "", encoding="utf-8")


def _has_phunter_fatal(text: str) -> bool:
    return bool(_PHUNTER_FATAL_PATTERN.search(text or ""))


def _normalize_prewarm_source(source: str | None) -> str:
    text = (source or PHUNTER_PREWARM_SOURCE_DEFAULT or "cve_kb").strip().lower()
    if text in {"tpl_cves", "tpl-cves", "tpl"}:
        return "tpl_cves"
    return "cve_kb"


def _classify_stage(binary_path: Path) -> str | None:
    stem = binary_path.stem.lower()
    match = _STAGE_TOKEN_PATTERN.search(stem)
    if not match:
        return None
    stage = match.group(2).lower()
    if stage in {"pre", "post"}:
        return stage
    return None


def _pair_key(binary_path: Path) -> str | None:
    stem = binary_path.stem.lower()
    if not _STAGE_TOKEN_PATTERN.search(stem):
        return None

    def _replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}{{stage}}{match.group(3)}"

    normalized = _STAGE_TOKEN_PATTERN.sub(_replace, stem, count=1)
    return f"{binary_path.suffix.lower()}::{normalized}"


def _load_prewarm_targets_from_cve_kb() -> list[dict]:
    try:
        data = json.loads(CVE_KB_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

    targets: list[dict] = []
    for row in data if isinstance(data, list) else []:
        pre = row.get("pre_patch_jar")
        post = row.get("post_patch_jar")
        diff = row.get("patch_diff")
        if not pre or not post:
            continue
        pre_path = Path(pre)
        post_path = Path(post)
        diff_path = Path(diff) if diff else None
        if not pre_path.is_absolute():
            pre_path = (BASE_DIR / pre_path).resolve()
        else:
            pre_path = pre_path.expanduser().resolve()
        if not post_path.is_absolute():
            post_path = (BASE_DIR / post_path).resolve()
        else:
            post_path = post_path.expanduser().resolve()
        if diff_path is not None:
            if not diff_path.is_absolute():
                diff_path = (BASE_DIR / diff_path).resolve()
            else:
                diff_path = diff_path.expanduser().resolve()
        targets.append({
            "cve_id": str(row.get("cve_id", "")),
            "pre_patch_jar": str(pre_path),
            "post_patch_jar": str(post_path),
            "patch_diff": str(diff_path) if diff_path is not None else "",
        })
    return targets


def _load_prewarm_targets_from_tpl_cves(root: Path) -> list[dict]:
    if not root.exists():
        return []

    targets: list[dict] = []
    for cve_dir in root.rglob("*"):
        if not cve_dir.is_dir():
            continue
        diff_files = sorted(
            p for p in cve_dir.glob("*.diff")
            if ":zone.identifier" not in p.name.lower()
        )
        if not diff_files:
            continue
        binaries = sorted(
            p for p in cve_dir.iterdir()
            if p.is_file()
            and p.suffix.lower() in {".jar", ".aar"}
            and ":zone.identifier" not in p.name.lower()
        )
        if not binaries:
            continue
        grouped: dict[str, dict[str, list[Path]]] = {}
        for binary in binaries:
            stage = _classify_stage(binary)
            key = _pair_key(binary)
            if stage is None or key is None:
                continue
            grouped.setdefault(key, {"pre": [], "post": []})
            grouped[key][stage].append(binary)

        if not grouped:
            continue
        cve_id = cve_dir.name
        # 多 diff 时按文件名稳定取第一份，后续按命中 key 复用即可。
        patch_diff = diff_files[0]
        for group in grouped.values():
            if not group["pre"] or not group["post"]:
                continue
            for pre in group["pre"]:
                for post in group["post"]:
                    targets.append({
                        "cve_id": cve_id,
                        "pre_patch_jar": str(pre.resolve()),
                        "post_patch_jar": str(post.resolve()),
                        "patch_diff": str(patch_diff.resolve()),
                    })
    return targets


def _dedupe_prewarm_targets(targets: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for target in targets:
        key = (
            str(target.get("pre_patch_jar", "")).strip(),
            str(target.get("post_patch_jar", "")).strip(),
            str(target.get("patch_diff", "")).strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(target)
    return deduped


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_analysis_cache_ready(cache_root: Path, domain: str, source_file: Path) -> bool:
    domain_root = cache_root / domain
    candidates: list[Path] = []
    if source_file.exists() and source_file.is_file():
        candidates.append(source_file)
    # PHunter 会先把 .aar 转成同名 .jar 再做分析缓存；
    # 预热校验需兼容这一路径，避免把已成功任务误判为失败。
    if source_file.suffix.lower() == ".aar":
        jar_candidate = source_file.with_suffix(".jar")
        if jar_candidate.exists() and jar_candidate.is_file():
            candidates.append(jar_candidate)

    seen_hashes: set[str] = set()
    for candidate in candidates:
        file_hash = _sha256_file(candidate)
        if file_hash in seen_hashes:
            continue
        seen_hashes.add(file_hash)
        # 兼容新旧布局:
        # - 新布局: <domain>/soot_cache_hash/<hash>/
        # - 旧布局: <domain>/<hash>/
        candidate_entries = [
            domain_root / "soot_cache_hash" / file_hash,
            domain_root / file_hash,
        ]
        for entry in candidate_entries:
            if (entry / ".ready").exists() and (entry / "analyzer.bin").exists():
                return True
    return False


def run_logged_command(
    cmd: List[str],
    *,
    cwd: Optional[Path],
    timeout: Optional[int],
    env: Optional[Dict[str, str]] = None,
    stream_output: bool = True,
    heartbeat_timeout: int = SUBPROCESS_HEARTBEAT_TIMEOUT,
    memory_limit_bytes: int = 0,
    stdout_log: Path,
    stderr_log: Path,
    suppress_terminal_patterns: tuple[re.Pattern[str], ...] = (),
) -> CommandResult:

    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    stderr_log.parent.mkdir(parents=True, exist_ok=True)
    stdout_log.write_text("", encoding="utf-8")
    stderr_log.write_text("", encoding="utf-8")

    def _append(log_path: Path, line: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def _should_echo(line: str) -> bool:
        if not stream_output:
            return False
        return not any(p.search(line) for p in suppress_terminal_patterns)

    def _on_stdout(line: str) -> None:
        _append(stdout_log, line)
        if _should_echo(line):
            print(line, flush=True)

    def _on_stderr(line: str) -> None:
        _append(stderr_log, line)
        if _should_echo(line):
            print(line, flush=True)

    result = run_command(
        cmd,
        cwd=cwd,
        timeout=timeout,
        env=env,
        # Echo is handled in callbacks so we can filter noisy lines.
        stream_output=False,
        raise_on_error=False,
        on_stdout_line=_on_stdout,
        on_stderr_line=_on_stderr,
        heartbeat_timeout=heartbeat_timeout,
        memory_limit_bytes=memory_limit_bytes,
    )
    return result


def _parse_detection_text(text: str) -> list[dict]:
    detections: list[dict] = []
    for match in _DETECTION_PATTERN.finditer(text or ""):
        raw_lib = match.group("lib").strip()
        similarity = float(match.group("similarity"))
        normalized = normalize_libhunter_lib(raw_lib)
        detections.append({
            "raw_lib": raw_lib,
            "library_name": normalized["library_name"],
            "detected_version": normalized["version"],
            "similarity": similarity,
        })
    detections.sort(key=lambda item: item["similarity"], reverse=True)
    return detections


def _is_cache_valid(pkl_path: Path, source_dex: Path) -> bool:
    if not pkl_path.exists():
        return False
    try:
        return pkl_path.stat().st_mtime >= source_dex.stat().st_mtime
    # 如果 pkl 的修改时间 >= 源 dex 的修改时间，就认为缓存没过期。
    except OSError:
        return False

# 统计并清理缓存状态
def warm_up_cache(tpl_dex_dir: Path, cache_dir: Path) -> dict:
    cache_dir.mkdir(parents=True, exist_ok=True)
    dex_files = list(tpl_dex_dir.glob("*.dex"))
    total = len(dex_files)
    cached = missing = stale = 0

    for dex in dex_files:
        pkl = cache_dir / dex.with_suffix(".pkl").name
        if not pkl.exists():
            missing += 1
        elif not _is_cache_valid(pkl, dex):
            stale += 1
            pkl.unlink(missing_ok=True)
        else:
            cached += 1
    # 这个字典后面会被 run_libhunter() 使用
    return {"total": total, "cached": cached, "missing": missing, "stale": stale}

# 清空目录内容但保留目录本身(为LibHunter的预热工作做准备)
def ensure_clean_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def prewarm_tpl_pickles(*, env: Dict[str, str], timeout: int) -> CommandResult:
    run_root = RAW_DIR / "libhunter" / "_prewarm"
    apk_input_dir = run_root / "apks"
    output_dir = run_root / "outputs"
    ensure_clean_dir(apk_input_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(PYTHON_BIN),
        str(LIBHUNTER_SCRIPT),
        "detect_all",
        "-o", str(output_dir),
        "-af", str(apk_input_dir),  # 空目录：仅触发 TPL 指纹提取与 pickle 构建
        "-p", str(LIBHUNTER_PROCESSES), # 并行进程数
        "-ld", str(LIBHUNTER_TPLS_DEX),
    ]
    if LIBHUNTER_TPLS_JAR.exists():
        cmd.extend(["-lf", str(LIBHUNTER_TPLS_JAR)])
    return run_logged_command(
        cmd,
        cwd=LIBHUNTER_DIR,
        timeout=timeout,
        env=env,
        stream_output=False,
        # 预热阶段可能长时间无输出，不应按心跳静默误判卡死
        heartbeat_timeout=0,
        stdout_log=LOG_DIR / "libhunter_prewarm.stdout.log",
        stderr_log=LOG_DIR / "libhunter_prewarm.stderr.log",
    )


def run_libhunter(apk_path: str | Path) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()

    checks = {
        "APK 文件": apk_path,
        "LibHunter 入口脚本": LIBHUNTER_SCRIPT,
        "TPL dex 特征库 (-ld)": LIBHUNTER_TPLS_DEX,
    }
    not_found = [f"  {label}: {path}" for label, path in checks.items() if not path.exists()]
    if not_found:
        raise FileNotFoundError("以下路径不存在，请检查目录结构：\n" + "\n".join(not_found))
    if not LIBHUNTER_TPLS_JAR.exists():
        print(
            f"[libhunter] 提示: 未找到 tpl_jar 目录 ({LIBHUNTER_TPLS_JAR})，"
            "将仅使用 tpl_dex 执行检测。"
        )

    env = os.environ.copy()
    env["PYTHONPATH"] = build_pythonpath()
    env["LH_PICKLE_DIR"] = str(PICKLE_CACHE_DIR)
    env["LH_LIB_THRESHOLD"] = str(LIB_SIMILAR_THRESHOLD)
    env.setdefault("LH_EXEC_MODE", "mp")
    # 限制每个进程内的 BLAS/OMP 线程，避免多进程场景下线程数爆炸。
    # 把各种常见数值计算库线程数都限制成 1，比如 NumPy/OpenBLAS/MKL
    env.setdefault("OMP_NUM_THREADS", "1")
    env.setdefault("OPENBLAS_NUM_THREADS", "1")
    env.setdefault("MKL_NUM_THREADS", "1")
    env.setdefault("NUMEXPR_NUM_THREADS", "1")
    env.setdefault("VECLIB_MAXIMUM_THREADS", "1")
    env.setdefault("BLIS_NUM_THREADS", "1")

    cache_stats = warm_up_cache(LIBHUNTER_TPLS_DEX, PICKLE_CACHE_DIR)
    if cache_stats["total"] == 0:
        print("[libhunter] 警告: tpl_dex 目录为空，无法检测任何库。")
    else:
        miss = cache_stats["missing"] + cache_stats["stale"]
        if miss > 0:
            print(
                f"[libhunter] 缓存预热: {cache_stats['cached']}/{cache_stats['total']} 命中, "
                f"{miss} 个 pkl 需要构建，开始执行预热 ..."
            )
            try:
                prewarm_timeout = max(DEFAULT_LIBHUNTER_TIMEOUT, 2 * 60 * 60)
                prewarm_start = time.time()
                prewarm_result = prewarm_tpl_pickles(env=env, timeout=prewarm_timeout)
                elapsed = time.time() - prewarm_start
                cache_stats = warm_up_cache(LIBHUNTER_TPLS_DEX, PICKLE_CACHE_DIR)
                remain = cache_stats["missing"] + cache_stats["stale"]
                if prewarm_result.returncode == 0 and remain == 0:
                    print(
                        f"[libhunter] 预热完成: 全部 {cache_stats['total']} 个 pkl 就绪 "
                        f"(耗时 {elapsed:.1f}s)。"
                    )
                elif prewarm_result.returncode == 0:
                    print(
                        f"[libhunter] 预热部分完成: 剩余 {remain} 个 pkl 未就绪，"
                        "将在本轮检测中按需构建。"
                    )
                else:
                    print(
                        f"[libhunter] 预热子任务退出码={prewarm_result.returncode}，"
                        "将继续执行检测并按需构建缓存。"
                    )
            except Exception as exc:
                print(
                    f"[libhunter] 预热失败: {exc}，将继续执行检测并按需构建缓存。"
                )
        else:
            print(
                f"[libhunter] 缓存预热: 全部 {cache_stats['total']} 个 pkl 命中，"
                f"跳过反编译阶段。"
            )

    run_root = RAW_DIR / "libhunter" / apk_path.stem
    apk_input_dir = run_root / "apks"
    output_dir = run_root / "outputs"
    apk_input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(apk_path, apk_input_dir / apk_path.name)

    cmd = [
        str(PYTHON_BIN),
        str(LIBHUNTER_SCRIPT),
        "detect_all",
        "-o", str(output_dir),
        "-af", str(apk_input_dir),
        "-p", str(LIBHUNTER_PROCESSES),
        "-ld", str(LIBHUNTER_TPLS_DEX),
    ]
    if LIBHUNTER_TPLS_JAR.exists():
        cmd.extend(["-lf", str(LIBHUNTER_TPLS_JAR)])

    result = run_logged_command(
        cmd,
        cwd=LIBHUNTER_DIR,
        timeout=DEFAULT_LIBHUNTER_TIMEOUT,
        env=env,
        stream_output=True,
        heartbeat_timeout=LIBHUNTER_HEARTBEAT_TIMEOUT,
        stdout_log=LOG_DIR / f"libhunter_{apk_path.stem}.stdout.log",
        stderr_log=LOG_DIR / f"libhunter_{apk_path.stem}.stderr.log",
        suppress_terminal_patterns=_LIBHUNTER_NOISY_TERMINAL_PATTERNS,
    )

    # 如果命令“卡死”
    if result.hung:
        return {
            "status": "hung",
            "cmd": result.cmd,
            "returncode": result.returncode,
            "raw_stdout": result.stdout,
            "raw_stderr": result.stderr,
            "result_file": None,
            "detections": [],
        }

    result_file = next(
        (f for f in (
            output_dir / f"{apk_path.name}.txt",
            output_dir / f"{apk_path.stem}.txt",
        ) if f.exists()),
        output_dir / f"{apk_path.name}.txt",
    )

    if result_file.exists():
        parsed_source = result_file.read_text(encoding="utf-8", errors="replace")
    else:
        parsed_source = "\n".join(p for p in (result.stdout, result.stderr) if p)

    detections = _parse_detection_text(parsed_source)

    if result.returncode != 0:
        status = "failed"
    elif not detections:
        status = "no_detections"
    else:
        status = "success"

    return {
        "status": status,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
        "result_file": str(result_file) if result_file.exists() else None,
        "detections": detections,
    }


def _extract_float(pattern: re.Pattern[str], text: str) -> float | None:
    match = pattern.search(text)
    return float(match.group(1)) if match else None


def _extract_int(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    return int(match.group(1)) if match else None


def _parse_patch_status(text: str) -> str:
    upper_text = text.upper()
    if "THE PATCH IS NOT PRESENT" in upper_text:
        return "PATCH_NOT_PRESENT"
    if "THE PATCH IS PRESENT" in upper_text:
        return "PATCH_PRESENT"
    return "UNKNOWN"


def _is_phunter_resource_limit(text: str) -> bool:
    return bool(_PHUNTER_RESOURCE_LIMIT_PATTERN.search(text or ""))


def build_phunter_cmd(
    *,
    apk_path: Path | None = None,
    pre_patch_jar: Path | None = None,
    post_patch_jar: Path | None = None,
    patch_diff: Path | None = None,
    thread_num: int | None = None,
    java_opts: list[str] | None = None,
    cache_dir: Path | None = None,
    cache_mode: str | None = None,
    prewarm_tpl_only: bool = False,
    prewarm_apk_only: bool = False,
) -> list[str]:
    cmd = [str(JAVA_BIN)]
    if java_opts:
        cmd.extend(java_opts)
    cmd.extend(["-jar", str(PHUNTER_JAR)])
    if pre_patch_jar is not None:
        cmd.extend(["--preTPL", str(pre_patch_jar)])
    if post_patch_jar is not None:
        cmd.extend(["--postTPL", str(post_patch_jar)])
    if thread_num is not None:
        cmd.extend(["--threadNum", str(thread_num)])
    cmd.extend(["--androidJar", str(ANDROID_JAR)])
    if patch_diff is not None:
        cmd.extend(["--patchFiles", str(patch_diff)])
    if apk_path is not None:
        cmd.extend(["--targetAPK", str(apk_path)])
    if cache_dir is not None:
        cmd.extend(["--cacheDir", str(cache_dir)])
    if cache_mode:
        cmd.extend(["--cacheMode", str(cache_mode)])
    if prewarm_tpl_only:
        cmd.append("--prewarmOnly")
    if prewarm_apk_only:
        cmd.append("--prewarmAPKOnly")
    return cmd


def prewarm_phunter_templates(source: str | None = None) -> dict:
    source_norm = _normalize_prewarm_source(source)
    if source_norm == "tpl_cves":
        targets = _load_prewarm_targets_from_tpl_cves(TPL_CVES_ROOT)
    else:
        targets = _load_prewarm_targets_from_cve_kb()
    targets = _dedupe_prewarm_targets(targets)

    summary = {
        "source": source_norm,
        "total": len(targets),
        "success": 0,
        "failed": 0,
        "skipped": 0,
        "fallback_used": 0,
    }
    if not targets:
        return summary

    print(f"[phunter] 模板预热源: {source_norm}, 待处理: {len(targets)}")
    for idx, target in enumerate(targets, start=1):
        pre = Path(target["pre_patch_jar"]).expanduser().resolve()
        post = Path(target["post_patch_jar"]).expanduser().resolve()
        if not pre.exists() or not post.exists():
            summary["skipped"] += 1
            continue

        # 先走上层 analysis 缓存路径；仅当其失败时才回退到下层 Soot 缓存路径。
        cmd = build_phunter_cmd(
            pre_patch_jar=pre,
            post_patch_jar=post,
            cache_dir=PHUNTER_CACHE_DIR,
            cache_mode=PHUNTER_CACHE_MODE,
            prewarm_tpl_only=True,
        )
        cve_id = target.get("cve_id") or f"item-{idx}"
        log_tag = f"phunter_prewarm_tpl_{idx:04d}_{cve_id}"
        upper_env = dict(os.environ)
        upper_env["PHUNTER_ANALYSIS_CACHE_ONLY"] = "1"
        result = run_logged_command(
            cmd,
            cwd=PHUNTER_DIR,
            timeout=PHUNTER_PREWARM_TIMEOUT,
            env=upper_env,
            stream_output=True,
            heartbeat_timeout=0,
            stdout_log=LOG_DIR / f"{log_tag}.stdout.log",
            stderr_log=LOG_DIR / f"{log_tag}.stderr.log",
        )
        combined = "\n".join(p for p in (result.stdout, result.stderr) if p)
        upper_ready = (
            _is_analysis_cache_ready(PHUNTER_CACHE_DIR, "binary_analysis", pre)
            and _is_analysis_cache_ready(PHUNTER_CACHE_DIR, "binary_analysis", post)
        )
        upper_ok = result.returncode == 0 and not _has_phunter_fatal(combined) and upper_ready

        if upper_ok:
            summary["success"] += 1
            continue

        summary["fallback_used"] += 1
        print(f"[phunter] 上层缓存预热失败，回退下层链路: {cve_id} (rc={result.returncode})")

        fallback_cmd = build_phunter_cmd(
            pre_patch_jar=pre,
            post_patch_jar=post,
            cache_dir=PHUNTER_CACHE_DIR,
            cache_mode=PHUNTER_CACHE_MODE,
            prewarm_tpl_only=True,
        )
        fallback_env = dict(os.environ)
        fallback_env.pop("PHUNTER_ANALYSIS_CACHE_ONLY", None)
        fallback_result = run_logged_command(
            fallback_cmd,
            cwd=PHUNTER_DIR,
            timeout=PHUNTER_PREWARM_TIMEOUT,
            env=fallback_env,
            stream_output=True,
            heartbeat_timeout=0,
            stdout_log=LOG_DIR / f"{log_tag}.fallback.stdout.log",
            stderr_log=LOG_DIR / f"{log_tag}.fallback.stderr.log",
        )
        fallback_combined = "\n".join(p for p in (fallback_result.stdout, fallback_result.stderr) if p)
        fallback_ready = (
            _is_analysis_cache_ready(PHUNTER_CACHE_DIR, "binary_analysis", pre)
            and _is_analysis_cache_ready(PHUNTER_CACHE_DIR, "binary_analysis", post)
        )
        if fallback_result.returncode == 0 and not _has_phunter_fatal(fallback_combined) and fallback_ready:
            summary["success"] += 1
        else:
            summary["failed"] += 1
            print(f"[phunter] 预热失败 {cve_id} (rc={fallback_result.returncode})")
    return summary


def prewarm_phunter_apk_cache(apk_path: str | Path) -> dict:
    apk = Path(apk_path).expanduser().resolve()
    if not apk.exists():
        return {"status": "skipped", "reason": f"APK not found: {apk}"}

    cmd = build_phunter_cmd(
        apk_path=apk,
        cache_dir=PHUNTER_CACHE_DIR,
        cache_mode=PHUNTER_CACHE_MODE,
        prewarm_apk_only=True,
    )
    result = run_logged_command(
        cmd,
        cwd=PHUNTER_DIR,
        timeout=PHUNTER_PREWARM_TIMEOUT,
        env=None,
        stream_output=True,
        heartbeat_timeout=0,
        stdout_log=LOG_DIR / f"phunter_prewarm_apk_{apk.stem}.stdout.log",
        stderr_log=LOG_DIR / f"phunter_prewarm_apk_{apk.stem}.stderr.log",
    )
    combined = "\n".join(p for p in (result.stdout, result.stderr) if p)
    if result.returncode == 0 and not _has_phunter_fatal(combined):
        return {"status": "success", "returncode": 0}
    return {"status": "failed", "returncode": result.returncode, "stderr": result.stderr}


def run_phunter(apk_path: str | Path, cve_meta: dict) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()
    pre_patch_jar = Path(cve_meta["pre_patch_jar"]).expanduser().resolve()
    post_patch_jar = Path(cve_meta["post_patch_jar"]).expanduser().resolve()
    patch_diff = Path(cve_meta["patch_diff"]).expanduser().resolve()

    missing_paths = [
        str(path)
        for path in (apk_path, PHUNTER_JAR, ANDROID_JAR,
                      pre_patch_jar, post_patch_jar, patch_diff)
        if not path.exists()
    ]
    if missing_paths:
        raise FileNotFoundError("Missing PHunter input files: " + ", ".join(missing_paths))

    cve_id = cve_meta["cve_id"]
    thread_num = int(cve_meta.get("thread_num", DEFAULT_PHUNTER_THREADS))
    java_opts = shlex.split(os.getenv("PHUNTER_JAVA_OPTS", ""))

    cmd = build_phunter_cmd(
        apk_path=apk_path,
        pre_patch_jar=pre_patch_jar,
        post_patch_jar=post_patch_jar,
        patch_diff=patch_diff,
        thread_num=thread_num,
        java_opts=java_opts,
        cache_dir=PHUNTER_CACHE_DIR,
        cache_mode=PHUNTER_CACHE_MODE,
    )

    result = run_logged_command(
        cmd,
        cwd=PHUNTER_DIR,
        timeout=DEFAULT_PHUNTER_TIMEOUT,
        env=None,
        stream_output=True,
        heartbeat_timeout=PHUNTER_HEARTBEAT_TIMEOUT,
        stdout_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stdout.log",
        stderr_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stderr.log",
    )

    # 如果 PHunter 卡死
    if result.hung:
        return {
            "status": "hung",
            "hung": True,
            "cve_id": cve_id,
            "cmd": result.cmd,
            "returncode": result.returncode,
            "patch_status": "HUNG",
            "patch_related_method_count": None,
            "pre_similarity": None,
            "post_similarity": None,
            "raw_stdout": result.stdout,
            "raw_stderr": result.stderr,
        }

    combined = "\n".join(p for p in (result.stdout, result.stderr) if p)
    retried = False
    # 资源不足时触发重试
    if result.returncode != 0 and _is_phunter_resource_limit(combined):
        retried = True
        # 降低线程数
        retry_thread_num = max(1, min(thread_num, 2))
        # 读取重试专用 JVM 参数
        retry_java_opts_raw = os.getenv(
            "PHUNTER_JAVA_RETRY_OPTS",  
            "-Xss256k -XX:ActiveProcessorCount=2", # -Xss256k：减小线程栈大小
            # -XX:ActiveProcessorCount=2：告诉 JVM 活跃处理器数按 2 处理
        )
        retry_java_opts = shlex.split(retry_java_opts_raw)
        retry_cmd = build_phunter_cmd(
            apk_path=apk_path,
            pre_patch_jar=pre_patch_jar,
            post_patch_jar=post_patch_jar,
            patch_diff=patch_diff,
            thread_num=retry_thread_num,
            java_opts=retry_java_opts,
            cache_dir=PHUNTER_CACHE_DIR,
            cache_mode=PHUNTER_CACHE_MODE,
        )
        retry_result = run_logged_command(
            retry_cmd,
            cwd=PHUNTER_DIR,
            timeout=DEFAULT_PHUNTER_TIMEOUT,
            env=None,
            stream_output=True,
            heartbeat_timeout=PHUNTER_HEARTBEAT_TIMEOUT,
            stdout_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.retry.stdout.log",
            stderr_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.retry.stderr.log",
        )
        # 如果重试后又卡死了
        if retry_result.hung:
            return {
                "status": "hung",
                "hung": True,
                "cve_id": cve_id,
                "cmd": retry_result.cmd,
                "returncode": retry_result.returncode,
                "patch_status": "HUNG",
                "patch_related_method_count": None,
                "pre_similarity": None,
                "post_similarity": None,
                "raw_stdout": retry_result.stdout,
                "raw_stderr": retry_result.stderr,
                "retried": True,
            }
        result = retry_result
        combined = "\n".join(p for p in (result.stdout, result.stderr) if p)

    patch_status = _parse_patch_status(combined)
    patch_related_method_count = _extract_int(_PATCH_METHODS_PATTERN, combined)
    pre_similarity = _extract_float(_PRE_SIMILARITY_PATTERN, combined)
    post_similarity = _extract_float(_POST_SIMILARITY_PATTERN, combined)

    if result.returncode == 0 and _has_phunter_fatal(combined):
        status = "failed"
        patch_status = "UNKNOWN"
    elif result.returncode == 0:
        status = "success"
    elif _is_phunter_resource_limit(combined):
        status = "resource_limited"
        patch_status = "RESOURCE_LIMIT"
    else:
        status = "failed"

    return {
        "status": status,
        "hung": False,
        "cve_id": cve_id,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "patch_status": patch_status,
        "patch_related_method_count": patch_related_method_count,
        "pre_similarity": pre_similarity,
        "post_similarity": post_similarity,
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
        "retried": retried,
    }
