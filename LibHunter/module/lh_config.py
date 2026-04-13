import logging
import logging.handlers
import multiprocessing
import os
import os.path
from pathlib import Path

# ── 运行参数 ──────────────────────────────────────────────────
# Default to half of system CPUs (env override still supported).
_CPU_COUNT = multiprocessing.cpu_count() or 1
max_thread_num = int(os.environ.get("LH_MAX_THREAD_NUM", str(max(1, _CPU_COUNT // 2))))

# ── pickle 缓存目录[预热] ──
pickle_dir = os.environ.get("LH_PICKLE_DIR", "").strip()
if not pickle_dir:
    raise RuntimeError("LH_PICKLE_DIR is required but not set.")

os.makedirs(pickle_dir, exist_ok=True)

# 检测模式
detect_type = "lib_version"

class_similar  = 1
method_similar = 0.75
lib_similar    = float(os.environ.get("LH_LIB_THRESHOLD", "0.85"))  # 不再硬编码 0.1

log_file = "log.txt"


def clear_log():
    if os.path.exists(log_file):
        os.remove(log_file)


def setup_logger():
    logger = logging.getLogger()
    if not logger.handlers:
        if multiprocessing.current_process().name == "MainProcess":
            logger.setLevel(logging.INFO)
            fh = logging.FileHandler(log_file, 'a', encoding='utf-8')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - [%(lineno)d] - %(message)s'
            )
            fh.setFormatter(formatter)
            logger.addHandler(fh)
    return logger


def listener_process(queue):
    logger = logging.getLogger()
    fh = logging.FileHandler(log_file, 'a', encoding='utf-8')
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(lineno)d] - %(message)s'
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)

    while True:
        record = queue.get()
        if record is None:
            break
        logger.handle(record)

    logger.removeHandler(fh)
    fh.close()


def worker_init(queue):
    h = logging.handlers.QueueHandler(queue)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(h)
    root.setLevel(logging.INFO)
