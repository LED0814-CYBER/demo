import argparse
import json
import logging
import os
import pickle
import time
from statistics import mean

from apk import Apk
from coarse_filter import CoarseFilterConfig, CoarseFilterEngine, build_lib_groups
from lib import ThirdLib


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("coarse_benchmark")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


def _default_pickle_dir() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "data", "coarse_index", "benchmark_pickle")


def _load_or_build_lib_obj(lib_dex_folder: str, rel_path: str, logger: logging.Logger, pickle_dir: str):
    os.makedirs(pickle_dir, exist_ok=True)
    flat_name = rel_path.replace("/", "_").replace("\\", "_")
    pickle_path = os.path.join(pickle_dir, flat_name).replace(".dex", ".pkl")
    try:
        if os.path.exists(pickle_path):
            with open(pickle_path, "rb") as f:
                return pickle.load(f)
        lib_obj = ThirdLib(os.path.join(lib_dex_folder, rel_path), logger)
        with open(pickle_path, "wb") as f:
            pickle.dump(lib_obj, f, protocol=pickle.HIGHEST_PROTOCOL)
        return lib_obj
    except Exception as e:
        logger.warning("load lib failed %s: %s", rel_path, e)
        return None


def _load_or_build_apk_obj(apk_path: str, logger: logging.Logger, pickle_dir: str):
    os.makedirs(pickle_dir, exist_ok=True)
    apk_name = os.path.basename(apk_path)
    pickle_path = os.path.join(pickle_dir, apk_name).replace(".apk", ".pkl")
    try:
        if os.path.exists(pickle_path):
            with open(pickle_path, "rb") as f:
                return pickle.load(f)
        apk_obj = Apk(apk_path, logger)
        with open(pickle_path, "wb") as f:
            pickle.dump(apk_obj, f, protocol=pickle.HIGHEST_PROTOCOL)
        return apk_obj
    except Exception as e:
        logger.warning("load apk failed %s: %s", apk_path, e)
        return None


def main():
    parser = argparse.ArgumentParser(description="LibHunter coarse-filter benchmark")
    parser.add_argument("--lib-dex-folder", required=True)
    parser.add_argument("--apk-folder", required=True)
    parser.add_argument("--ground-truth", default="", help="JSON: {apk_name: [family,...]}")
    parser.add_argument("--sample-limit", type=int, default=0)
    parser.add_argument("--pickle-dir", default=os.environ.get("LH_PICKLE_DIR", _default_pickle_dir()))
    args = parser.parse_args()

    logger = _setup_logger()

    lib_dex_folder = os.path.abspath(args.lib_dex_folder)
    apk_folder = os.path.abspath(args.apk_folder)

    lib_groups = build_lib_groups(lib_dex_folder)
    config = CoarseFilterConfig.from_env()

    engine = CoarseFilterEngine(
        lib_dex_folder=lib_dex_folder,
        load_lib_obj=lambda rel_path: _load_or_build_lib_obj(lib_dex_folder, rel_path, logger, args.pickle_dir),
        logger=logger,
        config=config,
    )

    index_stats = engine.ensure_index(lib_groups)
    logger.info(
        "coarse index ready: total=%d reused=%d rebuilt=%d elapsed=%dms",
        index_stats.get("total_families", 0),
        index_stats.get("reused_families", 0),
        index_stats.get("rebuilt_families", 0),
        index_stats.get("elapsed_ms", 0),
    )

    gt = {}
    if args.ground_truth:
        with open(args.ground_truth, "r", encoding="utf-8") as f:
            gt = json.load(f)

    apks = [f for f in os.listdir(apk_folder) if f.endswith(".apk")]
    apks.sort()
    if args.sample_limit > 0:
        apks = apks[: args.sample_limit]

    prune_ratios = []
    recalls = []
    elapsed_ms = []

    for apk_name in apks:
        apk_path = os.path.join(apk_folder, apk_name)
        apk_obj = _load_or_build_apk_obj(apk_path, logger, args.pickle_dir)
        if apk_obj is None:
            continue

        t0 = time.perf_counter()
        candidates, metrics = engine.select_candidate_groups(apk_obj, lib_groups)
        dt_ms = int((time.perf_counter() - t0) * 1000)

        prune_ratios.append(metrics["coarse_prune_ratio"])
        elapsed_ms.append(dt_ms)

        recall_value = None
        expected = set(gt.get(apk_name, [])) if gt else set()
        if expected:
            hit = len(expected & set(candidates))
            recall_value = hit / float(len(expected))
            recalls.append(recall_value)

        logger.info(
            "%s: groups=%d candidates=%d prune=%.2f%% elapsed=%dms recall=%s",
            apk_name,
            metrics["coarse_total_groups"],
            metrics["coarse_candidate_groups"],
            metrics["coarse_prune_ratio"] * 100.0,
            dt_ms,
            "N/A" if recall_value is None else f"{recall_value * 100.0:.2f}%",
        )

    avg_prune = mean(prune_ratios) if prune_ratios else 0.0
    avg_recall = mean(recalls) if recalls else None
    avg_elapsed = mean(elapsed_ms) if elapsed_ms else 0.0

    print("=== Coarse Benchmark Summary ===")
    print(f"apk_count={len(prune_ratios)}")
    print(f"avg_prune_ratio={avg_prune:.4f} ({avg_prune * 100.0:.2f}%)")
    if avg_recall is None:
        print("avg_recall=N/A (provide --ground-truth to compute recall)")
    else:
        print(f"avg_recall={avg_recall:.4f} ({avg_recall * 100.0:.2f}%)")
    print(f"avg_elapsed_ms={avg_elapsed:.2f}")


if __name__ == "__main__":
    main()
