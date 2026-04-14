from __future__ import annotations

import hashlib
import logging
import math
import os
import pickle
import re
import time
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

import numpy as np
from datasketch import MinHash, MinHashLSH
from packaging.version import InvalidVersion, Version


DEFAULT_INDEX_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "coarse_index",
)
INDEX_FILENAME = "coarse_index.pkl"
INDEX_SCHEMA_VERSION = 5

MAX_HASH = int(np.iinfo(np.uint64).max)

TOKEN_RE = re.compile(r"[a-z0-9]{2,}")
_API_SEG_RE = re.compile(r"[a-z0-9_]+")

_STOPWORDS = {
    "a", "an", "and", "android", "app", "application", "array", "base", "builder", "by", "class",
    "com", "common", "core", "data", "default", "dex", "do", "for", "from", "get", "handler",
    "helper", "impl", "in", "init", "internal", "io", "is", "it", "java", "javax", "json", "lang",
    "lib", "main", "manager", "method", "model", "module", "net", "of", "on", "or", "org", "other",
    "package", "parse", "parser", "public", "set", "service", "static", "string", "support", "the",
    "this", "to", "true", "type", "util", "utils", "value", "version", "void", "with", "x",
}

_API_BLACKLIST_PREFIXES = (
    "java.lang.",
    "java.util.",
    "kotlin.",
    "kotlinx.",
    "androidx.",
    "android.support.",
)

_API_WHITELIST_PREFIXES = (
    "android.net.",
    "javax.crypto.",
    "android.hardware.",
    "android.telephony.",
    "android.media.",
    "java.net.",
    "javax.net.",
    "javax.security.",
    "okhttp3.",
    "retrofit2.",
)


@dataclass(frozen=True)
class CoarseFilterConfig:
    enabled: bool = True
    score_threshold: float = 0.12
    top_k: int = 60

    minhash_perm: int = 128
    lsh_bands: int = 32
    lsh_rows: int = 4
    fallback_on_empty: bool = True

    min_token_len: int = 3
    high_freq_ratio: float = 0.60
    high_freq_min_df: int = 12

    keep_ratio: float = 0.20
    max_keep_ratio: float = 0.90
    min_keep: int = 10
    rerank_keep_ratio: float = 0.20
    min_keep_ratio: float = 0.10

    target_prune_ratio: float = 0.80
    max_prune_ratio: float = 0.90

    robust_w_str: float = 0.50
    robust_w_api: float = 0.50
    robust_lowq_w_str: float = 0.10
    robust_lowq_w_api: float = 0.90
    robust_smooth: bool = False

    str_min_long_ratio: float = 0.25
    str_max_entropy_ratio: float = 0.55
    str_min_printable_ratio: float = 0.85
    str_entropy_threshold: float = 3.60

    @classmethod
    def from_env(cls) -> "CoarseFilterConfig":
        target_prune_ratio = _clamp_ratio(float(os.environ.get("LH_COARSE_TARGET_PRUNE_RATIO", "0.80")))
        max_prune_ratio = _clamp_ratio(float(os.environ.get("LH_COARSE_MAX_PRUNE_RATIO", "0.90")))
        if target_prune_ratio > max_prune_ratio:
            target_prune_ratio = max_prune_ratio

        keep_ratio = _clamp_ratio(float(os.environ.get("LH_COARSE_KEEP_RATIO", str(1.0 - target_prune_ratio))))
        max_keep_ratio = _clamp_ratio(float(os.environ.get("LH_COARSE_MAX_KEEP_RATIO", "0.90")))

        return cls(
            enabled=_env_bool("LH_COARSE_ENABLED", True),
            score_threshold=float(os.environ.get("LH_COARSE_SCORE_THRESHOLD", "0.12")),
            top_k=max(1, int(os.environ.get("LH_COARSE_TOP_K", "60"))),
            minhash_perm=max(16, int(os.environ.get("LH_COARSE_MINHASH_PERM", "128"))),
            lsh_bands=max(1, int(os.environ.get("LH_COARSE_LSH_BANDS", "32"))),
            lsh_rows=max(1, int(os.environ.get("LH_COARSE_LSH_ROWS", "4"))),
            fallback_on_empty=_env_bool("LH_COARSE_FALLBACK_ON_EMPTY", True),
            min_token_len=max(2, int(os.environ.get("LH_COARSE_MIN_TOKEN_LEN", "3"))),
            high_freq_ratio=_clamp_ratio(float(os.environ.get("LH_COARSE_API_DF_RATIO", "0.60"))),
            high_freq_min_df=max(2, int(os.environ.get("LH_COARSE_API_DF_MIN", "12"))),
            keep_ratio=keep_ratio,
            max_keep_ratio=max_keep_ratio,
            min_keep=max(1, int(os.environ.get("LH_COARSE_MIN_KEEP", "10"))),
            rerank_keep_ratio=_clamp_ratio(float(os.environ.get("LH_COARSE_RERANK_KEEP_RATIO", "0.20"))),
            min_keep_ratio=_clamp_ratio(float(os.environ.get("LH_COARSE_MIN_KEEP_RATIO", "0.10"))),
            target_prune_ratio=target_prune_ratio,
            max_prune_ratio=max_prune_ratio,
            robust_w_str=_clamp_ratio(float(os.environ.get("LH_COARSE_ROBUST_W_STR", "0.5"))),
            robust_w_api=_clamp_ratio(float(os.environ.get("LH_COARSE_ROBUST_W_API", "0.5"))),
            robust_lowq_w_str=_clamp_ratio(float(os.environ.get("LH_COARSE_ROBUST_LOWQ_W_STR", "0.1"))),
            robust_lowq_w_api=_clamp_ratio(float(os.environ.get("LH_COARSE_ROBUST_LOWQ_W_API", "0.9"))),
            robust_smooth=_env_bool("LH_COARSE_ROBUST_SMOOTH", False),
            str_min_long_ratio=_clamp_ratio(float(os.environ.get("LH_COARSE_STR_MIN_LONG_RATIO", "0.25"))),
            str_max_entropy_ratio=_clamp_ratio(float(os.environ.get("LH_COARSE_STR_MAX_ENTROPY_RATIO", "0.55"))),
            str_min_printable_ratio=_clamp_ratio(float(os.environ.get("LH_COARSE_STR_MIN_PRINTABLE_RATIO", "0.85"))),
            str_entropy_threshold=float(os.environ.get("LH_COARSE_STR_ENTROPY_THRESHOLD", "3.6")),
        )


class CoarseFilterEngine:
    def __init__(
        self,
        lib_dex_folder: str,
        load_lib_obj: Callable[[str], object],
        logger: Optional[logging.Logger] = None,
        config: Optional[CoarseFilterConfig] = None,
        index_dir: Optional[str] = None,
    ) -> None:
        self.lib_dex_folder = os.path.abspath(lib_dex_folder)
        self.load_lib_obj = load_lib_obj
        self.logger = logger or logging.getLogger(__name__)
        self.config = config or CoarseFilterConfig.from_env()
        self.index_dir = index_dir or DEFAULT_INDEX_DIR
        self.index_path = os.path.join(self.index_dir, INDEX_FILENAME)
        self._index_data: Optional[dict] = None

        self._lsh_str: Optional[MinHashLSH] = None
        self._lsh_api: Optional[MinHashLSH] = None

    def ensure_index(self, lib_groups: Dict[str, List[str]]) -> dict:
        os.makedirs(self.index_dir, exist_ok=True)
        started = time.perf_counter()
        index_data = self._safe_load_index()

        family_metas = self._build_family_metas(lib_groups)
        old_entries = index_data.get("family_entries", {}) if index_data else {}
        entries: Dict[str, dict] = {}

        reused = 0
        rebuilt = 0

        for family, meta in family_metas.items():
            old_entry = old_entries.get(family)
            if old_entry and old_entry.get("dex_meta") == meta["dex_meta"]:
                entries[family] = old_entry
                reused += 1
                continue
            entries[family] = self._build_family_entry(family, meta["versions"], meta["dex_meta"])
            rebuilt += 1

        high_df_api = self._compute_high_df_api(entries)

        for entry in entries.values():
            raw_str_tokens = set(entry.get("raw_str_tokens", []))
            raw_api_tokens = set(entry.get("raw_api_tokens", []))

            api_tokens = clean_api_features(
                raw_api_tokens,
                high_df_tokens=high_df_api,
                min_token_len=self.config.min_token_len,
            )

            entry["str_tokens"] = sorted(raw_str_tokens)
            entry["api_tokens"] = sorted(api_tokens)
            entry["sig_str"] = _tokens_to_signature(raw_str_tokens, self.config.minhash_perm)
            entry["sig_api"] = _tokens_to_signature(api_tokens, self.config.minhash_perm)

        self._index_data = {
            "schema": INDEX_SCHEMA_VERSION,
            "config": self._config_snapshot(),
            "lib_dex_folder": self.lib_dex_folder,
            "family_entries": entries,
            "high_freq_api": sorted(high_df_api),
            "updated_at_ms": int(time.time() * 1000),
        }
        self._save_index(self._index_data)
        self._rebuild_lsh_cache()

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "total_families": len(entries),
            "reused_families": reused,
            "rebuilt_families": rebuilt,
            "elapsed_ms": elapsed_ms,
        }
    def select_candidate_groups(self, apk_obj, lib_groups: Dict[str, List[str]]) -> Tuple[Set[str], dict]:
        started = time.perf_counter()
        if not self.config.enabled:
            all_groups = set(lib_groups.keys())
            return all_groups, {
                "coarse_total_groups": len(all_groups),
                "coarse_candidate_groups": len(all_groups),
                "coarse_prune_ratio": 0.0,
                "coarse_elapsed_ms": int((time.perf_counter() - started) * 1000),
                "fallback_triggered": False,
                "initial_candidates": len(all_groups),
                "rerank_keep_count": len(all_groups),
            }

        if self._index_data is None:
            self.ensure_index(lib_groups)
        if self._lsh_str is None or self._lsh_api is None:
            self._rebuild_lsh_cache()

        index_data = self._index_data or {}
        entries = index_data.get("family_entries", {})
        indexed_families = set(entries.keys())

        query = extract_apk_features(apk_obj, self.config.min_token_len)
        q_str_tokens = set(query.get("str_tokens", set()))
        q_api_tokens = set(query.get("api_tokens", set()))
        q_raw_strings = set(query.get("raw_strings", set()))

        q_api_tokens = clean_api_features(
            q_api_tokens,
            high_df_tokens=set(index_data.get("high_freq_api", [])),
            min_token_len=self.config.min_token_len,
        )

        q_sig_str = _tokens_to_signature(q_str_tokens, self.config.minhash_perm)
        q_sig_api = _tokens_to_signature(q_api_tokens, self.config.minhash_perm)

        q_str_quality, is_low_quality, q_str_details = check_string_quality(
            q_raw_strings,
            min_long_ratio=self.config.str_min_long_ratio,
            max_entropy_ratio=self.config.str_max_entropy_ratio,
            min_printable_ratio=self.config.str_min_printable_ratio,
            entropy_threshold=self.config.str_entropy_threshold,
        )

        q_mh_str = _signature_to_minhash(q_sig_str, self.config.minhash_perm)
        q_mh_api = _signature_to_minhash(q_sig_api, self.config.minhash_perm)
        initial = set(self._lsh_str.query(q_mh_str)) | set(self._lsh_api.query(q_mh_api))

        score_by_family: Dict[str, dict] = {}
        for family in initial:
            entry = entries.get(family)
            if not entry:
                continue
            score_by_family[family] = self._score_family(entry, q_sig_str, q_sig_api, is_low_quality)

        keep_count = self._compute_keep_count(len(lib_groups))

        ranked_initial = sorted(score_by_family.items(), key=lambda x: (-x[1]["robust"], x[0]))
        selected: Set[str] = {family for family, _ in ranked_initial[:keep_count]}

        if len(selected) < keep_count:
            for family, entry in entries.items():
                if family in score_by_family:
                    continue
                score_by_family[family] = self._score_family(entry, q_sig_str, q_sig_api, is_low_quality)
            ranked_all = sorted(score_by_family.items(), key=lambda x: (-x[1]["robust"], x[0]))
            selected = {family for family, _ in ranked_all[:keep_count]}

        selected |= (set(lib_groups.keys()) - indexed_families)

        fallback_triggered = False
        if not selected and self.config.fallback_on_empty:
            selected = set(lib_groups.keys())
            fallback_triggered = True

        candidate_count = len(selected)
        total_groups = len(lib_groups)
        prune_ratio = 0.0 if total_groups == 0 else 1.0 - (candidate_count / float(total_groups))
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        _, adaptive_meta = calculate_robust_score(
            {"j_str": 1.0, "j_api": 1.0},
            {},
            is_low_quality=is_low_quality,
            smooth=self.config.robust_smooth,
            base_weights=(self.config.robust_w_str, self.config.robust_w_api),
            low_quality_weights=(self.config.robust_lowq_w_str, self.config.robust_lowq_w_api),
        )

        metrics = {
            "coarse_total_groups": total_groups,
            "coarse_candidate_groups": candidate_count,
            "coarse_prune_ratio": prune_ratio,
            "coarse_elapsed_ms": elapsed_ms,
            "fallback_triggered": fallback_triggered,
            "initial_candidates": len(initial),
            "rerank_keep_count": keep_count,
            "api_tokens_before": int(query.get("api_tokens_before", 0)),
            "api_tokens_after": int(len(q_api_tokens)),
            "string_quality": {
                "q_str": q_str_quality,
                "is_low_quality": is_low_quality,
                **q_str_details,
            },
            "adaptive_weights": {
                "w_str": adaptive_meta.get("w_str", 0.0),
                "w_api": adaptive_meta.get("w_api", 0.0),
                "smooth": self.config.robust_smooth,
            },
        }
        return selected, metrics

    def _rebuild_lsh_cache(self) -> None:
        entries = (self._index_data or {}).get("family_entries", {})
        bands, rows = _effective_bands_rows(
            self.config.minhash_perm,
            self.config.lsh_bands,
            self.config.lsh_rows,
        )
        self._lsh_str = MinHashLSH(threshold=0.0, num_perm=self.config.minhash_perm, params=(bands, rows))
        self._lsh_api = MinHashLSH(threshold=0.0, num_perm=self.config.minhash_perm, params=(bands, rows))

        for family, entry in entries.items():
            self._lsh_str.insert(family, _signature_to_minhash(entry.get("sig_str", []), self.config.minhash_perm))
            self._lsh_api.insert(family, _signature_to_minhash(entry.get("sig_api", []), self.config.minhash_perm))

    def _compute_keep_count(self, total_groups: int) -> int:
        if total_groups <= 0:
            return 0
        keep_ratio = max(self.config.keep_ratio, self.config.rerank_keep_ratio)
        keep = max(self.config.min_keep, int(math.ceil(total_groups * keep_ratio)))
        keep = max(keep, int(math.ceil(total_groups * self.config.min_keep_ratio)))
        keep_upper = max(1, int(math.ceil(total_groups * self.config.max_keep_ratio)))
        return min(keep, keep_upper, total_groups)

    def _config_snapshot(self) -> dict:
        return {
            "minhash_perm": self.config.minhash_perm,
            "lsh_bands": self.config.lsh_bands,
            "lsh_rows": self.config.lsh_rows,
            "min_token_len": self.config.min_token_len,
            "high_freq_ratio": self.config.high_freq_ratio,
            "high_freq_min_df": self.config.high_freq_min_df,
            "keep_ratio": self.config.keep_ratio,
            "max_keep_ratio": self.config.max_keep_ratio,
            "min_keep": self.config.min_keep,
            "rerank_keep_ratio": self.config.rerank_keep_ratio,
            "min_keep_ratio": self.config.min_keep_ratio,
            "robust_w_str": self.config.robust_w_str,
            "robust_w_api": self.config.robust_w_api,
            "robust_lowq_w_str": self.config.robust_lowq_w_str,
            "robust_lowq_w_api": self.config.robust_lowq_w_api,
            "robust_smooth": self.config.robust_smooth,
        }

    def _score_family(self, entry: dict, q_sig_str: List[int], q_sig_api: List[int], is_low_quality: bool) -> dict:
        j_str = _sig_similarity(q_sig_str, entry.get("sig_str", []))
        j_api = _sig_similarity(q_sig_api, entry.get("sig_api", []))
        robust, robust_meta = calculate_robust_score(
            {"j_str": j_str, "j_api": j_api},
            {},
            is_low_quality=is_low_quality,
            smooth=self.config.robust_smooth,
            base_weights=(self.config.robust_w_str, self.config.robust_w_api),
            low_quality_weights=(self.config.robust_lowq_w_str, self.config.robust_lowq_w_api),
        )
        return {
            "robust": robust,
            "j_str": j_str,
            "j_api": j_api,
            "w_str": robust_meta.get("w_str", 0.5),
            "w_api": robust_meta.get("w_api", 0.5),
        }

    def _safe_load_index(self) -> Optional[dict]:
        if not os.path.exists(self.index_path):
            return None
        try:
            with open(self.index_path, "rb") as f:
                data = pickle.load(f)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None
        if data.get("schema") != INDEX_SCHEMA_VERSION:
            return None
        if data.get("config") != self._config_snapshot():
            return None
        if data.get("lib_dex_folder") != self.lib_dex_folder:
            return None
        return data

    def _save_index(self, data: dict) -> None:
        with open(self.index_path, "wb") as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

    def _build_family_metas(self, lib_groups: Dict[str, List[str]]) -> Dict[str, dict]:
        family_metas: Dict[str, dict] = {}
        for family, versions in lib_groups.items():
            meta_list = []
            for rel_path in sorted(set(versions)):
                abs_path = os.path.join(self.lib_dex_folder, rel_path)
                if os.path.exists(abs_path):
                    meta_list.append(_build_dex_meta(rel_path, abs_path))
            family_metas[family] = {
                "versions": sorted(set(versions), key=_version_sort_key),
                "dex_meta": sorted(meta_list, key=lambda x: x["path"]),
            }
        return family_metas

    def _build_family_entry(self, family: str, versions: List[str], dex_meta: List[dict]) -> dict:
        raw_str_tokens: Set[str] = set()
        raw_api_tokens: Set[str] = set()

        selected = _select_representatives(versions)
        parsed_count = 0

        for rel_path in selected:
            try:
                lib_obj = self.load_lib_obj(rel_path)
            except Exception as e:
                self.logger.warning("[libhunter] coarse load failed for %s: %s", rel_path, e)
                lib_obj = None

            if lib_obj is None:
                continue

            classes_dict = getattr(lib_obj, "classes_dict", None)
            if not isinstance(classes_dict, dict):
                continue

            _, _, str_tokens, _ = extract_tokens_from_classes(classes_dict, self.config.min_token_len)
            raw_str_tokens |= str_tokens

            ext_api = getattr(lib_obj, "external_api_tokens", set())
            if isinstance(ext_api, (set, list, tuple)):
                raw_api_tokens |= _normalize_api_tokens(ext_api)

            parsed_count += 1

        force_include = False
        if not raw_str_tokens and not raw_api_tokens:
            fallback_tokens = _normalize_tokens(family, self.config.min_token_len)
            raw_str_tokens |= fallback_tokens
            raw_api_tokens |= _normalize_api_tokens(fallback_tokens)
            force_include = True

        return {
            "family": family,
            "versions": sorted(set(versions), key=_version_sort_key),
            "representatives": selected,
            "dex_meta": dex_meta,
            "parsed_representatives": parsed_count,
            "force_include": force_include,
            "raw_str_tokens": sorted(raw_str_tokens),
            "raw_api_tokens": sorted(raw_api_tokens),
        }

    def _compute_high_df_api(self, entries: Dict[str, dict]) -> Set[str]:
        family_count = max(1, len(entries))
        df = Counter()
        for entry in entries.values():
            df.update(set(entry.get("raw_api_tokens", [])))
        cutoff = max(self.config.high_freq_min_df, int(family_count * self.config.high_freq_ratio))
        return {token for token, cnt in df.items() if cnt >= cutoff}


def build_lib_groups(lib_dex_folder: str) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    if not os.path.isdir(lib_dex_folder):
        return groups

    for family_name in os.listdir(lib_dex_folder):
        family_path = os.path.join(lib_dex_folder, family_name)
        if not os.path.isdir(family_path):
            continue
        versions = [f"{family_name}/{name}" for name in os.listdir(family_path) if name.endswith(".dex")]
        if versions:
            groups[family_name] = sorted(versions, key=_version_sort_key)

    return groups
def extract_apk_features(apk_obj, min_token_len: int) -> dict:
    classes_dict = getattr(apk_obj, "classes_dict", {})
    if not isinstance(classes_dict, dict):
        classes_dict = {}

    _, _, str_tokens, raw_strings = extract_tokens_from_classes(classes_dict, min_token_len)

    ext_api = getattr(apk_obj, "external_api_tokens", set())
    api_before = len(ext_api) if isinstance(ext_api, (set, list, tuple)) else 0
    api_tokens = clean_api_features(ext_api, min_token_len=min_token_len)

    return {
        "str_tokens": str_tokens,
        "api_tokens": api_tokens,
        "raw_strings": raw_strings,
        "api_tokens_before": api_before,
        "api_tokens_after": len(api_tokens),
    }


def extract_apk_tokens(apk_obj, min_token_len: int) -> Tuple[Set[str], Set[str], Set[str]]:
    data = extract_apk_features(apk_obj, min_token_len)
    return set(), set(), set(data["str_tokens"])


def extract_tokens_from_classes(
    classes_dict: Dict[str, list],
    min_token_len: int,
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    pkg_tokens: Set[str] = set()
    sig_tokens: Set[str] = set()
    str_tokens: Set[str] = set()
    raw_strings: Set[str] = set()

    for class_name, class_info in classes_dict.items():
        pkg_tokens |= _normalize_tokens(class_name, min_token_len)

        method_sigs = _extract_method_sig_list(class_info)
        for sig in method_sigs:
            sig_tokens |= _normalize_tokens(sig, min_token_len)

        method_info_dict = _extract_method_info_dict(class_info)
        for method_name, method_info in method_info_dict.items():
            sig_tokens |= _normalize_tokens(method_name, min_token_len)

            if isinstance(method_info, (list, tuple)) and len(method_info) > 2 and isinstance(method_info[2], list):
                for raw in method_info[2]:
                    if raw is None:
                        continue
                    text = str(raw)
                    raw_strings.add(text)
                    str_tokens |= _normalize_tokens(text, min_token_len)

    return pkg_tokens, sig_tokens, str_tokens, raw_strings


def _extract_method_info_dict(class_info) -> Dict[str, list]:
    if not isinstance(class_info, (list, tuple)):
        return {}
    for item in class_info:
        if not isinstance(item, dict) or not item:
            continue
        first_value = next(iter(item.values()))
        if isinstance(first_value, (list, tuple)):
            return item
    return {}


def _extract_method_sig_list(class_info) -> List[str]:
    if not isinstance(class_info, (list, tuple)):
        return []

    candidates = []
    if len(class_info) == 2 and isinstance(class_info[0], list):
        candidates.append(class_info[0])
    if len(class_info) > 4 and isinstance(class_info[4], list):
        candidates.append(class_info[4])
    if len(class_info) > 5 and isinstance(class_info[5], list):
        candidates.append(class_info[5])

    out = []
    for collection in candidates:
        for item in collection:
            if hasattr(item, "pattern"):
                out.append(getattr(item, "pattern"))
            elif isinstance(item, str):
                out.append(item)
    return out


def clean_api_features(
    api_set,
    high_df_tokens: Optional[Set[str]] = None,
    min_token_len: int = 3,
) -> Set[str]:
    if not isinstance(api_set, (set, list, tuple)):
        return set()

    high_df_tokens = set(high_df_tokens or set())
    normalized = _normalize_api_tokens(api_set)
    cleaned: Set[str] = set()

    for token in normalized:
        if len(token) < min_token_len:
            continue
        whitelisted = _has_prefix(token, _API_WHITELIST_PREFIXES)
        if token in high_df_tokens and not whitelisted:
            continue
        if _has_prefix(token, _API_BLACKLIST_PREFIXES) and not whitelisted:
            continue
        cleaned.add(token)

    return cleaned


def check_string_quality(
    string_set,
    min_long_ratio: float = 0.25,
    max_entropy_ratio: float = 0.55,
    min_printable_ratio: float = 0.85,
    entropy_threshold: float = 3.60,
) -> Tuple[float, bool, dict]:
    if not isinstance(string_set, (set, list, tuple)):
        return 0.0, True, {"long_ratio": 0.0, "high_entropy_ratio": 1.0, "printable_ratio": 0.0, "sample_size": 0}

    cleaned = [str(s) for s in string_set if isinstance(s, str) and s]
    if not cleaned:
        return 0.0, True, {"long_ratio": 0.0, "high_entropy_ratio": 1.0, "printable_ratio": 0.0, "sample_size": 0}

    total = len(cleaned)
    long_count = 0
    high_entropy_count = 0
    printable_chars = 0
    total_chars = 0

    for s in cleaned:
        if len(s) > 5:
            long_count += 1
        if _looks_like_ciphertext(s) and _string_entropy(s) >= entropy_threshold:
            high_entropy_count += 1
        total_chars += len(s)
        printable_chars += sum(1 for ch in s if ch.isprintable() and ord(ch) >= 32)

    long_ratio = long_count / float(total)
    high_entropy_ratio = high_entropy_count / float(total)
    printable_ratio = (printable_chars / float(total_chars)) if total_chars > 0 else 0.0

    q_long = _clamp_ratio((long_ratio - 0.05) / 0.80)
    q_entropy = 1.0 - _clamp_ratio((high_entropy_ratio - 0.10) / 0.90)
    q_print = _clamp_ratio((printable_ratio - 0.40) / 0.60)
    q_str = _clamp_ratio(0.40 * q_long + 0.35 * q_entropy + 0.25 * q_print)
    q_str = _clamp_ratio(q_str * (1.0 - 0.5 * high_entropy_ratio))

    is_low_quality = (
        long_ratio < min_long_ratio
        or high_entropy_ratio > max_entropy_ratio
        or printable_ratio < min_printable_ratio
    )

    return q_str, is_low_quality, {
        "long_ratio": long_ratio,
        "high_entropy_ratio": high_entropy_ratio,
        "printable_ratio": printable_ratio,
        "sample_size": total,
    }


def calculate_robust_score(
    apk_minhash: dict,
    lib_minhash: dict,
    q_str: float = 1.0,
    is_low_quality: bool = False,
    smooth: bool = False,
    base_weights: Tuple[float, float] = (0.5, 0.5),
    low_quality_weights: Tuple[float, float] = (0.1, 0.9),
) -> Tuple[float, dict]:
    if "j_str" in apk_minhash:
        j_str = float(apk_minhash.get("j_str", 0.0))
    else:
        j_str = _sig_similarity(apk_minhash.get("sig_str", []), lib_minhash.get("sig_str", []))

    if "j_api" in apk_minhash:
        j_api = float(apk_minhash.get("j_api", 0.0))
    else:
        j_api = _sig_similarity(apk_minhash.get("sig_api", []), lib_minhash.get("sig_api", []))

    base_w_str, base_w_api = base_weights
    low_w_str, low_w_api = low_quality_weights

    if smooth:
        q = _clamp_ratio(q_str)
        w_str = low_w_str + (base_w_str - low_w_str) * q
        w_api = low_w_api + (base_w_api - low_w_api) * q
    elif is_low_quality:
        w_str, w_api = low_w_str, low_w_api
    else:
        w_str, w_api = base_w_str, base_w_api

    total_w = w_str + w_api
    if total_w <= 0:
        w_str, w_api = 0.5, 0.5
    else:
        w_str /= total_w
        w_api /= total_w

    robust = _clamp_ratio(w_str * j_str + w_api * j_api)
    return robust, {"w_str": w_str, "w_api": w_api, "j_str": j_str, "j_api": j_api}


def _tokens_to_signature(tokens: Set[str], num_perm: int) -> List[int]:
    if not tokens:
        return [MAX_HASH] * num_perm
    mh = MinHash(num_perm=num_perm)
    for token in sorted(tokens):
        mh.update(token.encode("utf-8"))
    return [int(v) for v in mh.hashvalues.tolist()]


def _signature_to_minhash(signature: Sequence[int], num_perm: int) -> MinHash:
    mh = MinHash(num_perm=num_perm)
    arr = np.array(list(signature), dtype=np.uint64)
    if arr.shape[0] < num_perm:
        pad = np.full((num_perm - arr.shape[0],), np.uint64(MAX_HASH), dtype=np.uint64)
        arr = np.concatenate([arr, pad])
    elif arr.shape[0] > num_perm:
        arr = arr[:num_perm]
    mh.hashvalues = arr
    return mh


def _effective_bands_rows(num_perm: int, bands: int, rows: int) -> Tuple[int, int]:
    rows = max(1, rows)
    bands = max(1, bands)
    max_bands = max(1, num_perm // rows)
    return min(bands, max_bands), rows


def _normalize_tokens(text, min_token_len: int) -> Set[str]:
    if text is None:
        return set()
    if hasattr(text, "pattern"):
        text = getattr(text, "pattern")

    text = str(text)
    if not text:
        return set()

    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = text.replace("/", " ").replace(".", " ").replace("$", " ")
    text = text.replace("->", " ").replace(";", " ").replace("{", " ").replace("}", " ")
    text = text.lower()

    tokens = set()
    for token in TOKEN_RE.findall(text):
        if len(token) < min_token_len:
            continue
        if token in _STOPWORDS:
            continue
        if token.isdigit():
            continue
        tokens.add(token)
    return tokens


def _normalize_api_tokens(api_set) -> Set[str]:
    out: Set[str] = set()
    for raw in api_set:
        if raw is None:
            continue
        text = str(raw).strip().lower()
        if not text:
            continue

        text = text.replace("->", ".").replace("/", ".")
        text = text.replace(";", ".").replace("(", ".").replace(")", ".")
        text = text.replace("$", ".")

        parts = [p for p in _API_SEG_RE.findall(text) if p]
        if len(parts) < 2:
            continue

        if parts[0].startswith("l") and len(parts[0]) > 1:
            head = parts[0][1:]
            if head in {"java", "javax", "android", "kotlin", "org", "com", "dalvik"}:
                parts[0] = head

        cap = min(len(parts), 4)
        if cap >= 2:
            out.add(".".join(parts[:2]))
        if cap >= 3:
            out.add(".".join(parts[:3]))
        if cap >= 4:
            out.add(".".join(parts[:4]))
    return out


def _select_representatives(versions: Sequence[str]) -> List[str]:
    if not versions:
        return []
    ordered = sorted(set(versions), key=_version_sort_key)
    picks = [ordered[-1], ordered[len(ordered) // 2], ordered[0]]
    out: List[str] = []
    seen: Set[str] = set()
    for item in picks:
        if item in seen:
            continue
        out.append(item)
        seen.add(item)
        if len(out) >= 3:
            break
    return out


def _version_sort_key(path: str):
    filename = os.path.basename(path)
    stem = filename[:-4] if filename.endswith(".dex") else filename
    version = stem.split("_", 1)[-1] if "_" in stem else stem
    normalized = version.replace("_", ".").strip()
    try:
        return (0, Version(normalized), normalized)
    except InvalidVersion:
        return (1, normalized.lower(), normalized)


def _sig_similarity(sig_a: Sequence[int], sig_b: Sequence[int]) -> float:
    if not sig_a or not sig_b:
        return 0.0
    length = min(len(sig_a), len(sig_b))
    if length <= 0:
        return 0.0
    equal = 0
    for i in range(length):
        if int(sig_a[i]) == int(sig_b[i]):
            equal += 1
    return equal / float(length)


def _string_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = float(len(text))
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / total
        entropy -= p * math.log2(p)
    return entropy


def _has_prefix(token: str, prefixes: Sequence[str]) -> bool:
    for prefix in prefixes:
        prefix = prefix.rstrip(".")
        if token == prefix or token.startswith(prefix + "."):
            return True
    return False


def _looks_like_ciphertext(text: str) -> bool:
    if len(text) < 8:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", text):
        return False
    alpha_num = sum(1 for ch in text if ch.isalnum())
    return (alpha_num / float(len(text))) >= 0.85


def _build_dex_meta(rel_path: str, abs_path: str) -> dict:
    return {
        "path": rel_path.replace("\\", "/"),
        "size": os.path.getsize(abs_path),
        "mtime_ms": int(os.path.getmtime(abs_path) * 1000),
        "sha1": _sha1_file(abs_path),
    }


def _sha1_file(path: str) -> str:
    sha1 = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            sha1.update(block)
    return sha1.hexdigest()


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _clamp_ratio(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value
