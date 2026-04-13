from __future__ import annotations

import hashlib
import logging
import math
import os
import pickle
import random
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


DEFAULT_INDEX_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "coarse_index",
)
INDEX_FILENAME = "coarse_index.pkl"
INDEX_SCHEMA_VERSION = 1

MAX_HASH = (1 << 61) - 1
MINHASH_PRIME = 2305843009213693951

TOKEN_RE = re.compile(r"[a-z0-9]{2,}")
_VERSION_SPLIT_RE = re.compile(r"(\d+|[a-zA-Z]+)")

_STOPWORDS = {
    "a",
    "an",
    "and",
    "android",
    "app",
    "application",
    "array",
    "base",
    "builder",
    "by",
    "class",
    "com",
    "common",
    "core",
    "data",
    "default",
    "dex",
    "do",
    "for",
    "from",
    "get",
    "handler",
    "helper",
    "impl",
    "in",
    "init",
    "internal",
    "io",
    "is",
    "it",
    "java",
    "javax",
    "json",
    "lang",
    "lib",
    "main",
    "manager",
    "method",
    "model",
    "module",
    "net",
    "of",
    "on",
    "or",
    "org",
    "other",
    "package",
    "parse",
    "parser",
    "public",
    "set",
    "service",
    "static",
    "string",
    "support",
    "the",
    "this",
    "to",
    "true",
    "type",
    "util",
    "utils",
    "value",
    "version",
    "void",
    "with",
    "x",
}


@dataclass(frozen=True)
class CoarseFilterConfig:
    enabled: bool = True
    score_threshold: float = 0.12
    top_k: int = 60
    minhash_perm: int = 128
    lsh_bands: int = 32
    lsh_rows: int = 4
    fallback_on_empty: bool = True
    high_freq_ratio: float = 0.35
    high_freq_min_df: int = 8
    min_token_len: int = 3
    target_prune_ratio: float = 0.80
    max_prune_ratio: float = 0.90

    @classmethod
    def from_env(cls) -> "CoarseFilterConfig":
        target_prune_ratio = _clamp_ratio(float(os.environ.get("LH_COARSE_TARGET_PRUNE_RATIO", "0.80")))
        max_prune_ratio = _clamp_ratio(float(os.environ.get("LH_COARSE_MAX_PRUNE_RATIO", "0.90")))
        if target_prune_ratio > max_prune_ratio:
            target_prune_ratio = max_prune_ratio
        return cls(
            enabled=_env_bool("LH_COARSE_ENABLED", True),
            score_threshold=float(os.environ.get("LH_COARSE_SCORE_THRESHOLD", "0.12")),
            top_k=max(1, int(os.environ.get("LH_COARSE_TOP_K", "60"))),
            minhash_perm=max(16, int(os.environ.get("LH_COARSE_MINHASH_PERM", "128"))),
            lsh_bands=max(1, int(os.environ.get("LH_COARSE_LSH_BANDS", "32"))),
            lsh_rows=max(1, int(os.environ.get("LH_COARSE_LSH_ROWS", "4"))),
            fallback_on_empty=_env_bool("LH_COARSE_FALLBACK_ON_EMPTY", True),
            high_freq_ratio=float(os.environ.get("LH_COARSE_HIGH_FREQ_RATIO", "0.35")),
            high_freq_min_df=max(2, int(os.environ.get("LH_COARSE_HIGH_FREQ_MIN_DF", "8"))),
            min_token_len=max(2, int(os.environ.get("LH_COARSE_MIN_TOKEN_LEN", "3"))),
            target_prune_ratio=target_prune_ratio,
            max_prune_ratio=max_prune_ratio,
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

        perm_total = self.config.minhash_perm
        self._permutations = _build_permutations(perm_total)

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

        high_freq = self._compute_high_freq_tokens(entries)

        for family, entry in entries.items():
            raw_pkg = set(entry.get("raw_pkg_tokens", []))
            raw_sig = set(entry.get("raw_sig_tokens", []))
            raw_str = set(entry.get("raw_str_tokens", []))

            pkg_tokens = raw_pkg - high_freq["pkg"]
            sig_tokens = raw_sig - high_freq["sig"]
            str_tokens = raw_str - high_freq["str"]

            entry["pkg_tokens"] = sorted(pkg_tokens)
            entry["sig_tokens"] = sorted(sig_tokens)
            entry["str_tokens"] = sorted(str_tokens)

            entry["sig_pkg"] = self._minhash(pkg_tokens)
            entry["sig_sig"] = self._minhash(sig_tokens)
            entry["sig_str"] = self._minhash(str_tokens)

        lsh_pkg = self._build_lsh(entries, "sig_pkg")
        lsh_sig = self._build_lsh(entries, "sig_sig")
        lsh_str = self._build_lsh(entries, "sig_str")

        self._index_data = {
            "schema": INDEX_SCHEMA_VERSION,
            "config": self._config_snapshot(),
            "lib_dex_folder": self.lib_dex_folder,
            "family_entries": entries,
            "high_freq": {k: sorted(v) for k, v in high_freq.items()},
            "lsh_pkg": {k: sorted(v) for k, v in lsh_pkg.items()},
            "lsh_sig": {k: sorted(v) for k, v in lsh_sig.items()},
            "lsh_str": {k: sorted(v) for k, v in lsh_str.items()},
            "updated_at_ms": int(time.time() * 1000),
        }
        self._save_index(self._index_data)

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
            metrics = {
                "coarse_total_groups": len(all_groups),
                "coarse_candidate_groups": len(all_groups),
                "coarse_prune_ratio": 0.0,
                "coarse_elapsed_ms": int((time.perf_counter() - started) * 1000),
                "fallback_triggered": False,
                "initial_candidates": len(all_groups),
            }
            return all_groups, metrics

        if self._index_data is None:
            self.ensure_index(lib_groups)

        index_data = self._index_data or {}
        entries = index_data.get("family_entries", {})
        indexed_families = set(entries.keys())

        q_pkg, q_sig, q_str = extract_apk_tokens(apk_obj, self.config.min_token_len)

        high_freq = index_data.get("high_freq", {})
        q_pkg -= set(high_freq.get("pkg", []))
        q_sig -= set(high_freq.get("sig", []))
        q_str -= set(high_freq.get("str", []))

        q_sig_pkg = self._minhash(q_pkg)
        q_sig_sig = self._minhash(q_sig)
        q_sig_str = self._minhash(q_str)

        initial = set()
        initial |= self._query_lsh(index_data.get("lsh_pkg", {}), q_sig_pkg)
        initial |= self._query_lsh(index_data.get("lsh_sig", {}), q_sig_sig)
        initial |= self._query_lsh(index_data.get("lsh_str", {}), q_sig_str)

        scores: Dict[str, float] = {}
        for family in initial:
            entry = entries.get(family)
            if not entry:
                continue
            scores[family] = self._score_family(entry, q_sig_pkg, q_sig_sig, q_sig_str)

        threshold_set = {f for f, s in scores.items() if s >= self.config.score_threshold}
        top_candidates = sorted(scores.items(), key=lambda x: (-x[1], x[0]))[: self.config.top_k]
        topk_set = {family for family, _ in top_candidates}
        candidate_groups = threshold_set | topk_set

        force_include = {
            family
            for family, entry in entries.items()
            if entry.get("force_include")
        }
        candidate_groups |= force_include

        missing_index_families = set(lib_groups.keys()) - indexed_families
        candidate_groups |= missing_index_families

        total_groups = len(lib_groups)
        target_keep = int(math.ceil(total_groups * (1.0 - self.config.target_prune_ratio)))
        min_keep = int(math.ceil(total_groups * (1.0 - self.config.max_prune_ratio)))
        desired_keep = max(1, max(target_keep, min_keep))

        if len(candidate_groups) < desired_keep:
            for family, entry in entries.items():
                if family in scores:
                    continue
                scores[family] = self._score_family(entry, q_sig_pkg, q_sig_sig, q_sig_str)

            ranked_all = sorted(scores.items(), key=lambda x: (-x[1], x[0]))
            for family, _ in ranked_all:
                candidate_groups.add(family)
                if len(candidate_groups) >= desired_keep:
                    break

        fallback_triggered = False
        if not candidate_groups and self.config.fallback_on_empty:
            candidate_groups = set(lib_groups.keys())
            fallback_triggered = True

        candidate_count = len(candidate_groups)
        prune_ratio = 0.0 if total_groups == 0 else 1.0 - (candidate_count / total_groups)
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        metrics = {
            "coarse_total_groups": total_groups,
            "coarse_candidate_groups": candidate_count,
            "coarse_prune_ratio": prune_ratio,
            "coarse_elapsed_ms": elapsed_ms,
            "fallback_triggered": fallback_triggered,
            "initial_candidates": len(initial),
            "coarse_target_keep_groups": desired_keep,
        }
        return candidate_groups, metrics

    def _config_snapshot(self) -> dict:
        return {
            "minhash_perm": self.config.minhash_perm,
            "lsh_bands": self.config.lsh_bands,
            "lsh_rows": self.config.lsh_rows,
            "min_token_len": self.config.min_token_len,
            "high_freq_ratio": self.config.high_freq_ratio,
            "high_freq_min_df": self.config.high_freq_min_df,
            "target_prune_ratio": self.config.target_prune_ratio,
            "max_prune_ratio": self.config.max_prune_ratio,
        }

    def _score_family(self, entry: dict, q_sig_pkg: List[int], q_sig_sig: List[int], q_sig_str: List[int]) -> float:
        j_pkg = _sig_similarity(q_sig_pkg, entry.get("sig_pkg", []))
        j_sig = _sig_similarity(q_sig_sig, entry.get("sig_sig", []))
        j_str = _sig_similarity(q_sig_str, entry.get("sig_str", []))
        return 0.45 * j_pkg + 0.35 * j_sig + 0.20 * j_str

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
        family_metas = {}
        for family, versions in lib_groups.items():
            meta_list = []
            for rel_path in sorted(set(versions)):
                abs_path = os.path.join(self.lib_dex_folder, rel_path)
                if not os.path.exists(abs_path):
                    continue
                meta_list.append(_build_dex_meta(rel_path, abs_path))
            family_metas[family] = {
                "versions": sorted(set(versions), key=_version_sort_key),
                "dex_meta": sorted(meta_list, key=lambda x: x["path"]),
            }
        return family_metas

    def _build_family_entry(self, family: str, versions: List[str], dex_meta: List[dict]) -> dict:
        raw_pkg: Set[str] = set()
        raw_sig: Set[str] = set()
        raw_str: Set[str] = set()

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

            pkg_tokens, sig_tokens, str_tokens = extract_tokens_from_classes(classes_dict, self.config.min_token_len)
            raw_pkg |= pkg_tokens
            raw_sig |= sig_tokens
            raw_str |= str_tokens
            parsed_count += 1

        force_include = False
        if not raw_pkg and not raw_sig and not raw_str:
            fallback_tokens = _normalize_tokens(family, self.config.min_token_len)
            raw_pkg |= fallback_tokens
            raw_sig |= fallback_tokens
            force_include = True

        return {
            "family": family,
            "versions": sorted(set(versions), key=_version_sort_key),
            "representatives": selected,
            "dex_meta": dex_meta,
            "parsed_representatives": parsed_count,
            "force_include": force_include,
            "raw_pkg_tokens": sorted(raw_pkg),
            "raw_sig_tokens": sorted(raw_sig),
            "raw_str_tokens": sorted(raw_str),
        }

    def _compute_high_freq_tokens(self, entries: Dict[str, dict]) -> Dict[str, Set[str]]:
        family_count = max(1, len(entries))

        df_pkg = Counter()
        df_sig = Counter()
        df_str = Counter()

        for entry in entries.values():
            df_pkg.update(set(entry.get("raw_pkg_tokens", [])))
            df_sig.update(set(entry.get("raw_sig_tokens", [])))
            df_str.update(set(entry.get("raw_str_tokens", [])))

        def _collect(df: Counter) -> Set[str]:
            cutoff = max(self.config.high_freq_min_df, int(family_count * self.config.high_freq_ratio))
            return {token for token, cnt in df.items() if cnt >= cutoff}

        return {
            "pkg": _collect(df_pkg),
            "sig": _collect(df_sig),
            "str": _collect(df_str),
        }

    def _minhash(self, tokens: Set[str]) -> List[int]:
        if not tokens:
            return [MAX_HASH] * self.config.minhash_perm

        token_hashes = [_hash_token(token) for token in tokens]
        signature = [MAX_HASH] * self.config.minhash_perm

        for h in token_hashes:
            for idx, (a, b) in enumerate(self._permutations):
                x = (a * h + b) % MINHASH_PRIME
                if x < signature[idx]:
                    signature[idx] = x

        return signature

    def _build_lsh(self, entries: Dict[str, dict], sig_key: str) -> Dict[str, Set[str]]:
        buckets: Dict[str, Set[str]] = defaultdict(set)
        for family, entry in entries.items():
            sig = entry.get(sig_key, [])
            for band_key in _iter_band_keys(sig, self.config.lsh_bands, self.config.lsh_rows):
                buckets[band_key].add(family)
        return buckets

    def _query_lsh(self, lsh_dict: Dict[str, Sequence[str]], sig: List[int]) -> Set[str]:
        candidates: Set[str] = set()
        for band_key in _iter_band_keys(sig, self.config.lsh_bands, self.config.lsh_rows):
            families = lsh_dict.get(band_key, [])
            if families:
                candidates.update(families)
        return candidates


def build_lib_groups(lib_dex_folder: str) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    if not os.path.isdir(lib_dex_folder):
        return groups

    for family_name in os.listdir(lib_dex_folder):
        family_path = os.path.join(lib_dex_folder, family_name)
        if not os.path.isdir(family_path):
            continue
        versions = []
        for file_name in os.listdir(family_path):
            if not file_name.endswith(".dex"):
                continue
            versions.append(f"{family_name}/{file_name}")
        if versions:
            groups[family_name] = sorted(versions, key=_version_sort_key)

    return groups


def extract_apk_tokens(apk_obj, min_token_len: int) -> Tuple[Set[str], Set[str], Set[str]]:
    classes_dict = getattr(apk_obj, "classes_dict", {})
    if not isinstance(classes_dict, dict):
        return set(), set(), set()
    return extract_tokens_from_classes(classes_dict, min_token_len)


def extract_tokens_from_classes(classes_dict: Dict[str, list], min_token_len: int) -> Tuple[Set[str], Set[str], Set[str]]:
    pkg_tokens: Set[str] = set()
    sig_tokens: Set[str] = set()
    str_tokens: Set[str] = set()

    for class_name, class_info in classes_dict.items():
        pkg_tokens |= _normalize_tokens(class_name, min_token_len)

        method_sigs = _extract_method_sig_list(class_info)
        for sig in method_sigs:
            sig_tokens |= _normalize_tokens(sig, min_token_len)

        method_info_dict = _extract_method_info_dict(class_info)
        for method_name, method_info in method_info_dict.items():
            sig_tokens |= _normalize_tokens(method_name, min_token_len)

            if isinstance(method_info, (list, tuple)):
                if len(method_info) > 4:
                    sig_tokens |= _normalize_tokens(method_info[4], min_token_len)
                if len(method_info) > 2 and isinstance(method_info[2], list):
                    for raw in method_info[2]:
                        str_tokens |= _normalize_tokens(raw, min_token_len)

    return pkg_tokens, sig_tokens, str_tokens


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


def _select_representatives(versions: Sequence[str]) -> List[str]:
    if not versions:
        return []
    ordered = sorted(set(versions), key=_version_sort_key)
    picks = [ordered[-1], ordered[len(ordered) // 2], ordered[0]]
    seen = set()
    out = []
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

    parts = []
    for piece in _VERSION_SPLIT_RE.findall(version):
        if piece.isdigit():
            parts.append((0, int(piece)))
        else:
            parts.append((1, piece.lower()))
    return parts, version


def _build_permutations(num_perm: int) -> List[Tuple[int, int]]:
    rng = random.Random(20260413)
    perms = []
    for _ in range(num_perm):
        a = rng.randrange(1, MINHASH_PRIME - 1)
        b = rng.randrange(0, MINHASH_PRIME - 1)
        perms.append((a, b))
    return perms


def _hash_token(token: str) -> int:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % MINHASH_PRIME


def _iter_band_keys(signature: Sequence[int], bands: int, rows: int) -> Iterable[str]:
    if not signature:
        return []

    max_bands = min(bands, len(signature) // rows)
    for band_idx in range(max_bands):
        start = band_idx * rows
        end = start + rows
        chunk = signature[start:end]
        raw = ",".join(str(v) for v in chunk)
        digest = hashlib.md5(raw.encode("utf-8")).hexdigest()
        yield f"{band_idx}:{digest}"


def _sig_similarity(sig_a: Sequence[int], sig_b: Sequence[int]) -> float:
    if not sig_a or not sig_b:
        return 0.0
    length = min(len(sig_a), len(sig_b))
    if length <= 0:
        return 0.0
    equal = 0
    for idx in range(length):
        if sig_a[idx] == sig_b[idx]:
            equal += 1
    return equal / float(length)


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
    if value > 0.99:
        return 0.99
    return value
