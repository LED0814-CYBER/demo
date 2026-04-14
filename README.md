# LibHunter 第一轮粗筛（Coarse Filter）说明

本文档说明当前 LibHunter 在精检前的首轮粗筛算法实现与使用方式。

## 1. 目标

- 在不改变 `detect` 输出格式的前提下，先做一轮高召回粗筛。
- 降低后续精检的库族数量，控制总体耗时。
- 默认策略以召回优先，剪枝率目标约 `80%`，并避免过严剪枝（不超过 `90%`）。

## 2. 算法概览

当前粗筛为“两路特征 + MinHash + LSH + 动态鲁棒重排”：

1. 以 `family` 为单位聚合库版本（默认代表版本：latest + median + oldest，最多 3 个）。
2. 提取两类特征：
   - `str_tokens`：字符串常量特征
   - `api_tokens`：外部 API 调用特征（含去噪）
3. 族级指纹：
   - `sig_str` = MinHash(`str_tokens`)
   - `sig_api` = MinHash(`api_tokens`)
4. 建两套 LSH：
   - `lsh_str`
   - `lsh_api`
5. APK 查询：
   - `initial = hit_str ∪ hit_api`
6. 候选重排：
   - 计算 `J_str`、`J_api`（由 MinHash 签名估计）
   - `J_robust = w_str * J_str + w_api * J_api`
   - 权重硬切换：
     - 正常字符串质量：`w_str=0.5, w_api=0.5`
     - 低质量字符串：`w_str=0.1, w_api=0.9`
7. 保留规则：
   - `keep_count = max(min_keep, ceil(total_groups * 0.2))`
   - `keep_count = min(keep_count, ceil(total_groups * 0.9))`
   - 按 `J_robust` 取前 `keep_count`
   - 若为空且 `fallback_on_empty=true`，回退全量

## 3. 去噪与质量检测

### 3.1 API 去噪 `clean_api_features`

- 黑名单过滤：如 `java.lang.*`、`java.util.*` 等高频通用簇
- 白名单保留：如 `android.net.*`、`javax.crypto.*`、`android.hardware.*`、`android.telephony.*`、`android.media.*`
- Family 维度高 DF 过滤：剔除跨家族高频 API token（可配置比例阈值）

### 3.2 字符串质量检测 `check_string_quality`

基于三类指标判断字符串是否低质量（疑似加密/乱码）：

- 长字符串占比（`len > 5`）
- 高熵字符串占比（Shannon entropy）
- 可打印字符占比

输出：

- `q_str in [0,1]`
- `is_low_quality`（是否触发降权）

## 4. 缓存与索引

系统运行时最关键的两类缓存：

1. `data/lib_pickle_cache/*.pkl`
   - 每个第三方库 dex 的 `ThirdLib` 解析对象缓存（含 `classes_dict`、`external_api_tokens`）
2. `LibHunter/data/coarse_index/coarse_index.pkl`
   - 族级压缩索引（签名、LSH、dex 元数据、配置快照）

索引支持增量复用：

- 若库文件 `size/mtime/hash` 未变化，则复用既有 family 索引；
- 仅对变化的 family 重建。

## 5. 关键配置（环境变量）

- `LH_COARSE_ENABLED=true`
- `LH_COARSE_MINHASH_PERM=128`
- `LH_COARSE_LSH_BANDS=32`
- `LH_COARSE_LSH_ROWS=4`
- `LH_COARSE_MIN_KEEP=10`
- `LH_COARSE_KEEP_RATIO=0.2`
- `LH_COARSE_MAX_KEEP_RATIO=0.9`
- `LH_COARSE_FALLBACK_ON_EMPTY=true`
- `LH_COARSE_API_DF_RATIO=0.60`
- `LH_COARSE_API_DF_MIN=12`
- `LH_COARSE_ROBUST_W_STR=0.5`
- `LH_COARSE_ROBUST_W_API=0.5`
- `LH_COARSE_ROBUST_LOWQ_W_STR=0.1`
- `LH_COARSE_ROBUST_LOWQ_W_API=0.9`

## 6. 日志指标

粗筛阶段会输出以下关键指标：

- `coarse_total_groups`
- `coarse_candidate_groups`
- `coarse_prune_ratio`
- `coarse_elapsed_ms`
- `fallback_triggered`
- `api_tokens_before / api_tokens_after`
- `string_quality`
- `adaptive_weights`
- `rerank_keep_count`

示例：

```text
[libhunter] Coarse filter: 460 -> 92 groups (pruned 80.0%), 240ms
```

## 7. 依赖

粗筛使用：

- `datasketch`（MinHash / LSH）
- `packaging`（版本排序）

请确保已安装：

```bash
pip3 install -r requirements.txt
```

## 8. 与精检关系

- 首轮粗筛只负责“库族候选召回与裁剪”。
- 后续 `detect` 精检逻辑和输出格式保持不变。
- 该设计保证粗筛是前置加速层，不改变核心判定接口。

