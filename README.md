# 本次更新总结：（详见飞书文档）
## Docker Compose 后端启动（API + Worker + Redis + Postgres）

### 1) 准备环境变量
```bash
cp .env.example .env
```

### 2) 构建镜像
```bash
docker compose build
```

### 3) 启动服务
```bash
docker compose up -d
```

### 4) 查看服务日志
```bash
docker compose logs -f api

docker compose logs -f worker
```

### 5) 任务流程（最小可用）
```bash
# 上传 APK
curl -F "file=@/home/leejm/Andriod_hunter/inputs/demo.apk" http://127.0.0.1:8000/api/upload

# 提交扫描任务（worker 会调用 python3 main.py --apk ...）
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"filename":"demo.apk"}'

# 查询任务状态
curl http://127.0.0.1:8000/api/task/<task_id>

# 查询报告
curl http://127.0.0.1:8000/api/report?task_id=<task_id>
```

### 6) 持久化目录
- `storage/uploads`：上传 APK
- `storage/reports`：最终 JSON 报告
- `storage/logs`：API / Worker / 扫描日志
- `data/phunter_soot_cache`：PHunter 缓存
- `data/lib_pickles_cache`：LibHunter pickle 缓存
- `outputs/raw`：保留兼容的扫描中间产物目录

### docker 常用指令：
``` bash
# 查看镜像
docker images

# 查看正在运行的容器
docker ps

# 查看所有容器
docker ps -a

# 停掉并删除 compose 启动的容器和网络
docker compose down

# 连镜像一起删
docker compose down --rmi all

# 连 volume 也删（最彻底）
docker compose down --rmi all -v
```

### 前端如何运行：
``` bash
cd frontend
npm install
npm run dev
```
然后浏览器打开：http://localhost:5173（已和docker内的后端连通）

### “不构建镜像，热同步代码到容器”流程：
``` bash
# 1) 把本地文件拷进容器（单文件）
docker compose cp engine/detector.py worker:/app/engine/detector.py
docker compose cp backend/celery_app.py worker:/app/backend/celery_app.py

# 2) 如果 API 也会 import 到这些代码，也同步一份
docker compose cp engine/detector.py api:/app/engine/detector.py
docker compose cp backend/celery_app.py api:/app/backend/celery_app.py

# 3) 目录也可以直接拷（整目录覆盖）
docker compose cp LibHunter/module worker:/app/LibHunter/
docker compose cp LibHunter/module api:/app/LibHunter/

# 4) 重启对应服务让新代码生效
docker compose restart worker
docker compose restart api

```
验证是否已同步成功：
```bash
docker compose exec -T worker sh -lc "sed -n '1,80p' /app/engine/detector.py"
docker compose exec -T worker sh -lc "sed -n '1,80p' /app/backend/celery_app.py"

```
### 缺点（等最终版代码改完后，还是需要重新构建镜像，以上指令只不过是快速打补丁的方式）
docker compose cp 是“热补丁”，不需要 build。
这类修改在“容器被重建”后会丢（比如 down/up --build 或重建容器）。
哪个服务执行这段代码，就要同步到哪个服务（这里主要是 worker，有时 api 也要同步）。

## **新增 PHunter 预热模式**
支持模板预热与 APK 预热，不跑完整检测流程即可提前生成缓存。
相关入口在 main.py / engine/detector.py / PHunter signTPL.MainClass（--prewarmOnly、--prewarmAPKOnly）。

### **缓存体系重构为“上层优先，失败回退”**
默认优先使用 binary_analysis / apk_analysis（分析结果缓存）；
仅当上层失败时才回退到底层 binary（Soot 产物链路）。
这样真实 APK 检测时更偏算法层执行，减少重复反编译。

### **缓存目录规范化**
采用 _aliases + soot_cache_hash 结构，按内容 hash 组织缓存，支持稳定命中与别名映射。
缓存命中通过文件 hash + 别名映射实现，兼容“不同文件名同内容”与“同文件名更新覆盖映射”的场景。
避免后续真实 APK 与 CVE 模板无法对齐。

### **终端命令**
```
1）正常检测 APK（自动复用 LibHunter + PHunter 缓存）：
$ python3 main.py --apk /home/leejm/Andriod_hunter/inputs/demo.apk
```
```
2）全量预热 PHunter（来源：TPL-CVEs）：（后续可删除）
$ python3 main.py --prewarm-phunter --prewarm-source tpl_cves
```
```
3） 全量预热 PHunter（来源：cve_kb.json）：
$ python3 main.py --prewarm-phunter --prewarm-source cve_kb
```
```
4） 只预热某个 APK 的 PHunter 缓存（apk_analysis）：
$ python3 main.py --prewarm-apk /home/leejm/Andriod_hunter/inputs/demo.apk
```
```
5） 单条手工预热（仅模板 pre/post，不跑 patch 检测）：
$ java -jar PHunter/PHunter.jar \
  --preTPL /path/to/pre.jar \
  --postTPL /path/to/post.jar \
  --androidJar PHunter/android-31/android.jar \
  --cacheDir data/phunter_soot_cache \
  --cacheMode readwrite \
  --prewarmOnly
```
```
6） 单条手工预热（仅 APK 缓存，不跑模板/patch）：
$ java -jar PHunter/PHunter.jar \
  --targetAPK /path/to/app.apk \
  --androidJar PHunter/android-31/android.jar \
  --cacheDir data/phunter_soot_cache \
  --cacheMode readwrite \
  --prewarmAPKOnly
```

### **可选环境变量（按需）**
```
预热超时（秒），大条目建议调大：
$ export PHUNTER_PREWARM_TIMEOUT=7200
```
```
缓存模式：off | readonly | readwrite
$ export PHUNTER_CACHE_MODE=readwrite
```
```
方法级预算（防极端路径爆炸）
$ export PHUNTER_DIGEST_METHOD_BUDGET_MS=30000
$ export PHUNTER_DIGEST_METHOD_BUDGET_NODES
```

### **对应代码文件**
src/symbolicExec/MethodDigest.java（状态去重 + 方法预算裁剪）
src/analyze/BinaryAnalyzer.java
src/analyze/MethodAttr.java
src/treeEditDistance/node/PredicateNodeData.java
src/analyze/AnalyzerCacheSupport.java（新文件）
src/analyze/SootCacheSupport.java（新文件）
src/signTPL/MainClass.java（预热参数相关）
engine/detector.py（修复 .aar -> .jar 缓存就绪误判）
---