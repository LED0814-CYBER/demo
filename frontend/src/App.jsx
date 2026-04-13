import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Loader2,
  Play,
  ShieldCheck,
  TerminalSquare,
  UploadCloud,
  XCircle,
} from "lucide-react";

const STATUS = {
  IDLE: "idle",
  LOADING: "loading",
  SUCCESS: "success",
  ERROR: "error",
  RUNNING: "running",
};

function inferSeverity(vuln) {
  const status = String(vuln.status || "").toUpperCase();
  if (status === "PRESENT") return "high";
  if (status === "NOT_PRESENT") return "low";
  return "medium";
}

function wsUrlForTask(taskId) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host;
  return `${protocol}//${host}/api/logs?task_id=${encodeURIComponent(taskId)}`;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "-";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
}

function StatusPill({ state }) {
  const common = "inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-semibold";
  if (state === STATUS.RUNNING) {
    return (
      <span className={`${common} bg-amber-400/15 text-amber-300 border border-amber-300/20`}>
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        扫描中
      </span>
    );
  }
  if (state === STATUS.SUCCESS) {
    return (
      <span className={`${common} bg-emerald-400/15 text-emerald-300 border border-emerald-300/20`}>
        <CheckCircle2 className="h-3.5 w-3.5" />
        已完成
      </span>
    );
  }
  if (state === STATUS.ERROR) {
    return (
      <span className={`${common} bg-rose-400/15 text-rose-300 border border-rose-300/20`}>
        <XCircle className="h-3.5 w-3.5" />
        失败
      </span>
    );
  }
  return <span className={`${common} bg-slate-400/15 text-slate-300 border border-slate-300/15`}>待机</span>;
}

function MetricCard({ title, value, colorClass }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/75 p-4">
      <p className="text-xs text-slate-400">{title}</p>
      <p className={`mt-2 text-2xl font-semibold ${colorClass}`}>{value}</p>
    </div>
  );
}

export default function App() {
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [uploadState, setUploadState] = useState(STATUS.IDLE);
  const [uploadError, setUploadError] = useState("");

  const [scanState, setScanState] = useState(STATUS.IDLE);
  const [scanError, setScanError] = useState("");
  const [taskId, setTaskId] = useState("");

  const [logs, setLogs] = useState(["[system] 等待上传 APK 文件..."]);
  const terminalRef = useRef(null);
  const wsRef = useRef(null);

  const [reportState, setReportState] = useState(STATUS.IDLE);
  const [report, setReport] = useState(null);
  const [expandRows, setExpandRows] = useState({});

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const vulnerabilities = report?.vulnerabilities || [];
  const grouped = useMemo(() => {
    const high = vulnerabilities.filter((v) => inferSeverity(v) === "high").length;
    const medium = vulnerabilities.filter((v) => inferSeverity(v) === "medium").length;
    const low = vulnerabilities.filter((v) => inferSeverity(v) === "low").length;
    return { high, medium, low };
  }, [vulnerabilities]);

  const onChooseFile = async (picked) => {
    if (!picked) return;
    if (!picked.name.toLowerCase().endsWith(".apk")) {
      setUploadState(STATUS.ERROR);
      setUploadError("仅支持 .apk 文件");
      return;
    }

    setFile(picked);
    setUploadState(STATUS.LOADING);
    setUploadError("");
    setScanState(STATUS.IDLE);
    setScanError("");
    setReport(null);
    setReportState(STATUS.IDLE);
    setTaskId("");
    setLogs([`[upload] 已接收文件: ${picked.name}`]);

    try {
      const body = new FormData();
      body.append("file", picked);
      const res = await fetch("/api/upload", { method: "POST", body });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.detail || `上传失败(${res.status})`);
      }
      const data = await res.json();
      setUploadState(STATUS.SUCCESS);
      setLogs((prev) => [...prev, `[upload] 成功上传: ${data.filename}`]);
    } catch (error) {
      const message = error instanceof Error ? error.message : "上传失败";
      setUploadState(STATUS.ERROR);
      setUploadError(message);
      setLogs((prev) => [...prev, `[error] ${message}`]);
    }
  };

  const fetchReport = async (currentTaskId) => {
    setReportState(STATUS.LOADING);
    try {
      const res = await fetch(`/api/report?task_id=${encodeURIComponent(currentTaskId)}`);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.detail || `报告获取失败(${res.status})`);
      }
      const data = await res.json();
      setReport(data.report || null);
      setReportState(STATUS.SUCCESS);
      setLogs((prev) => [...prev, "[report] 检测报告已加载"]);
    } catch (error) {
      const message = error instanceof Error ? error.message : "报告获取失败";
      setReportState(STATUS.ERROR);
      setScanState(STATUS.ERROR);
      setScanError(message);
      setLogs((prev) => [...prev, `[error] ${message}`]);
    }
  };

  const startScan = async () => {
    if (!file || uploadState !== STATUS.SUCCESS) return;

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setScanState(STATUS.RUNNING);
    setReportState(STATUS.IDLE);
    setReport(null);
    setExpandRows({});
    setScanError("");

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: file.name }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.detail || `任务启动失败(${res.status})`);
      }

      const data = await res.json();
      const currentTaskId = data?.task?.task_id;
      if (!currentTaskId) throw new Error("后端未返回任务 ID");

      setTaskId(currentTaskId);
      setLogs((prev) => [...prev, `[scan] 任务启动: ${currentTaskId}`]);

      const ws = new WebSocket(wsUrlForTask(currentTaskId));
      wsRef.current = ws;

      ws.onmessage = async (evt) => {
        try {
          const dataMsg = JSON.parse(evt.data);
          if (dataMsg.type === "meta") {
            setLogs((prev) => [...prev, `[meta] apk=${dataMsg.apk_name}, status=${dataMsg.status}`]);
            return;
          }

          if (dataMsg.type === "log") {
            const from = dataMsg.file ? `[${dataMsg.file}] ` : "";
            setLogs((prev) => [...prev, `${from}${dataMsg.message || ""}`]);
            return;
          }

          if (dataMsg.type === "done") {
            if (dataMsg.status === "completed") {
              setScanState(STATUS.SUCCESS);
              setLogs((prev) => [...prev, "[scan] 后端任务完成，开始拉取报告..."]);
              await fetchReport(currentTaskId);
            } else {
              const message = dataMsg.error || "扫描任务失败";
              setScanState(STATUS.ERROR);
              setScanError(message);
              setLogs((prev) => [...prev, `[error] ${message}`]);
            }
            ws.close();
          }
        } catch {
          setLogs((prev) => [...prev, evt.data]);
        }
      };

      ws.onerror = () => {
        setLogs((prev) => [...prev, "[warn] WebSocket 中断，请稍后查看报告"]);
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "任务启动失败";
      setScanState(STATUS.ERROR);
      setScanError(message);
      setLogs((prev) => [...prev, `[error] ${message}`]);
    }
  };

  const canScan = uploadState === STATUS.SUCCESS && scanState !== STATUS.RUNNING;

  return (
    <div className="min-h-screen text-slate-100">
      <header className="sticky top-0 z-20 border-b border-cyan-900/60 bg-slate-950/85 backdrop-blur-xl">
        <nav className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-cyan-500/15 p-2 text-cyan-300">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="text-lg font-semibold tracking-tight">App Vulnerability Hunter</p>
              <p className="text-xs text-slate-400">FastAPI Security Dashboard</p>
            </div>
          </div>
          <StatusPill state={scanState} />
        </nav>
      </header>

      <main className="mx-auto grid w-full max-w-7xl gap-6 px-6 py-6 lg:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-neon">
          <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold text-cyan-100">
            <UploadCloud className="h-5 w-5" />
            操作区
          </h2>

          <div
            className={`relative min-h-[230px] rounded-2xl border-2 border-dashed p-6 text-center transition ${
              dragging
                ? "border-cyan-400 bg-cyan-500/10"
                : "border-slate-700 bg-slate-950/60 hover:border-cyan-700"
            }`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              void onChooseFile(e.dataTransfer.files?.[0]);
            }}
          >
            <input
              id="apk-file"
              type="file"
              accept=".apk"
              className="hidden"
              onChange={(e) => {
                void onChooseFile(e.target.files?.[0]);
              }}
            />
            <button
              type="button"
              className="absolute inset-0 h-full w-full"
              onClick={() => document.getElementById("apk-file")?.click()}
              aria-label="choose apk"
            />

            <div className="pointer-events-none">
              <UploadCloud className="mx-auto h-12 w-12 text-cyan-300/80" />
              <p className="mt-3 text-sm font-medium">拖拽 APK 到此处，或点击上传</p>
              <p className="mt-1 text-xs text-slate-400">支持自动上传并准备检测任务</p>
              {file && (
                <div className="mx-auto mt-4 max-w-xl rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-left text-xs">
                  <p className="truncate text-slate-200">文件: {file.name}</p>
                  <p className="mt-1 text-slate-400">大小: {formatBytes(file.size)}</p>
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 space-y-2 text-sm">
            {uploadState === STATUS.LOADING && (
              <p className="inline-flex items-center gap-2 text-amber-300">
                <Loader2 className="h-4 w-4 animate-spin" />
                文件上传中...
              </p>
            )}
            {uploadState === STATUS.SUCCESS && (
              <p className="inline-flex items-center gap-2 text-emerald-300">
                <CheckCircle2 className="h-4 w-4" />
                上传成功，可直接开始检测
              </p>
            )}
            {uploadState === STATUS.ERROR && (
              <p className="inline-flex items-center gap-2 text-rose-300">
                <AlertTriangle className="h-4 w-4" />
                {uploadError}
              </p>
            )}
          </div>

          <button
            type="button"
            onClick={startScan}
            disabled={!canScan}
            className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-500 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {scanState === STATUS.RUNNING ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            开始检测
          </button>

          {scanError && (
            <p className="mt-4 rounded-lg border border-rose-700/50 bg-rose-950/30 px-3 py-2 text-sm text-rose-300">
              检测错误: {scanError}
            </p>
          )}
        </section>

        <section className="rounded-2xl border border-emerald-900/40 bg-[#020902] p-4 shadow-2xl">
          <div className="mb-3 flex items-center justify-between text-emerald-300">
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <TerminalSquare className="h-4 w-4" />
              实时终端
            </h2>
            <span className="text-xs text-emerald-500">{taskId ? `task: ${taskId}` : "task: - "}</span>
          </div>

          <div
            ref={terminalRef}
            className="h-[420px] overflow-y-auto rounded-xl border border-emerald-950 bg-black/80 p-3 font-mono text-xs leading-6 text-emerald-300"
          >
            {logs.map((line, idx) => (
              <div key={`${line}-${idx}`} className="animate-terminal-fade whitespace-pre-wrap break-words">
                <span className="mr-2 text-emerald-700">$</span>
                {line}
              </div>
            ))}
          </div>
        </section>
      </main>

      <section className="mx-auto mb-8 w-full max-w-7xl px-6">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold text-cyan-100">
            <Bug className="h-5 w-5" />
            检测结果
          </h2>

          {reportState === STATUS.LOADING && (
            <p className="inline-flex items-center gap-2 text-amber-300">
              <Loader2 className="h-4 w-4 animate-spin" />
              正在拉取报告...
            </p>
          )}

          {reportState !== STATUS.SUCCESS && reportState !== STATUS.LOADING && (
            <p className="text-sm text-slate-400">报告将在扫描成功后自动显示。</p>
          )}

          {reportState === STATUS.SUCCESS && report && (
            <>
              <div className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-4">
                <MetricCard title="高危漏洞" value={grouped.high} colorClass="text-rose-300" />
                <MetricCard title="中危漏洞" value={grouped.medium} colorClass="text-amber-300" />
                <MetricCard title="低危/已修复" value={grouped.low} colorClass="text-emerald-300" />
                <MetricCard title="总漏洞记录" value={vulnerabilities.length} colorClass="text-cyan-300" />
              </div>

              <div className="mb-5 space-y-2 rounded-xl border border-slate-800 bg-slate-950/60 p-4 text-sm">
                <p className="text-slate-300">
                  APK: <span className="font-medium text-white">{report?.apk_info?.name || "-"}</span>
                </p>
                <p className="text-slate-400">SHA256: {report?.apk_info?.sha256 || "-"}</p>
                <p className="text-slate-400">文件大小: {formatBytes(report?.apk_info?.size)}</p>
              </div>

              <div className="overflow-hidden rounded-xl border border-slate-800">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-900 text-slate-300">
                    <tr>
                      <th className="px-4 py-3">CVE</th>
                      <th className="px-4 py-3">组件</th>
                      <th className="px-4 py-3">状态</th>
                      <th className="px-4 py-3">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerabilities.length === 0 && (
                      <tr className="border-t border-slate-800">
                        <td colSpan={4} className="px-4 py-4 text-slate-400">
                          未发现漏洞记录
                        </td>
                      </tr>
                    )}

                    {vulnerabilities.map((v, idx) => {
                      const isOpen = Boolean(expandRows[idx]);
                      const level = inferSeverity(v);
                      const label =
                        level === "high"
                          ? "高危"
                          : level === "medium"
                            ? "中危"
                            : "低危/已修复";

                      const badgeClass =
                        level === "high"
                          ? "bg-rose-400/15 text-rose-300 border-rose-300/30"
                          : level === "medium"
                            ? "bg-amber-400/15 text-amber-300 border-amber-300/30"
                            : "bg-emerald-400/15 text-emerald-300 border-emerald-300/30";

                      return (
                        <React.Fragment key={`${v.cve_id || "vuln"}-${idx}`}>
                          <tr className="border-t border-slate-800 bg-slate-950/40">
                            <td className="px-4 py-3 font-medium text-slate-100">{v.cve_id || "-"}</td>
                            <td className="px-4 py-3 text-slate-300">{v.library || "-"}</td>
                            <td className="px-4 py-3">
                              <span className={`rounded-full border px-2 py-1 text-xs font-semibold ${badgeClass}`}>
                                {label}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <button
                                className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200"
                                onClick={() =>
                                  setExpandRows((prev) => ({
                                    ...prev,
                                    [idx]: !prev[idx],
                                  }))
                                }
                              >
                                {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                                {isOpen ? "收起" : "详情"}
                              </button>
                            </td>
                          </tr>
                          {isOpen && (
                            <tr className="border-t border-slate-800 bg-slate-900/40">
                              <td className="px-4 py-4 text-slate-300" colSpan={4}>
                                <div className="grid grid-cols-1 gap-2 text-xs md:grid-cols-3">
                                  <p>Patch Status: {String(v.status || "-")}</p>
                                  <p>Pre Similarity: {v.pre_similarity ?? "-"}</p>
                                  <p>Post Similarity: {v.post_similarity ?? "-"}</p>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </section>
    </div>
  );
}
