import { Loader2, PlayCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { Panel } from "../components/common/Panel";
import { StageBadge } from "../components/common/StageBadge";
import { UploadDropzone } from "../components/upload/UploadDropzone";
import { useTaskStore } from "../store/taskStore";
import { formatBytes } from "../utils/format";

export function NewTaskPage(): JSX.Element {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const uploadAndAnalyze = useTaskStore((state) => state.uploadAndAnalyze);
  const taskStage = useTaskStore((state) => state.taskStage);
  const uploadState = useTaskStore((state) => state.uploadState);
  const uploadContext = useTaskStore((state) => state.uploadContext);
  const errorMessage = useTaskStore((state) => state.errorMessage);

  const canStart = useMemo(() => {
    return Boolean(selectedFile) && uploadState !== "PENDING";
  }, [selectedFile, uploadState]);

  const startTask = async () => {
    if (!selectedFile) return;
    const taskId = await uploadAndAnalyze(selectedFile);
    navigate(`/task/${taskId}/execution`);
  };

  return (
    <div className="space-y-6">
      <Panel
        title="新建扫描任务"
        right={
          <div className="inline-flex items-center gap-2">
            <StageBadge stage={taskStage} />
          </div>
        }
      >
        <p className="mb-4 text-sm leading-7 text-slate-300">
          上传 APK 后会自动调用 <code>/api/upload</code> 与 <code>/api/analyze</code>，并跳转到执行监控页。
        </p>

        <UploadDropzone file={selectedFile} onFileSelect={setSelectedFile} disabled={uploadState === "PENDING"} />

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={!canStart}
            onClick={() => void startTask()}
            className="inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-4 py-2 font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {uploadState === "PENDING" ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
            上传并开始扫描
          </button>

          {selectedFile && <span className="text-xs text-slate-400">{selectedFile.name} · {formatBytes(selectedFile.size)}</span>}
        </div>

        {uploadContext && (
          <div className="mt-4 rounded-xl border border-emerald-600/40 bg-emerald-900/20 px-3 py-2 text-xs text-emerald-100">
            已上传：{uploadContext.fileName}（{formatBytes(uploadContext.size)}）
          </div>
        )}

        {errorMessage && (
          <div className="mt-4 rounded-xl border border-rose-700/50 bg-rose-900/25 px-3 py-2 text-xs text-rose-100">
            {errorMessage}
          </div>
        )}
      </Panel>
    </div>
  );
}
