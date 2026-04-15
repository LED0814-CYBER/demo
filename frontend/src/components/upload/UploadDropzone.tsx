import { FileArchive, UploadCloud } from "lucide-react";
import { useRef, useState } from "react";

import { formatBytes } from "../../utils/format";

interface UploadDropzoneProps {
  file: File | null;
  onFileSelect: (file: File) => void;
  disabled?: boolean;
}

export function UploadDropzone({ file, onFileSelect, disabled = false }: UploadDropzoneProps): JSX.Element {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragging, setDragging] = useState(false);

  const chooseFile = (selected: File | null | undefined) => {
    if (!selected || disabled) return;
    onFileSelect(selected);
  };

  return (
    <div
      className={`relative rounded-2xl border-2 border-dashed p-8 transition ${
        dragging
          ? "border-cyan-300 bg-cyan-500/10"
          : "border-slate-600/70 bg-slate-950/55 hover:border-cyan-600/80"
      } ${disabled ? "opacity-70" : ""}`}
      onDragOver={(event) => {
        event.preventDefault();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        chooseFile(event.dataTransfer.files?.[0]);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".apk"
        className="hidden"
        onChange={(event) => chooseFile(event.target.files?.[0])}
      />

      <button
        type="button"
        disabled={disabled}
        className="absolute inset-0"
        onClick={() => inputRef.current?.click()}
        aria-label="select-apk"
      />

      <div className="pointer-events-none text-center">
        <UploadCloud className="mx-auto h-11 w-11 text-cyan-200/80" />
        <p className="mt-3 text-sm font-semibold text-slate-100">拖拽 APK 或点击选择文件</p>
        <p className="mt-1 text-xs text-slate-400">保持现有后端协议，无需修改服务端。</p>

        {file && (
          <div className="mx-auto mt-4 max-w-xl rounded-lg border border-slate-700/80 bg-slate-900/75 px-3 py-2 text-left">
            <p className="inline-flex items-center gap-2 text-sm text-slate-100">
              <FileArchive className="h-4 w-4 text-cyan-200" />
              {file.name}
            </p>
            <p className="mt-1 text-xs text-slate-400">{formatBytes(file.size)}</p>
          </div>
        )}
      </div>
    </div>
  );
}
