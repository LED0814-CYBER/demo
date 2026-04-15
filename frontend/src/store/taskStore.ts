import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import { ApiError, fetchReport, startAnalyze, uploadApk } from "../services/api";
import { adaptReport } from "../services/adapters/reportAdapter";
import { mapBackendTaskStatusToStage } from "../services/adapters/statusAdapter";
import { createTaskLogSocket, type TaskLogSocketController } from "../services/socket";
import type { LogEntry, ReportModel, RequestState, TaskStage, UploadContext, WsConnectionState } from "../types/domain";
import { nowId } from "../utils/identity";
import { loadLastTask, saveLastTask } from "../utils/storage";

let activeSocket: TaskLogSocketController | null = null;
let pollingTimer: ReturnType<typeof setInterval> | null = null;

const POLL_INTERVAL_MS = 4000;
const MAX_POLL_ROUNDS = 45;
const MAX_LOGS = 800;

function appendLogEntry(logs: LogEntry[], entry: Omit<LogEntry, "id" | "timestamp">): LogEntry[] {
  const next = [...logs, { id: nowId("log"), timestamp: Date.now(), ...entry }];
  return next.length > MAX_LOGS ? next.slice(next.length - MAX_LOGS) : next;
}

function uniqueTaskHistory(history: string[], taskId: string): string[] {
  return [taskId, ...history.filter((id) => id !== taskId)].slice(0, 20);
}

interface TaskStoreState {
  currentTaskId: string | null;
  lastTaskId: string | null;
  uploadContext: UploadContext | null;

  uploadState: RequestState;
  taskStage: TaskStage;
  wsState: WsConnectionState;
  isPollingFallback: boolean;

  logs: LogEntry[];
  reportsByTask: Record<string, ReportModel>;
  historyTaskIds: string[];

  errorMessage: string | null;
  activeVulnerabilityId: string | null;
  selectedLibraryId: string | null;

  resetForNewTask: () => void;
  appendSystemLog: (message: string, source?: LogEntry["source"]) => void;
  uploadAndAnalyze: (file: File) => Promise<string>;
  ensureReport: (taskId: string, silent?: boolean) => Promise<ReportModel | null>;
  connectExecution: (taskId: string) => Promise<void>;
  stopRealtime: () => void;
  startPollingFallback: (taskId: string) => void;

  setActiveVulnerability: (id: string | null) => void;
  setSelectedLibrary: (id: string | null) => void;
}

const initialLogs: LogEntry[] = [
  {
    id: nowId("log"),
    timestamp: Date.now(),
    source: "system",
    message: "[system] 就绪，等待创建扫描任务。",
  },
];

const clearRealtimeResources = () => {
  if (activeSocket) {
    activeSocket.close();
    activeSocket = null;
  }
  if (pollingTimer) {
    clearInterval(pollingTimer);
    pollingTimer = null;
  }
};

export const useTaskStore = create<TaskStoreState>()(
  persist(
    (set, get) => ({
      currentTaskId: null,
      lastTaskId: loadLastTask(),
      uploadContext: null,

      uploadState: "IDLE",
      taskStage: "IDLE",
      wsState: "DISCONNECTED",
      isPollingFallback: false,

      logs: initialLogs,
      reportsByTask: {},
      historyTaskIds: [],

      errorMessage: null,
      activeVulnerabilityId: null,
      selectedLibraryId: null,

      resetForNewTask: () => {
        clearRealtimeResources();
        set((state) => ({
          ...state,
          currentTaskId: null,
          uploadContext: null,
          uploadState: "IDLE",
          taskStage: "IDLE",
          wsState: "DISCONNECTED",
          isPollingFallback: false,
          errorMessage: null,
          activeVulnerabilityId: null,
          selectedLibraryId: null,
          logs: appendLogEntry([], {
            source: "system",
            message: "[system] 新任务初始化完成。",
          }),
        }));
      },

      appendSystemLog: (message, source = "system") => {
        set((state) => ({
          logs: appendLogEntry(state.logs, { message, source }),
        }));
      },

      uploadAndAnalyze: async (file) => {
        clearRealtimeResources();
        set((state) => ({
          ...state,
          uploadState: "PENDING",
          taskStage: "UPLOADING",
          wsState: "DISCONNECTED",
          isPollingFallback: false,
          currentTaskId: null,
          errorMessage: null,
          activeVulnerabilityId: null,
          selectedLibraryId: null,
          logs: appendLogEntry([], {
            source: "system",
            message: `[upload] 已接收文件: ${file.name}`,
          }),
        }));

        try {
          const uploadResult = await uploadApk(file);
          set((state) => ({
            ...state,
            uploadState: "SUCCESS",
            uploadContext: {
              fileName: uploadResult.filename,
              size: uploadResult.size,
              uploadedPath: uploadResult.path,
            },
            logs: appendLogEntry(state.logs, {
              source: "system",
              message: `[upload] 上传成功: ${uploadResult.filename}`,
            }),
          }));

          const analyzeResult = await startAnalyze({ filename: uploadResult.filename });
          const taskId = analyzeResult.task?.task_id;
          if (!taskId) throw new Error("后端未返回任务 ID");

          saveLastTask(taskId);

          set((state) => ({
            ...state,
            currentTaskId: taskId,
            lastTaskId: taskId,
            taskStage: "QUEUED",
            historyTaskIds: uniqueTaskHistory(state.historyTaskIds, taskId),
            logs: appendLogEntry(state.logs, {
              source: "system",
              message: `[scan] 任务已创建: ${taskId}`,
            }),
          }));

          return taskId;
        } catch (error) {
          const message = error instanceof Error ? error.message : "上传或任务创建失败";
          set((state) => ({
            ...state,
            uploadState: "ERROR",
            taskStage: "FAILED",
            errorMessage: message,
            logs: appendLogEntry(state.logs, {
              source: "system",
              message: `[error] ${message}`,
            }),
          }));
          throw error;
        }
      },

      ensureReport: async (taskId, silent = false) => {
        try {
          const raw = await fetchReport(taskId);
          const report = adaptReport(raw, taskId);

          set((state) => ({
            ...state,
            reportsByTask: {
              ...state.reportsByTask,
              [taskId]: report,
            },
            currentTaskId: taskId,
            lastTaskId: taskId,
            taskStage: "REPORT_READY",
            wsState: state.wsState === "FAILED" ? "DEGRADED" : state.wsState,
            historyTaskIds: uniqueTaskHistory(state.historyTaskIds, taskId),
            activeVulnerabilityId: state.activeVulnerabilityId || report.vulnerabilities[0]?.id || null,
            selectedLibraryId: state.selectedLibraryId || report.usedLibraries[0]?.id || null,
            errorMessage: null,
            logs: silent
              ? state.logs
              : appendLogEntry(state.logs, {
                  source: "system",
                  message: "[report] 报告已加载。",
                }),
          }));

          saveLastTask(taskId);
          return report;
        } catch (error) {
          if (silent && error instanceof ApiError && error.status === 404) {
            return null;
          }

          const message = error instanceof Error ? error.message : "报告拉取失败";
          set((state) => ({
            ...state,
            errorMessage: message,
            taskStage: state.taskStage === "REPORT_READY" ? state.taskStage : "FAILED",
            logs: appendLogEntry(state.logs, {
              source: "system",
              message: `[error] ${message}`,
            }),
          }));
          throw error;
        }
      },

      connectExecution: async (taskId) => {
        clearRealtimeResources();
        saveLastTask(taskId);

        set((state) => ({
          ...state,
          currentTaskId: taskId,
          lastTaskId: taskId,
          errorMessage: null,
          wsState: "CONNECTING",
          taskStage: state.taskStage === "REPORT_READY" ? "REPORT_READY" : "QUEUED",
          historyTaskIds: uniqueTaskHistory(state.historyTaskIds, taskId),
          logs: appendLogEntry(state.logs, {
            source: "system",
            message: `[system] 正在恢复任务 ${taskId} 的执行上下文...`,
          }),
        }));

        const report = await get().ensureReport(taskId, true);
        if (report) {
          set((state) => ({
            ...state,
            wsState: "DISCONNECTED",
            taskStage: "REPORT_READY",
            logs: appendLogEntry(state.logs, {
              source: "system",
              message: "[system] 检测到报告已就绪，已恢复完成。",
            }),
          }));
          return;
        }

        activeSocket = createTaskLogSocket(taskId, {
          onOpen: () => {
            set((state) => ({
              ...state,
              wsState: "CONNECTED",
              taskStage: state.taskStage === "QUEUED" ? "SCANNING" : state.taskStage,
              logs: appendLogEntry(state.logs, {
                source: "socket",
                message: "[socket] 实时通道已连接。",
              }),
            }));
          },
          onStateChange: (socketState) => {
            set((state) => ({
              ...state,
              wsState:
                socketState === "CONNECTING"
                  ? "CONNECTING"
                  : socketState === "CONNECTED"
                    ? "CONNECTED"
                    : socketState === "RECONNECTING"
                      ? "RECONNECTING"
                      : "FAILED",
            }));
          },
          onRetry: (attempt, delayMs) => {
            set((state) => ({
              ...state,
              wsState: "RECONNECTING",
              logs: appendLogEntry(state.logs, {
                source: "socket",
                message: `[socket] 连接中断，第 ${attempt} 次重连将在 ${delayMs}ms 后进行。`,
              }),
            }));
          },
          onError: (message) => {
            set((state) => ({
              ...state,
              errorMessage: message,
            }));
          },
          onGiveUp: () => {
            set((state) => ({
              ...state,
              wsState: "FAILED",
              logs: appendLogEntry(state.logs, {
                source: "socket",
                message: "[socket] 重连失败，进入短轮询降级模式。",
              }),
            }));
            get().startPollingFallback(taskId);
          },
          onMessage: async (message) => {
            if (message.type === "meta") {
              set((state) => ({
                ...state,
                taskStage: mapBackendTaskStatusToStage(message.status),
                logs: appendLogEntry(state.logs, {
                  source: "meta",
                  message: `[meta] apk=${message.apk_name} status=${message.status}`,
                }),
              }));
              return;
            }

            if (message.type === "log") {
              const content = `${message.file ? `[${message.file}] ` : ""}${message.message || ""}`;
              const source = message.file?.includes("stderr") ? "stderr" : "stdout";
              set((state) => ({
                ...state,
                taskStage: state.taskStage === "QUEUED" ? "SCANNING" : state.taskStage,
                logs: appendLogEntry(state.logs, {
                  source,
                  message: content,
                }),
              }));
              return;
            }

            if (message.type === "error") {
              set((state) => ({
                ...state,
                taskStage: "FAILED",
                errorMessage: message.message,
                logs: appendLogEntry(state.logs, {
                  source: "socket",
                  message: `[error] ${message.message}`,
                }),
              }));
              return;
            }

            if (message.type === "done") {
              if (message.status === "completed") {
                set((state) => ({
                  ...state,
                  taskStage: "SCANNING",
                  logs: appendLogEntry(state.logs, {
                    source: "system",
                    message: "[scan] 任务完成，正在拉取报告...",
                  }),
                }));
                const loaded = await get().ensureReport(taskId, true);
                if (!loaded) {
                  get().startPollingFallback(taskId);
                }
              } else {
                const failMessage = message.error || "扫描失败";
                set((state) => ({
                  ...state,
                  taskStage: "FAILED",
                  errorMessage: failMessage,
                  logs: appendLogEntry(state.logs, {
                    source: "system",
                    message: `[error] ${failMessage}`,
                  }),
                }));
              }

              if (activeSocket) {
                activeSocket.close();
                activeSocket = null;
              }

              set((state) => ({
                ...state,
                wsState: state.taskStage === "REPORT_READY" ? "DISCONNECTED" : state.wsState,
              }));
            }
          },
        });

        activeSocket.connect();
      },

      stopRealtime: () => {
        clearRealtimeResources();
        set((state) => ({
          ...state,
          wsState: "DISCONNECTED",
          isPollingFallback: false,
        }));
      },

      startPollingFallback: (taskId) => {
        if (pollingTimer) {
          clearInterval(pollingTimer);
          pollingTimer = null;
        }

        let rounds = 0;
        set((state) => ({
          ...state,
          isPollingFallback: true,
          wsState: "DEGRADED",
          logs: appendLogEntry(state.logs, {
            source: "system",
            message: "[polling] 已切换短轮询，持续检查报告是否可用。",
          }),
        }));

        pollingTimer = setInterval(async () => {
          rounds += 1;
          const report = await get().ensureReport(taskId, true);
          if (report) {
            if (pollingTimer) {
              clearInterval(pollingTimer);
              pollingTimer = null;
            }
            set((state) => ({
              ...state,
              isPollingFallback: false,
              wsState: "DEGRADED",
              logs: appendLogEntry(state.logs, {
                source: "system",
                message: "[polling] 报告已就绪，恢复成功。",
              }),
            }));
            return;
          }

          if (rounds >= MAX_POLL_ROUNDS) {
            if (pollingTimer) {
              clearInterval(pollingTimer);
              pollingTimer = null;
            }
            set((state) => ({
              ...state,
              isPollingFallback: false,
              wsState: "FAILED",
              errorMessage: "轮询超时，报告仍未就绪。",
              taskStage: state.taskStage === "REPORT_READY" ? state.taskStage : "FAILED",
              logs: appendLogEntry(state.logs, {
                source: "system",
                message: "[polling] 降级轮询超时，请稍后手动进入报告页重试。",
              }),
            }));
          }
        }, POLL_INTERVAL_MS);
      },

      setActiveVulnerability: (id) => {
        set({ activeVulnerabilityId: id });
      },

      setSelectedLibrary: (id) => {
        set({ selectedLibraryId: id });
      },
    }),
    {
      name: "avh-task-store-v2",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        currentTaskId: state.currentTaskId,
        lastTaskId: state.lastTaskId,
        uploadContext: state.uploadContext,
        taskStage: state.taskStage,
        logs: state.logs.slice(-300),
        reportsByTask: state.reportsByTask,
        historyTaskIds: state.historyTaskIds,
        activeVulnerabilityId: state.activeVulnerabilityId,
        selectedLibraryId: state.selectedLibraryId,
      }),
    },
  ),
);
