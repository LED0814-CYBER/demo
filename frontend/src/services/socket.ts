import type { TaskLogMessageRaw } from "../types/contracts";

export interface TaskSocketCallbacks {
  onOpen?: () => void;
  onClose?: () => void;
  onMessage: (message: TaskLogMessageRaw) => void;
  onStateChange?: (state: "CONNECTING" | "CONNECTED" | "RECONNECTING" | "FAILED") => void;
  onRetry?: (attempt: number, delayMs: number) => void;
  onError?: (error: string) => void;
  onGiveUp?: () => void;
}

export interface TaskSocketOptions {
  maxRetries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
}

export interface TaskLogSocketController {
  connect: () => void;
  close: () => void;
}

function buildSocketUrl(taskId: string): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/api/logs?task_id=${encodeURIComponent(taskId)}`;
}

function parseSocketMessage(payload: unknown): TaskLogMessageRaw | null {
  if (!payload || typeof payload !== "object") return null;
  const candidate = payload as Partial<TaskLogMessageRaw>;
  if (!candidate.type || typeof candidate.type !== "string") return null;
  return candidate as TaskLogMessageRaw;
}

export function createTaskLogSocket(
  taskId: string,
  callbacks: TaskSocketCallbacks,
  options: TaskSocketOptions = {},
): TaskLogSocketController {
  const maxRetries = options.maxRetries ?? 5;
  const baseDelayMs = options.baseDelayMs ?? 900;
  const maxDelayMs = options.maxDelayMs ?? 6500;

  let socket: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let retries = 0;
  let manualClose = false;

  const connect = () => {
    if (manualClose) return;

    callbacks.onStateChange?.(retries === 0 ? "CONNECTING" : "RECONNECTING");

    socket = new WebSocket(buildSocketUrl(taskId));

    socket.onopen = () => {
      retries = 0;
      callbacks.onStateChange?.("CONNECTED");
      callbacks.onOpen?.();
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const parsed = parseSocketMessage(data);
        if (parsed) {
          callbacks.onMessage(parsed);
        }
      } catch {
        callbacks.onError?.("WebSocket 消息解析失败");
      }
    };

    socket.onerror = () => {
      callbacks.onError?.("WebSocket 连接出现异常");
    };

    socket.onclose = () => {
      callbacks.onClose?.();
      if (manualClose) return;

      if (retries >= maxRetries) {
        callbacks.onStateChange?.("FAILED");
        callbacks.onGiveUp?.();
        return;
      }

      retries += 1;
      const delay = Math.min(baseDelayMs * 2 ** (retries - 1), maxDelayMs);
      callbacks.onRetry?.(retries, delay);
      reconnectTimer = setTimeout(connect, delay);
    };
  };

  const close = () => {
    manualClose = true;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (socket && socket.readyState <= WebSocket.OPEN) {
      socket.close();
    }
    socket = null;
  };

  return {
    connect,
    close,
  };
}
