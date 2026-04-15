import { useEffect } from "react";

import { useTaskStore } from "../store/taskStore";

export function useTaskBootstrap(taskId: string | undefined): void {
  const connectExecution = useTaskStore((state) => state.connectExecution);

  useEffect(() => {
    if (!taskId) return;
    void connectExecution(taskId);
  }, [taskId, connectExecution]);
}
