const STORAGE_KEY = "avh:last-task";

export function saveLastTask(taskId: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, taskId);
  } catch {
    // ignore localStorage quota errors
  }
}

export function loadLastTask(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}
