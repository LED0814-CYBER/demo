import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/common/AppShell";
import { DashboardPage } from "./routes/DashboardPage";
import { ExecutionPage } from "./routes/ExecutionPage";
import { NewTaskPage } from "./routes/NewTaskPage";
import { ReportPage } from "./routes/ReportPage";

export default function App(): JSX.Element {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/task/new" element={<NewTaskPage />} />
        <Route path="/task/:taskId/execution" element={<ExecutionPage />} />
        <Route path="/report/:taskId" element={<ReportPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
