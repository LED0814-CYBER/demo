import { useEffect, useMemo, useState } from "react";

import { buildCopilotNarrative, streamCopilotText } from "../utils/copilot";
import type { ReportModel, VulnerabilityModel } from "../types/domain";

export function useCopilotStream(vulnerability: VulnerabilityModel | null, report: ReportModel | null): string {
  const [text, setText] = useState("");

  const narrative = useMemo(() => buildCopilotNarrative(vulnerability, report), [vulnerability, report]);

  useEffect(() => {
    let stopped = false;

    const run = async () => {
      setText("");
      for await (const token of streamCopilotText(narrative)) {
        if (stopped) return;
        setText((prev) => prev + token);
      }
    };

    void run();

    return () => {
      stopped = true;
    };
  }, [narrative]);

  return text;
}
