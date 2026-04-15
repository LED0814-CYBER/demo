import * as echarts from "echarts";
import { useEffect, useMemo, useRef } from "react";

import type { UsedLibraryModel } from "../../types/domain";

interface SbomGraphProps {
  apkName: string;
  libraries: UsedLibraryModel[];
  selectedLibraryId: string | null;
  onSelectLibrary: (libraryId: string) => void;
}

export function SbomGraph({ apkName, libraries, selectedLibraryId, onSelectLibrary }: SbomGraphProps): JSX.Element {
  const holderRef = useRef<HTMLDivElement | null>(null);

  const graphData = useMemo(() => {
    const centerId = "apk-center";
    const nodes = [
      {
        id: centerId,
        name: apkName,
        symbolSize: 62,
        category: 0,
        value: 0,
        itemStyle: {
          color: "#0ea5e9",
        },
        label: {
          color: "#e0f2fe",
          fontWeight: 600,
        },
      },
      ...libraries.map((lib) => {
        const risk = lib.vulnerabilityCount > 0;
        return {
          id: lib.id,
          name: `${lib.artifact}\n${lib.version}`,
          category: risk ? 1 : 2,
          symbolSize: Math.max(24, 24 + lib.vulnerabilityCount * 7),
          value: lib.vulnerabilityCount,
          itemStyle: {
            color: selectedLibraryId === lib.id ? "#38bdf8" : risk ? "#f97316" : "#22c55e",
            borderColor: selectedLibraryId === lib.id ? "#bae6fd" : "#0b1120",
            borderWidth: selectedLibraryId === lib.id ? 2 : 1,
          },
        };
      }),
    ];

    const links = libraries.map((lib) => ({
      source: centerId,
      target: lib.id,
      lineStyle: {
        color: lib.vulnerabilityCount > 0 ? "#fb7185" : "#22c55e",
        width: lib.vulnerabilityCount > 0 ? 2 : 1,
        opacity: 0.65,
      },
    }));

    return { nodes, links };
  }, [apkName, libraries, selectedLibraryId]);

  useEffect(() => {
    if (!holderRef.current) return;

    const chart = echarts.init(holderRef.current);
    chart.setOption({
      backgroundColor: "transparent",
      tooltip: {
        trigger: "item",
      },
      series: [
        {
          type: "graph",
          layout: "force",
          roam: true,
          draggable: true,
          data: graphData.nodes,
          links: graphData.links,
          categories: [
            { name: "APK" },
            { name: "Risk" },
            { name: "Safe" },
          ],
          label: {
            show: true,
            position: "right",
            color: "#cbd5e1",
            fontSize: 11,
          },
          force: {
            repulsion: 260,
            gravity: 0.06,
            edgeLength: [80, 150],
          },
          emphasis: {
            focus: "adjacency",
            lineStyle: {
              width: 4,
            },
          },
        },
      ],
    });

    chart.on("click", (params) => {
      const id = params.data && typeof params.data === "object" ? String((params.data as { id?: string }).id || "") : "";
      if (id && id !== "apk-center") {
        onSelectLibrary(id);
      }
    });

    const resizeHandler = () => chart.resize();
    window.addEventListener("resize", resizeHandler);

    return () => {
      window.removeEventListener("resize", resizeHandler);
      chart.dispose();
    };
  }, [graphData, onSelectLibrary]);

  return <div ref={holderRef} className="h-[360px] w-full rounded-xl border border-slate-700/70 bg-slate-950/35" />;
}
