import type { UsedLibraryRaw } from "../../types/contracts";
import type { SeverityLevel, UsedLibraryModel } from "../../types/domain";
import { toSlug } from "../../utils/identity";

function parseCoordinates(libraryName: string): { group: string; artifact: string } {
  const [group, artifact] = libraryName.split(":");
  return {
    group: group || "unknown.group",
    artifact: artifact || libraryName || "unknown-artifact",
  };
}

export function adaptLibrary(
  raw: UsedLibraryRaw,
  vulnerabilityCount: number,
  maxSeverity: SeverityLevel,
): UsedLibraryModel {
  const libraryName = raw.library_name || "unknown:unknown";
  const parsed = parseCoordinates(libraryName);
  const version = raw.version || "-";
  const confidence = Number.isFinite(raw.similarity) ? Number(raw.similarity) : 0;

  return {
    id: `${toSlug(libraryName)}-${toSlug(version)}`,
    rawName: raw.raw_name || "",
    libraryName,
    group: parsed.group,
    artifact: parsed.artifact,
    version,
    confidence,
    vulnerabilityCount,
    maxSeverity,
  };
}
