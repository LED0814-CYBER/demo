export function toSlug(input: string): string {
  return (input || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function buildVulnerabilityId(cveId: string, library: string): string {
  return `${toSlug(cveId)}::${toSlug(library)}`;
}

export function nowId(prefix = "id"): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}
