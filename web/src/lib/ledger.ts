import raw from "@/data/ledger.json";
import type { ControlRow, Finding, Ledger } from "./types";

export const ledger = raw as Ledger;

export function findingBySlug(slug: string): Finding | undefined {
  return ledger.findings.find((item) => item.slug === slug);
}

export type ControlFamily = { family: string; controls: ControlRow[] };

// The ledger already sorts controls by family, then by number, with unmapped last.
export function controlFamilies(): ControlFamily[] {
  const families: ControlFamily[] = [];
  for (const row of ledger.controls ?? []) {
    const last = families[families.length - 1];
    if (last && last.family === row.family) last.controls.push(row);
    else families.push({ family: row.family, controls: [row] });
  }
  return families;
}

export function formatDay(value: string | null): string {
  if (!value) return "—";
  const [year, month, day] = value.slice(0, 10).split("-");
  const names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${Number(day)} ${names[Number(month) - 1]} ${year}`;
}
