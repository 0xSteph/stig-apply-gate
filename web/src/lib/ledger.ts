import raw from "@/data/ledger.json";
import type { Finding, Ledger } from "./types";

export const ledger = raw as Ledger;

export function findingBySlug(slug: string): Finding | undefined {
  return ledger.findings.find((item) => item.slug === slug);
}

export function formatDay(value: string | null): string {
  if (!value) return "—";
  const [year, month, day] = value.slice(0, 10).split("-");
  const names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${Number(day)} ${names[Number(month) - 1]} ${year}`;
}
