import Link from "next/link";
import { Shell } from "@/components/shell";
import { CatMark } from "@/components/marks";
import { formatDay, ledger } from "@/lib/ledger";

const sections = [
  ["regressed", "Regressed this period", "Passing at the previous milestone, failing now. The clock starts over."],
  ["new", "New this period", "Not in the previous export. Usually a new plugin or a host that just got scanned."],
  ["closed", "Closed this period", "Was failing, now passing. Keep the evidence of the fix with the POA&M row."],
  ["opened_since_baseline", "Opened since the baseline", "Clean at the first scan, failing before this month. Easy to miss if you only diff the last two files."],
  ["persistent", "Still open", "Failing then, failing now. These are the ones that age out."],
];

export default function DriftPage() {
  const { milestones } = ledger;
  return (
    <Shell>
      <h1 className="font-heading text-4xl text-[#f3ead2]">Drift</h1>
      <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
        Baseline {formatDay(milestones.baseline)}, previous {formatDay(milestones.previous)}, current{" "}
        {formatDay(milestones.current)}. A host that is missing from the later ACAS file is not marked closed. A plugin
        that disappears while the host is still in the file is.
      </p>
      <div className="mt-8 space-y-8">
        {sections.map(([key, title, help]) => {
          const rows = ledger.drift[key] ?? [];
          return (
            <section key={key}>
              <h2 className="font-heading text-2xl">{title}</h2>
              <p className="mt-1 text-sm text-muted-foreground">{help}</p>
              {rows.length === 0 ? (
                <p className="mt-3 text-sm">None.</p>
              ) : (
                <ul className="mt-3 space-y-2">
                  {rows.map((row) => (
                    <li key={row.slug} className="flex flex-wrap items-center gap-2 text-sm">
                      <Link href={`/findings/${row.slug}`} className="font-mono text-xs underline-offset-4 hover:underline">
                        {row.control}
                      </Link>
                      <span className="text-muted-foreground">{row.host.split(".")[0]}</span>
                      <CatMark cat={row.cat} />
                      <span>{row.title}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          );
        })}
      </div>
    </Shell>
  );
}
