import Link from "next/link";
import { Shell } from "@/components/shell";
import { CatMark, ClassMark, ClockMark } from "@/components/marks";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { formatDay, ledger } from "@/lib/ledger";

type Search = Record<string, string | string[] | undefined>;

function one(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] ?? "" : value ?? "";
}

export default async function FindingsPage({ searchParams }: { searchParams: Promise<Search> }) {
  const params = await searchParams;
  const cat = one(params.cat);
  const clock = one(params.clock);
  const platform = one(params.platform);
  const klass = one(params.class);
  const q = one(params.q).trim().toLowerCase();
  const showClosed = one(params.closed) === "1";

  const rows = ledger.findings.filter((item) => {
    if (!showClosed && item.clock === "closed") return false;
    if (cat && item.cat !== cat) return false;
    if (clock && item.clock !== clock) return false;
    if (platform && item.platform !== platform) return false;
    if (klass && item.remediation.class !== klass) return false;
    if (!q) return true;
    const haystack = `${item.host} ${item.control} ${item.title} ${item.vuln_num ?? ""} ${item.cve ?? ""}`.toLowerCase();
    return haystack.includes(q);
  });

  const platforms = [...new Set(ledger.findings.map((item) => item.platform))];
  const classes = [...new Set(ledger.findings.map((item) => item.remediation.class))];

  return (
    <Shell>
      <h1 className="font-heading text-4xl text-[#f3ead2]">Findings</h1>
      <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
        {rows.length} shown. Closed results stay out of the way until you ask for them. CAT I is 30 days, CAT II is 90,
        CAT III is 365, unless the site policy file says otherwise.
      </p>

      <form className="mt-6 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-end" action="/findings">
        <label className="grid gap-1 text-xs text-muted-foreground">
          Search
          <Input name="q" defaultValue={one(params.q)} placeholder="Host, rule, CVE" className="w-full sm:w-56" />
        </label>
        <label className="grid gap-1 text-xs text-muted-foreground">
          CAT
          <select name="cat" defaultValue={cat} className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm">
            <option value="">Any</option>
            <option value="I">I</option>
            <option value="II">II</option>
            <option value="III">III</option>
          </select>
        </label>
        <label className="grid gap-1 text-xs text-muted-foreground">
          Clock
          <select name="clock" defaultValue={clock} className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm">
            <option value="">Any</option>
            <option value="overdue">Past clock</option>
            <option value="due_soon">Due soon</option>
            <option value="on_track">Inside clock</option>
            <option value="excepted">Excepted</option>
          </select>
        </label>
        <label className="grid gap-1 text-xs text-muted-foreground">
          Platform
          <select name="platform" defaultValue={platform} className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm">
            <option value="">Any</option>
            {platforms.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-1 text-xs text-muted-foreground">
          Class
          <select name="class" defaultValue={klass} className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm">
            <option value="">Any</option>
            {classes.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" name="closed" value="1" defaultChecked={showClosed} />
          Show closed
        </label>
        <Button type="submit" variant="secondary">
          Filter
        </Button>
        <Button variant="ghost" render={<Link href="/findings" />}>
          Clear
        </Button>
      </form>

      {rows.length === 0 ? (
        <p className="mt-10 text-muted-foreground">Nothing matches. Clear the filter or include closed results.</p>
      ) : (
        <div className="mt-6 overflow-x-auto">
          <table className="w-full min-w-[860px] text-sm">
            <thead className="text-left text-xs tracking-wide text-muted-foreground uppercase">
              <tr className="border-b border-border">
                <th className="py-2 pr-3 font-medium">Host</th>
                <th className="py-2 pr-3 font-medium">Control</th>
                <th className="py-2 pr-3 font-medium">Class</th>
                <th className="py-2 pr-3 font-medium">Clock</th>
                <th className="py-2 font-medium">Due</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.slug} className="border-b border-border/70">
                  <td className="py-3 pr-3 align-top">
                    <p className="font-mono text-xs">{item.host_short}</p>
                    <p className="text-xs text-muted-foreground">{item.platform}</p>
                  </td>
                  <td className="py-3 pr-3">
                    <Link href={`/findings/${item.slug}`} className="font-medium underline-offset-4 hover:underline">
                      {item.control}
                    </Link>
                    <p className="mt-0.5 max-w-xl text-muted-foreground">{item.title}</p>
                  </td>
                  <td className="py-3 pr-3 align-top">
                    <ClassMark value={item.remediation.class} />
                  </td>
                  <td className="py-3 pr-3 align-top">
                    <span className="flex flex-wrap gap-1">
                      <CatMark cat={item.cat} />
                      <ClockMark clock={item.clock} />
                    </span>
                  </td>
                  <td className="py-3 align-top whitespace-nowrap">{formatDay(item.due)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Shell>
  );
}
