import Link from "next/link";
import { Shell } from "@/components/shell";
import { CatMark, ClockMark, ClassMark } from "@/components/marks";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDay, ledger } from "@/lib/ledger";

export default function HomePage() {
  const { site, brief, stats, attention, windows, generated_for, policy } = ledger;
  const counts = [
    { label: "Past clock", value: stats.overdue, hint: "CAT timer already ran out" },
    { label: "Due soon", value: stats.due_soon, hint: `Inside ${policy.due_soon_days} days` },
    { label: "Regressions", value: stats.regressions, hint: "Was passing, now is not" },
    { label: "Excepted", value: stats.excepted, hint: "Signed, and still in force" },
  ];

  return (
    <Shell>
      <p className="text-xs tracking-[0.16em] text-muted-foreground uppercase">
        {site.environment} · sample clock {formatDay(generated_for)}
      </p>
      <h1 className="font-heading mt-2 text-4xl text-[#f3ead2] sm:text-5xl">{site.name}</h1>
      <p className="mt-3 max-w-3xl text-base leading-relaxed text-muted-foreground">{site.description}</p>

      <div className="mt-8 grid gap-4 lg:grid-cols-[1.5fr_0.9fr]">
        <Card>
          <CardHeader>
            <CardTitle className="font-heading text-2xl">Note for the ISSO</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-[15px] leading-relaxed">
            {brief.paragraphs.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </CardContent>
        </Card>
        <div className="grid grid-cols-2 gap-3">
          {counts.map((item) => (
            <Card key={item.label} size="sm">
              <CardHeader>
                <CardTitle className="text-xs tracking-wide text-muted-foreground uppercase">{item.label}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="font-heading text-4xl">{item.value}</p>
                <p className="mt-1 text-xs text-muted-foreground">{item.hint}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <section className="mt-10">
        <h2 className="font-heading text-2xl">This week</h2>
        <p className="mt-1 text-sm text-muted-foreground">Open rows are the ones that need a person, not another scan.</p>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="text-left text-xs tracking-wide text-muted-foreground uppercase">
              <tr className="border-b border-border">
                <th className="py-2 pr-3 font-medium">Host</th>
                <th className="py-2 pr-3 font-medium">Control</th>
                <th className="py-2 pr-3 font-medium">Why it is here</th>
                <th className="py-2 pr-3 font-medium">Clock</th>
                <th className="py-2 font-medium">Due</th>
              </tr>
            </thead>
            <tbody>
              {attention.map((row) => (
                <tr key={`${row.kind}-${row.slug}-${row.reason}`} className="border-b border-border/70">
                  <td className="py-3 pr-3 font-mono text-xs">{row.host}</td>
                  <td className="py-3 pr-3">
                    <Link href={row.href} className="font-medium underline-offset-4 hover:underline">
                      {row.control}
                    </Link>
                    <p className="mt-0.5 text-muted-foreground">{row.title}</p>
                  </td>
                  <td className="py-3 pr-3 text-muted-foreground">{row.reason}</td>
                  <td className="py-3 pr-3">
                    <span className="flex flex-wrap gap-1">
                      {row.cat ? <CatMark cat={row.cat} /> : null}
                      <ClockMark clock={row.clock} />
                    </span>
                  </td>
                  <td className="py-3 whitespace-nowrap">{formatDay(row.due)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-10">
        <h2 className="font-heading text-2xl">Will not apply</h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          The playbook stops on these rows. A scanner pass is not enough, and a signed exception is not a fix.
          {ledger.apply_gate.unscanned.length > 0
            ? ` No scan this period: ${ledger.apply_gate.unscanned.map((host) => host.split(".")[0]).join(", ")}.`
            : ""}
        </p>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="text-left text-xs tracking-wide text-muted-foreground uppercase">
              <tr className="border-b border-border">
                <th className="py-2 pr-3 font-medium">Host</th>
                <th className="py-2 pr-3 font-medium">Control</th>
                <th className="py-2 pr-3 font-medium">Stop</th>
                <th className="py-2 font-medium">Why the change does not run</th>
              </tr>
            </thead>
            <tbody>
              {ledger.apply_gate.decisions
                .filter((row) => row.action !== "allow")
                .map((row) => (
                  <tr key={`${row.slug}-${row.action}`} className="border-b border-border/70">
                    <td className="py-3 pr-3 font-mono text-xs">{row.host_short}</td>
                    <td className="py-3 pr-3">
                      <Link href={`/findings/${row.slug}`} className="font-mono text-xs underline-offset-4 hover:underline">
                        {row.control}
                      </Link>
                    </td>
                    <td className="py-3 pr-3">
                      <ClassMark value={row.label} />
                    </td>
                    <td className="py-3 text-muted-foreground">{row.reason}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-10">
        <h2 className="font-heading text-2xl">One visit per host</h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Schedule the change around the host, not around the scanner row. The oldest overdue work is first.
        </p>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          {windows.map((visit) => (
            <Card key={visit.host}>
              <CardHeader>
                <CardTitle className="font-mono text-base">{visit.host_short}</CardTitle>
                <p className="text-sm leading-relaxed text-muted-foreground">{visit.note}</p>
              </CardHeader>
              <CardContent className="space-y-3">
                {visit.items.map((item) => (
                  <div key={item.slug} className="flex flex-wrap items-center gap-2">
                    <Link href={`/findings/${item.slug}`} className="font-mono text-xs underline-offset-4 hover:underline">
                      {item.control}
                    </Link>
                    <CatMark cat={item.cat} />
                    <ClockMark clock={item.clock} />
                    <ClassMark value={item.class} />
                  </div>
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      </section>
    </Shell>
  );
}
