import Link from "next/link";
import { notFound } from "next/navigation";
import { ExceptionDraft } from "@/components/exception-draft";
import { CatMark, ClassMark, ClockMark } from "@/components/marks";
import { Shell } from "@/components/shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { findingBySlug, formatDay, ledger } from "@/lib/ledger";

export default async function FindingPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const finding = findingBySlug(slug);
  if (!finding) notFound();
  const exception = ledger.exceptions.find((item) => item.id === finding.exception_id);
  const decision = ledger.apply_gate.decisions.find((item) => item.slug === finding.slug);

  return (
    <Shell>
      <p className="text-xs text-muted-foreground">
        <Link href="/findings" className="underline-offset-4 hover:underline">
          Findings
        </Link>
        <span> / {finding.host_short}</span>
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <CatMark cat={finding.cat} />
        <ClockMark clock={finding.clock} />
        <ClassMark value={finding.remediation.class} />
        {finding.regression ? <ClassMark value="regression" /> : null}
        {finding.flags.includes("severity_unverified") ? <ClassMark value="confirm severity" /> : null}
      </div>
      <h1 className="font-heading mt-3 text-3xl text-[#f3ead2] sm:text-4xl">{finding.title}</h1>
      {decision && decision.action !== "allow" ? (
        <p className="mt-3 max-w-3xl text-sm leading-relaxed">
          <ClassMark value={decision.label} /> <span className="text-muted-foreground">{decision.reason}</span>
        </p>
      ) : null}
      <p className="mt-2 font-mono text-sm text-muted-foreground">
        {finding.control}
        {finding.vuln_num ? ` · ${finding.vuln_num}` : ""}
        {finding.rule_id ? ` · ${finding.rule_id}` : ""}
        {finding.cve ? ` · ${finding.cve}` : ""}
        {finding.plugin_id ? ` · plugin ${finding.plugin_id}` : ""}
      </p>

      <div className="mt-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <Card>
          <CardHeader>
            <CardTitle>What to do</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm leading-relaxed">
            <p>{finding.remediation.summary}</p>
            <p>{finding.remediation.why}</p>
            <p>
              <span className="text-muted-foreground">Do not: </span>
              {finding.remediation.avoid}
            </p>
            <p className="font-mono text-xs text-muted-foreground">Verify: {finding.remediation.verify}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Clock</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>Host {finding.host}</p>
            <p className="text-muted-foreground">{finding.role}</p>
            <p>Opened {formatDay(finding.first_seen)}</p>
            <p>Last seen {formatDay(finding.last_seen)}</p>
            <p>Due {formatDay(finding.due)}</p>
            {finding.days_overdue > 0 ? <p>{finding.days_overdue} days past due</p> : null}
            <p className="text-muted-foreground">
              Category came from {finding.cat_source === "stig" ? "the benchmark severity" : finding.cat_source}.
              {!finding.severity_verified ? " The severity on this row was not re-checked against the current STIG release." : ""}
            </p>
            {finding.cci.length > 0 ? <p className="font-mono text-xs">{finding.cci.join(" ")}</p> : null}
          </CardContent>
        </Card>
      </div>

      <section className="mt-6">
        <h2 className="font-heading text-2xl">Scan history</h2>
        <ol className="mt-3 flex flex-wrap gap-2">
          {finding.history.map((point) => (
            <li key={`${point.date}-${point.result}`} className="rounded-lg border border-border px-3 py-2 text-sm">
              <p className="font-mono text-xs">{formatDay(point.date)}</p>
              <p>{point.result}</p>
              <p className="text-xs text-muted-foreground">{point.sources.join(", ")}</p>
            </li>
          ))}
        </ol>
        {finding.comments ? <p className="mt-4 max-w-3xl text-sm leading-relaxed">{finding.comments}</p> : null}
        {finding.detail && finding.detail !== finding.comments ? (
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">{finding.detail}</p>
        ) : null}
      </section>

      <section className="mt-8">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-heading text-2xl">Exception</h2>
          <ExceptionDraft host={finding.host} control={finding.control} />
        </div>
        {exception ? (
          <Card className="mt-4">
            <CardHeader>
              <CardTitle>
                {exception.id} · {exception.display_status}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm leading-relaxed">
              <p>{exception.rationale}</p>
              <p>
                <span className="text-muted-foreground">Compensating control: </span>
                {exception.compensating}
              </p>
              <p className="text-muted-foreground">
                {exception.approver_name ? `${exception.approver_name}, ` : ""}
                {exception.approver || "unsigned"} · expires {formatDay(exception.expires)} · {exception.ticket}
              </p>
            </CardContent>
          </Card>
        ) : (
          <p className="mt-3 text-sm text-muted-foreground">No exception is on file. The clock keeps running.</p>
        )}
      </section>
    </Shell>
  );
}
