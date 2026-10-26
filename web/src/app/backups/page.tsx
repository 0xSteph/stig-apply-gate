import { ClockMark } from "@/components/marks";
import { Shell } from "@/components/shell";
import { Badge } from "@/components/ui/badge";
import { formatDay, ledger } from "@/lib/ledger";
import type { Backup, RestoreTest } from "@/lib/types";
import { cn } from "cn";

function duration(minutes: number | null): string {
  if (minutes === null) return "not recorded";
  const hours = Math.floor(minutes / 60);
  const rest = Math.round(minutes % 60);
  if (hours && rest) return `${hours}h ${rest}m`;
  if (hours) return `${hours}h`;
  return `${rest}m`;
}

function RtoMark({ test, rtoHours }: { test: RestoreTest; rtoHours: number }) {
  const tone =
    test.rto_met === false ? "text-[#ffb4a2]" : test.rto_met === true ? "text-[#d5e2cf]" : "text-muted-foreground";
  const verdict = test.rto_met === false ? "missed" : test.rto_met === true ? "met" : "no RTO";
  return (
    <span className={cn("whitespace-nowrap", tone)}>
      {duration(test.duration_minutes)} / {rtoHours}h <span className="text-xs">{verdict}</span>
    </span>
  );
}

function ScopeMark({ test }: { test: RestoreTest }) {
  return (
    <Badge
      variant="outline"
      className={cn("font-mono text-[11px] tracking-normal", test.scope !== "full" && "border-[#f0d48a]/50 text-[#f0d48a]")}
    >
      {test.scope}
    </Badge>
  );
}

function ResultMark({ test }: { test: RestoreTest }) {
  return (
    <Badge
      className={cn(
        "border-transparent",
        test.result === "pass" ? "bg-[#1e2a22] text-[#d5e2cf]" : "bg-[#3a221c] text-[#ffb4a2]",
      )}
    >
      {test.result}
    </Badge>
  );
}

function restoreCell(item: Backup) {
  if (item.qualifying_test) {
    return (
      <>
        {formatDay(item.qualifying_test.date)}
        <p className="text-xs text-muted-foreground">{item.restore_age_days} days ago</p>
      </>
    );
  }
  if (item.restore_tests.length > 0) {
    return <p className="text-[#ffb4a2]">None qualifies</p>;
  }
  if (item.last_restore_test) {
    return (
      <>
        {formatDay(item.last_restore_test)}
        <p className="text-xs text-muted-foreground">{item.restore_age_days} days ago, scope not recorded</p>
      </>
    );
  }
  return <p className="text-[#ffb4a2]">None on record</p>;
}

const flagText: Record<string, string> = {
  restore_date_mismatch: "The recorded last restore date does not match the newest test entry. The entries were used.",
};

export default function BackupsPage() {
  return (
    <Shell>
      <h1 className="font-heading text-4xl text-[#f3ead2]">Backups</h1>
      <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
        RPO is measured to noon on the sample clock, so a nightly job that finished yesterday still counts. A restore
        test older than the policy does not. A successful backup job is not a restore test, and neither is a
        config-only or partial restore, or one that failed: only a full restore that passed resets the clock. RTO is
        read from how long the newest test actually took.
      </p>
      <div className="mt-6 overflow-x-auto">
        <table className="w-full min-w-[880px] text-sm">
          <thead className="text-left text-xs tracking-wide text-muted-foreground uppercase">
            <tr className="border-b border-border">
              <th className="py-2 pr-3 font-medium">Host</th>
              <th className="py-2 pr-3 font-medium">Method</th>
              <th className="py-2 pr-3 font-medium">RPO / RTO</th>
              <th className="py-2 pr-3 font-medium">Last good</th>
              <th className="py-2 pr-3 font-medium">Full restore test</th>
              <th className="py-2 pr-3 font-medium">Newest test</th>
              <th className="py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {ledger.backups.map((item) => (
              <tr key={item.host} className="border-b border-border/70 align-top">
                <td className="py-3 pr-3 font-mono text-xs">{item.host.split(".")[0]}</td>
                <td className="py-3 pr-3">
                  <p>{item.method}</p>
                  {item.reasons.length > 0 ? (
                    <ul className="mt-1 list-disc pl-4 text-muted-foreground">
                      {item.reasons.map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-1 text-muted-foreground">{item.notes}</p>
                  )}
                </td>
                <td className="py-3 pr-3 whitespace-nowrap">
                  {item.rpo_hours}h / {item.rto_hours}h
                </td>
                <td className="py-3 pr-3 whitespace-nowrap">{formatDay(item.last_success)}</td>
                <td className="py-3 pr-3 whitespace-nowrap">{restoreCell(item)}</td>
                <td className="py-3 pr-3">
                  {item.newest_test ? (
                    <div className="space-y-1">
                      <div className="flex flex-wrap gap-1">
                        <ScopeMark test={item.newest_test} />
                        <ResultMark test={item.newest_test} />
                      </div>
                      <RtoMark test={item.newest_test} rtoHours={item.rto_hours} />
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
                <td className="py-3">
                  <ClockMark clock={item.status === "ok" ? "on_track" : "breach"} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <section className="mt-8">
        <h2 className="font-heading text-2xl">Restore test history</h2>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
          Newest first. A row that does not count is still the record of what was tried.
        </p>
        <div className="mt-4 grid gap-6">
          {ledger.backups.map((item) => (
            <div key={item.host} className="rounded-lg border border-border p-4">
              <div className="flex flex-wrap items-baseline gap-3">
                <h3 className="font-mono text-sm">{item.host}</h3>
                <ClockMark clock={item.status === "ok" ? "on_track" : "breach"} />
                <span className="text-xs text-muted-foreground">
                  RTO {item.rto_hours}h · restore test every {item.restore_test_max_days} days
                </span>
              </div>
              {item.reasons.length > 0 ? (
                <ul className="mt-2 list-disc pl-4 text-sm text-muted-foreground">
                  {item.reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              ) : null}
              {item.flags.map((flag) => (
                <p key={flag} className="mt-2 text-sm text-[#f0d48a]">
                  <span className="font-mono text-xs">{flag}</span> {flagText[flag] ?? ""}
                </p>
              ))}
              {item.restore_tests.length > 0 ? (
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full min-w-[760px] text-sm">
                    <thead className="text-left text-xs tracking-wide text-muted-foreground uppercase">
                      <tr className="border-b border-border">
                        <th className="py-2 pr-3 font-medium">Date</th>
                        <th className="py-2 pr-3 font-medium">Scope</th>
                        <th className="py-2 pr-3 font-medium">Duration / RTO</th>
                        <th className="py-2 pr-3 font-medium">Result</th>
                        <th className="py-2 font-medium">Restored</th>
                      </tr>
                    </thead>
                    <tbody>
                      {item.restore_tests.map((test) => (
                        <tr key={`${test.date}-${test.scope}`} className="border-b border-border/70 align-top">
                          <td className="py-2 pr-3 whitespace-nowrap">
                            {formatDay(test.date)}
                            <p className="text-xs text-muted-foreground">
                              {test.qualifies ? "counts" : "does not count"}
                            </p>
                          </td>
                          <td className="py-2 pr-3">
                            <ScopeMark test={test} />
                          </td>
                          <td className="py-2 pr-3">
                            <RtoMark test={test} rtoHours={item.rto_hours} />
                          </td>
                          <td className="py-2 pr-3">
                            <ResultMark test={test} />
                          </td>
                          <td className="py-2">
                            <p>{test.restored}</p>
                            {test.notes ? <p className="text-muted-foreground">{test.notes}</p> : null}
                            <p className="text-xs text-muted-foreground">
                              {test.tester}
                              {test.ticket ? ` · ${test.ticket}` : ""}
                            </p>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="mt-2 text-sm text-muted-foreground">
                  No restore test entries. {item.last_restore_test ? `Last recorded date ${formatDay(item.last_restore_test)}.` : ""}
                </p>
              )}
            </div>
          ))}
        </div>
      </section>
    </Shell>
  );
}
