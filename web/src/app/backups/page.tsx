import { ClockMark } from "@/components/marks";
import { Shell } from "@/components/shell";
import { formatDay, ledger } from "@/lib/ledger";

export default function BackupsPage() {
  return (
    <Shell>
      <h1 className="font-heading text-4xl text-[#f3ead2]">Backups</h1>
      <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
        RPO is measured to noon on the sample clock, so a nightly job that finished yesterday still counts. A restore
        test older than the policy does not. A successful backup job is not a restore test.
      </p>
      <div className="mt-6 overflow-x-auto">
        <table className="w-full min-w-[820px] text-sm">
          <thead className="text-left text-xs tracking-wide text-muted-foreground uppercase">
            <tr className="border-b border-border">
              <th className="py-2 pr-3 font-medium">Host</th>
              <th className="py-2 pr-3 font-medium">Method</th>
              <th className="py-2 pr-3 font-medium">RPO / RTO</th>
              <th className="py-2 pr-3 font-medium">Last good</th>
              <th className="py-2 pr-3 font-medium">Restore test</th>
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
                <td className="py-3 pr-3 whitespace-nowrap">
                  {formatDay(item.last_restore_test)}
                  <p className="text-xs text-muted-foreground">{item.restore_age_days} days ago</p>
                </td>
                <td className="py-3">
                  <ClockMark clock={item.status === "ok" ? "on_track" : "breach"} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}
