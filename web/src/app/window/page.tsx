import { Shell } from "@/components/shell";
import windowReport from "@/data/window.json";

export default function WindowPage() {
  return (
    <Shell>
      <p className="text-xs tracking-[0.16em] text-muted-foreground uppercase">Isolated copy · {windowReport.as_of}</p>
      <h1 className="font-heading mt-2 text-4xl text-[#f3ead2]">Test window</h1>
      <div className="mt-4 max-w-3xl space-y-4 text-[15px] leading-relaxed text-muted-foreground">
        <p>
          Integration Lab is the only place a change is tried. The playbook inventory is this lab, and a host marked
          operations is refused even when the same change is allowed here. A maintenance window is the scheduled time
          to apply a change the lab already proved, with someone at the console and a rollback. It is not the time you
          find out whether the change is safe.
        </p>
        <p>
          The comparisons below were built from a copy of the lab records. They did not change{" "}
          <span className="font-mono text-sm">fixtures/lab</span>, the ledger this site reads, or the apply-gate file
          the playbook reads. Run <span className="font-mono text-sm">python -m findings rehearse</span> to do it
          again. Add <span className="font-mono text-sm">--publish</span> when this page should match that run.
        </p>
      </div>

      <section className="mt-10">
        <h2 className="font-heading text-2xl">Unchanged lab</h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Handoff on this record is {windowReport.handoff_ready ? "ready" : "not ready"}. Walk these before you change
          anything.
        </p>
        <ul className="mt-4 space-y-3">
          {windowReport.stories.map((story) => (
            <li key={`${story.host}-${story.control}`} className="rounded-xl border border-border px-4 py-3">
              <p className="text-sm font-medium">
                <span className="font-mono text-xs">{story.host_short}</span>
                <span> · {story.control} · {story.label}</span>
              </p>
              <p className="mt-1 text-sm text-muted-foreground">{story.point}</p>
              <p className="mt-1 text-sm">{story.reason}</p>
            </li>
          ))}
        </ul>
      </section>

      {windowReport.cases.map((item) => (
        <section key={item.id} className="mt-10">
          <h2 className="font-heading text-2xl">{item.title}</h2>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">{item.change}</p>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed">{item.meaning}</p>
          <ul className="mt-4 space-y-3">
            {item.rows.map((row) => (
              <li key={row.control} className="rounded-xl border border-border px-4 py-3">
                <p className="text-sm font-medium">
                  <span className="font-mono text-xs">{row.host_short}</span>
                  <span> · {row.control} · {row.before_label} to {row.after_label}</span>
                </p>
                <p className="mt-2 text-sm text-muted-foreground">Before: {row.before_reason}</p>
                <p className="mt-1 text-sm">After: {row.after_reason}</p>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </Shell>
  );
}
