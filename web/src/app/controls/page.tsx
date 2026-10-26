import Link from "next/link";
import { Shell } from "@/components/shell";
import { CatMark, ClockMark } from "@/components/marks";
import { controlFamilies, formatDay } from "@/lib/ledger";

const familyNames: Record<string, string> = {
  AC: "Access Control",
  AT: "Awareness and Training",
  AU: "Audit and Accountability",
  CA: "Assessment, Authorization, and Monitoring",
  CM: "Configuration Management",
  CP: "Contingency Planning",
  IA: "Identification and Authentication",
  IR: "Incident Response",
  MA: "Maintenance",
  MP: "Media Protection",
  PE: "Physical and Environmental Protection",
  PL: "Planning",
  PM: "Program Management",
  PS: "Personnel Security",
  PT: "PII Processing and Transparency",
  RA: "Risk Assessment",
  SA: "System and Services Acquisition",
  SC: "System and Communications Protection",
  SI: "System and Information Integrity",
  SR: "Supply Chain Risk Management",
};

export default function ControlsPage() {
  const families = controlFamilies();
  return (
    <Shell>
      <h1 className="font-heading text-4xl text-[#f3ead2]">Controls</h1>
      <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
        The NIST SP 800-53 controls behind the CCIs the scanners reported. A checklist row has a CCI but no control id,
        so it takes the control another scan reported for the same CCI. A finding with no CCI, or with a CCI no scan tied
        to a control, is listed under Unmapped. Open counts include excepted rows.
      </p>

      {families.length === 0 ? (
        <p className="mt-10 text-muted-foreground">No findings in this ledger.</p>
      ) : (
        <div className="mt-8 space-y-10">
          {families.map(({ family, controls }) => {
            const open = controls.reduce((sum, row) => sum + row.open, 0);
            const overdue = controls.reduce((sum, row) => sum + row.overdue, 0);
            const excepted = controls.reduce((sum, row) => sum + row.excepted, 0);
            const unmapped = family === "unmapped";
            return (
              <section key={family}>
                <h2 className="flex flex-wrap items-baseline gap-3 font-heading text-2xl">
                  {unmapped ? (
                    "Unmapped"
                  ) : (
                    <>
                      <span>{family}</span>
                      <span className="text-base text-muted-foreground">{familyNames[family] ?? ""}</span>
                    </>
                  )}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  {unmapped
                    ? `No control to file these under. ${open} open, ${overdue} past clock, ${excepted} excepted.`
                    : `${controls.length} ${controls.length === 1 ? "control" : "controls"}. ${open} open, ${overdue} past clock, ${excepted} excepted.`}
                </p>
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full min-w-[860px] text-sm">
                    <thead className="text-left text-xs tracking-wide text-muted-foreground uppercase">
                      <tr className="border-b border-border">
                        <th className="py-2 pr-3 font-medium">Control</th>
                        <th className="py-2 pr-3 font-medium">Worst clock</th>
                        <th className="py-2 pr-3 text-right font-medium">Open</th>
                        <th className="py-2 pr-3 text-right font-medium">Past clock</th>
                        <th className="py-2 pr-3 text-right font-medium">Excepted</th>
                        <th className="py-2 pr-3 font-medium">Earliest due</th>
                        <th className="py-2 font-medium">Findings</th>
                      </tr>
                    </thead>
                    <tbody>
                      {controls.map((row) => (
                        <tr key={row.control} className="border-b border-border/70">
                          <td className="py-3 pr-3 align-top">
                            <p className="font-mono text-xs">{unmapped ? "—" : row.control}</p>
                            <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                              {row.ccis.length ? row.ccis.join(" ") : "no CCI"}
                            </p>
                          </td>
                          <td className="py-3 pr-3 align-top">
                            <ClockMark clock={row.worst_clock} />
                            {row.open_all_excepted ? (
                              <p className="mt-1 text-xs text-muted-foreground">Every open row is excepted</p>
                            ) : null}
                          </td>
                          <td className="py-3 pr-3 text-right align-top tabular-nums">{row.open}</td>
                          <td className="py-3 pr-3 text-right align-top tabular-nums">{row.overdue}</td>
                          <td className="py-3 pr-3 text-right align-top tabular-nums">{row.excepted}</td>
                          <td className="py-3 pr-3 align-top whitespace-nowrap">{formatDay(row.earliest_due)}</td>
                          <td className="py-3 align-top">
                            <ul className="space-y-1.5">
                              {row.findings.map((item) => (
                                <li key={item.slug} className="flex flex-wrap items-center gap-2">
                                  <Link
                                    href={`/findings/${item.slug}`}
                                    className="font-mono text-xs underline-offset-4 hover:underline"
                                  >
                                    {item.control}
                                  </Link>
                                  <span className="text-xs text-muted-foreground">{item.host_short}</span>
                                  <CatMark cat={item.cat} />
                                  <ClockMark clock={item.clock} />
                                  {item.mapped_by === "same_cci" ? (
                                    <span className="text-xs text-muted-foreground">control from CCI</span>
                                  ) : null}
                                </li>
                              ))}
                            </ul>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            );
          })}
        </div>
      )}
    </Shell>
  );
}
