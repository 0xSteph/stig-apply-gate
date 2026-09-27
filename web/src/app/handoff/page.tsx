import { Shell } from "@/components/shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ledger } from "@/lib/ledger";

export default function HandoffPage() {
  const { handoff, services, hosts } = ledger;
  return (
    <Shell>
      <p className="text-xs tracking-[0.16em] text-muted-foreground uppercase">Steady state</p>
      <h1 className="font-heading mt-2 text-4xl text-[#f3ead2]">
        {handoff.ready ? "Ready to hand off" : "Not ready to hand off"}
      </h1>
      <p className="mt-3 max-w-3xl text-sm leading-relaxed text-muted-foreground">
        An authority to operate is the start of operations, not the end of the project. These gates are the list you
        walk with the ISSM before the people who built the lab stop being the people who run it.
      </p>
      <ul className="mt-6 space-y-3">
        {handoff.gates.map((gate) => (
          <li key={gate.id} className="rounded-xl border border-border px-4 py-3">
            <p className="text-sm font-medium">
              <span className={gate.status === "pass" ? "text-[#c9d7c4]" : "text-[#ffb4a2]"}>
                {gate.status === "pass" ? "Pass" : "Fail"}
              </span>
              <span> · {gate.title}</span>
            </p>
            <p className="mt-1 text-sm text-muted-foreground">{gate.detail}</p>
          </li>
        ))}
      </ul>

      <div className="mt-8 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Services</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {services.map((service) => (
              <p key={service.name}>
                {service.name}
                <span className="text-muted-foreground"> · {service.host.split(".")[0]} · </span>
                {service.runbook ? service.runbook : "no runbook"}
              </p>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Who owns the box</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {hosts.map((host) => (
              <p key={host.hostname}>
                <span className="font-mono text-xs">{host.hostname.split(".")[0]}</span>
                <span className="text-muted-foreground"> · {host.role} · {host.owner}</span>
              </p>
            ))}
          </CardContent>
        </Card>
      </div>
    </Shell>
  );
}
