import Link from "next/link";
import { Shell } from "@/components/shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDay, ledger } from "@/lib/ledger";

export default function ExceptionsPage() {
  return (
    <Shell>
      <h1 className="font-heading text-4xl text-[#f3ead2]">Exceptions</h1>
      <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
        An approved exception pauses the clock until the end date. A pending one does not. The morning after the end
        date, the finding is open again and already due.
      </p>
      <div className="mt-6 grid gap-4">
        {ledger.exceptions.map((item) => (
          <Card key={item.id}>
            <CardHeader>
              <CardTitle className="flex flex-wrap items-baseline gap-3">
                <span className="font-mono text-sm">{item.id}</span>
                <span className="text-base capitalize">{item.display_status}</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm leading-relaxed">
              <p>
                {item.finding_slug ? (
                  <Link href={`/findings/${item.finding_slug}`} className="font-mono text-xs underline-offset-4 hover:underline">
                    {item.control}
                  </Link>
                ) : (
                  <span className="font-mono text-xs">{item.control}</span>
                )}
                <span className="text-muted-foreground"> on {item.host}</span>
              </p>
              <p>{item.rationale}</p>
              <p>
                <span className="text-muted-foreground">Compensating control: </span>
                {item.compensating}
              </p>
              <p className="text-muted-foreground">
                {item.approver_name ? `${item.approver_name} · ` : "Not signed · "}
                expires {formatDay(item.expires)} · {item.ticket}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </Shell>
  );
}
