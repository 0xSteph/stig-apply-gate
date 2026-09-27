"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

type Draft = {
  rationale: string;
  compensating: string;
  expires: string;
  ticket: string;
};

const empty: Draft = { rationale: "", compensating: "", expires: "", ticket: "" };

export function ExceptionDraft({ host, control }: { host: string; control: string }) {
  const storageKey = `register-draft:${host}:${control}`;
  const [draft, setDraft] = useState<Draft>(empty);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) return;
    try {
      setDraft({ ...empty, ...JSON.parse(raw) });
    } catch {
      setDraft(empty);
    }
  }, [storageKey]);

  const record = {
    id: "EX-DRAFT",
    host,
    control,
    status: "pending",
    rationale: draft.rationale,
    compensating: draft.compensating,
    approver: "ISSO",
    approver_name: "",
    approved_on: "",
    expires: draft.expires,
    ticket: draft.ticket,
  };

  return (
    <Dialog>
      <DialogTrigger render={<Button variant="outline" />}>Draft an exception</DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Exception draft</DialogTitle>
          <DialogDescription>
            This stays in this browser. A draft is not an accepted exception. Paste it into the exceptions file and
            re-run the register when the ISSO has signed.
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            window.localStorage.setItem(storageKey, JSON.stringify(draft));
            setSaved(true);
          }}
        >
          <label className="grid gap-1 text-sm">
            Why the control cannot be closed yet
            <Input
              value={draft.rationale}
              onChange={(event) => setDraft({ ...draft, rationale: event.target.value })}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            Compensating control
            <Input
              value={draft.compensating}
              onChange={(event) => setDraft({ ...draft, compensating: event.target.value })}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            Requested end date
            <Input
              type="date"
              value={draft.expires}
              onChange={(event) => setDraft({ ...draft, expires: event.target.value })}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            Change ticket
            <Input value={draft.ticket} onChange={(event) => setDraft({ ...draft, ticket: event.target.value })} />
          </label>
          <DialogFooter>
            <Button type="submit">Keep on this browser</Button>
          </DialogFooter>
        </form>
        {saved && (
          <pre className="max-h-48 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs">
            {JSON.stringify(record, null, 2)}
          </pre>
        )}
      </DialogContent>
    </Dialog>
  );
}
