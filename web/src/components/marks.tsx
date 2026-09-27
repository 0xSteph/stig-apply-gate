import { Badge } from "@/components/ui/badge";
import { cn } from "cn";

const clockClass: Record<string, string> = {
  overdue: "bg-[#3a221c] text-[#ffb4a2]",
  due_soon: "bg-[#3a3114] text-[#f0d48a]",
  on_track: "bg-[#1e2a22] text-[#d5e2cf]",
  excepted: "bg-[#1c2830] text-[#c5dff0]",
  closed: "bg-[#262626] text-[#bdbdbd]",
  not_reviewed: "bg-[#262626] text-[#bdbdbd]",
  breach: "bg-[#3a221c] text-[#ffb4a2]",
};

const clockLabel: Record<string, string> = {
  overdue: "Past clock",
  due_soon: "Due soon",
  on_track: "Inside clock",
  excepted: "Excepted",
  closed: "Closed",
  not_reviewed: "Not reviewed",
  breach: "Breach",
};

export function ClockMark({ clock }: { clock: string }) {
  return (
    <Badge className={cn("border-transparent", clockClass[clock] ?? clockClass.not_reviewed)}>
      {clockLabel[clock] ?? clock}
    </Badge>
  );
}

export function CatMark({ cat }: { cat: string }) {
  if (!cat) return null;
  const tone =
    cat === "I" ? "bg-[#3a221c] text-[#ffb4a2]" : cat === "II" ? "bg-[#3a3114] text-[#f0d48a]" : "bg-[#1e2a22] text-[#d5e2cf]";
  return <Badge className={cn("border-transparent", tone)}>CAT {cat}</Badge>;
}

export function ClassMark({ value }: { value: string }) {
  return (
    <Badge variant="outline" className="font-mono text-[11px] tracking-normal">
      {value}
    </Badge>
  );
}
