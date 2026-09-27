"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "cn";

const links = [
  { href: "/", label: "Overview" },
  { href: "/findings", label: "Findings" },
  { href: "/drift", label: "Drift" },
  { href: "/exceptions", label: "Exceptions" },
  { href: "/backups", label: "Backups" },
  { href: "/handoff", label: "Handoff" },
  { href: "/window", label: "Test window" },
  { href: "/method", label: "How this works" },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  return (
    <div className="min-h-screen">
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-4 sm:px-6">
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <Link href="/" className="font-heading text-2xl tracking-tight text-[#f3ead2] sm:text-3xl">
              Findings Register
            </Link>
            <p className="text-right text-xs text-muted-foreground">
              Offline
              <span className="hidden sm:inline"> · no scanner, no AI, no host changes</span>
            </p>
          </div>
          <nav className="flex gap-1 overflow-x-auto pb-1">
            {links.map((link) => {
              const active = link.href === "/" ? pathname === "/" : pathname.startsWith(link.href);
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={cn(
                    "shrink-0 rounded-full px-3 py-1.5 text-sm text-muted-foreground",
                    active && "bg-secondary text-foreground"
                  )}
                >
                  {link.label}
                </Link>
              );
            })}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6">{children}</main>
    </div>
  );
}
