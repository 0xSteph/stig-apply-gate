export type Clock = "overdue" | "due_soon" | "on_track" | "excepted" | "closed" | "not_reviewed" | string;

export type Remediation = {
  class: string;
  summary: string;
  why: string;
  verify: string;
  avoid: string;
};

export type Finding = {
  slug: string;
  host: string;
  host_short: string;
  platform: string;
  role: string;
  owner: string;
  control: string;
  rule_ver: string | null;
  vuln_num: string | null;
  rule_id: string | null;
  plugin_id: string | null;
  cve: string | null;
  title: string;
  benchmark: string;
  severity: string | null;
  severity_verified: boolean;
  severity_override: string | null;
  cat: string;
  cat_source: string;
  cci: string[];
  nist: string[];
  result: string;
  clock: Clock;
  flags: string[];
  regression: boolean;
  first_seen: string;
  last_seen: string;
  due: string | null;
  days_to_due: number | null;
  days_overdue: number;
  history: { date: string; result: string; sources: string[] }[];
  comments: string;
  detail: string;
  engineer_note: string;
  cvss: number | null;
  remediation: Remediation;
  exception_id: string | null;
  drift: string;
  apply_action: string | null;
  apply_reason: string | null;
};

export type ExceptionRow = {
  id: string;
  host: string;
  control: string;
  status: string;
  display_status: string;
  rationale: string;
  compensating: string;
  approver: string;
  approver_name: string;
  approved_on: string;
  expires: string;
  ticket: string;
  finding_slug: string | null;
};

export type Backup = {
  host: string;
  method: string;
  rpo_hours: number;
  rto_hours: number;
  last_success: string;
  last_restore_test: string;
  restore_test_max_days: number;
  notes: string;
  age_hours: number;
  restore_age_days: number;
  rpo_met: boolean;
  restore_met: boolean;
  status: string;
  reasons: string[];
};

export type Ledger = {
  tool: string;
  version: string;
  generated_for: string;
  site: { name: string; environment: string; description: string };
  policy: {
    sla_days: Record<string, number>;
    due_soon_days: number;
    regression_restarts_clock: boolean;
    exception_grace_days: number;
  };
  milestones: Record<string, string>;
  hosts: {
    hostname: string;
    platform: string;
    role: string;
    owner: string;
    address: string;
    window_note: string;
  }[];
  services: { name: string; host: string; runbook: string | null }[];
  findings: Finding[];
  exceptions: ExceptionRow[];
  drift: Record<string, { slug: string; host: string; control: string; title: string; cat: string }[]>;
  backups: Backup[];
  attention: {
    kind: string;
    slug: string;
    href: string;
    title: string;
    host: string;
    control: string;
    cat: string;
    clock: string;
    reason: string;
    due: string | null;
  }[];
  windows: {
    host: string;
    host_short: string;
    note: string;
    items: { slug: string; control: string; title: string; cat: string; clock: string; class: string; days_overdue: number }[];
  }[];
  brief: { paragraphs: string[] };
  handoff: { ready: boolean; gates: { id: string; title: string; status: string; detail: string }[] };
  apply_gate: {
    decisions: {
      host: string;
      host_short: string;
      control: string;
      slug: string;
      tag: string | null;
      action: string;
      label: string;
      reason: string;
    }[];
    unscanned: string[];
    counts: Record<string, number>;
  };
  stats: {
    open: number;
    overdue: number;
    due_soon: number;
    excepted: number;
    regressions: number;
    closed_this_period: number;
    by_cat: Record<string, { open: number; overdue: number }>;
  };
};
