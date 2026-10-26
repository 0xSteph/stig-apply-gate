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

export type RestoreScope = "full" | "partial" | "config-only" | string;

export type RestoreTest = {
  date: string;
  duration_minutes: number | null;
  // Derived from duration_minutes against the record's rto_hours. Null when either is missing.
  rto_met: boolean | null;
  restored: string;
  scope: RestoreScope;
  tester: string;
  result: "pass" | "fail" | string;
  ticket: string | null;
  notes: string;
  age_days: number;
  // A full restore that passed. Only these reset the restore-test clock.
  qualifies: boolean;
};

export type Backup = {
  host: string;
  method: string;
  rpo_hours: number;
  rto_hours: number;
  last_success: string;
  last_restore_test: string | null;
  restore_test_max_days: number;
  notes: string;
  restore_tests: RestoreTest[];
  newest_test: RestoreTest | null;
  qualifying_test: RestoreTest | null;
  age_hours: number;
  // Age of the newest qualifying test. Null when no test qualifies.
  restore_age_days: number | null;
  rpo_met: boolean;
  restore_met: boolean;
  // Null for a record that has a date but no restore test entries.
  restore_scope_ok: boolean | null;
  rto_met: boolean | null;
  status: string;
  reasons: string[];
  flags: string[];
};

export type ControlFinding = {
  slug: string;
  host: string;
  host_short: string;
  control: string;
  title: string;
  cat: string;
  clock: Clock;
  due: string | null;
  mapped_by: "reported" | "same_cci" | "no_cci" | "no_control" | string;
};

export type ControlRow = {
  control: string;
  family: string;
  ccis: string[];
  findings: ControlFinding[];
  open: number;
  overdue: number;
  due_soon: number;
  excepted: number;
  closed: number;
  worst_clock: Clock;
  open_all_excepted: boolean;
  earliest_due: string | null;
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
  controls: ControlRow[];
};
