import { Shell } from "@/components/shell";

export default function MethodPage() {
  return (
    <Shell>
      <h1 className="font-heading text-4xl text-[#f3ead2]">How this works</h1>
      <div className="mt-6 max-w-3xl space-y-8 text-[15px] leading-relaxed">
        <section className="space-y-4">
          <h2 className="font-heading text-2xl">What this is</h2>
          <p>
            A register of findings you already have. SCC, OpenSCAP, STIG Viewer, ACAS, and Evaluate-STIG produce the
            exports. eMASS and a spreadsheet already track what was applied and what is late. This page does that
            transcription for a lab that has the files and does not have them in one place: which row is still open,
            which CAT clock it is on, and whether the fix is safe to hand to Ansible.
          </p>
          <p>
            It does not scan a host, and it does not log into one. The sample is Integration Lab, an unclassified
            stand-in: a domain controller that also does DNS and DHCP, a WSUS server, a RHEL repository, one mission
            host, and vSphere. Rule identifiers that include a vulnerability number are public STIG identifiers. Titles
            and results were written for this lab.
          </p>
        </section>

        <section className="space-y-4">
          <h2 className="font-heading text-2xl">No AI</h2>
          <p>
            Nothing on this page calls a model. The clocks are calendar arithmetic on the dates in the export. A
            checklist row and an XCCDF result join when they share a rule id, a vulnerability number, or a CVE. If a
            value is missing, the row is marked unverified instead of being filled in.
          </p>
        </section>

        <section className="space-y-4">
          <h2 className="font-heading text-2xl">When a file will not read</h2>
          <p>
            The command stops, names the file, and writes no ledger. A failed file is not a host that passed.
          </p>
          <ul className="list-disc space-y-2 pl-5">
            <li>Broken XML, or an XCCDF file that is only the benchmark and has no results.</li>
            <li>A checklist or CSV with no findings.</li>
            <li>A CSV with no Host column, or a row whose host cell is blank. The message includes the headers it saw. A <span className="font-mono text-sm">.nessus</span> file has to be exported to CSV first.</li>
            <li>A result value other than Open, NotAFinding, Not_Applicable, Not_Reviewed, pass, or fail.</li>
          </ul>
          <p>Re-export the file and rerun. The register does not guess a column or a status.</p>
        </section>

        <section className="space-y-4">
          <h2 className="font-heading text-2xl">The playbook stops</h2>
          <p>
            A stock STIG role ships the controls turned on. Someone is supposed to remember which ones to skip. This
            register writes an apply gate, and the play reads it before it edits a file.
          </p>
          <ul className="list-disc space-y-2 pl-5">
            <li>A signed exception still in force. The stop lifts the day after it expires.</li>
            <li>Two hosts taking time from each other. Fixing either side leaves the loop.</li>
            <li>A backup outside its RPO or restore-test window, when the change restarts a service or removes a feature.</li>
            <li>A check that would pass with a value that is not true, such as a syslog target with nobody listening.</li>
            <li>A client that passes while the repo it installs from still fails the same check.</li>
            <li>A signing key that is not imported. The play runs the check even on a dry run, and stops if the key is missing.</li>
            <li>One of several changes that restart the same service. They land together, or the restart does not run.</li>
            <li>A host in the inventory with no scan this period. It is not treated as clean.</li>
          </ul>
        </section>

        <section className="space-y-4">
          <h2 className="font-heading text-2xl">Try a change without applying it</h2>
          <p>
            <span className="font-mono text-sm">ansible-playbook --check --diff</span> on one host, limited to the
            tags marked automate. Those modules support check mode, so the run prints the diff and does not write the
            files or the backup. <span className="font-mono text-sm">ssh-root</span> and{" "}
            <span className="font-mono text-sm">audit</span> stay out of that run: one restarts sshd, the other
            installs a package.
          </p>
        </section>

        <section className="space-y-4">
          <h2 className="font-heading text-2xl">Put a change back</h2>
          <p>
            On a real run, the role first copies the repo files, <span className="font-mono text-sm">dnf.conf</span>,{" "}
            <span className="font-mono text-sm">pwquality.conf</span>, and <span className="font-mono text-sm">sshd_config</span>{" "}
            under <span className="font-mono text-sm">/var/backups/findings-register/</span>.{" "}
            <span className="font-mono text-sm">ansible/revert.yml</span> puts those files back. It does not restart
            sshd, and it does not remove the audit package.
          </p>
          <p>
            On Windows, the script with no switches only reports. <span className="font-mono text-sm">-Apply</span>{" "}
            saves whether FS-SMB1 was installed, then removes it. <span className="font-mono text-sm">-Revert</span>{" "}
            reinstalls it only when that saved state says it was installed. The two switches together are refused.
            Password length is never written on a domain member. That fix is the GPO.
          </p>
        </section>

        <section className="space-y-4">
          <h2 className="font-heading text-2xl">When something breaks</h2>
          <ul className="list-disc space-y-2 pl-5">
            <li>Turning on GPG checks stops installs when the key was never imported. Revert the repo files, or import the key.</li>
            <li>Restarting sshd drops the session that restarted it. Do that from the console. Revert restores the file and leaves the daemon alone until you restart it on purpose.</li>
            <li>Removing SMBv1 wants a reboot. Revert puts the feature back and warns about that reboot. It cannot undo a reboot that already happened.</li>
            <li>The domain controller time finding is a loop with ESXi. Automating either side makes the other worse.</li>
            <li>ESXi SSH stays up while the signed break-glass exception is in force. Stopping it would pass the scanner and violate the signature.</li>
          </ul>
        </section>

        <section className="space-y-4">
          <h2 className="font-heading text-2xl">What the sample is arguing</h2>
          <ul className="list-disc space-y-2 pl-5">
            <li>The oldest CAT I is a repository GPG check. It is safe to automate, and it fails closed if the key was never imported.</li>
            <li>SMBv1 on WSUS was an approved exception through 1 Sep. The exception ended. The feature is still installed, so the row is late.</li>
            <li>The mission host wants one bench visit: OpenSSH, the audit package, and PermitRootLogin, then a single sshd restart. Three restarts is how you drop the only path to the box.</li>
            <li>Empty syslog is an honest failure. Pointing logHost at a collector that does not exist is a false pass.</li>
            <li>Password length on the member server is a GPO link, not a local secedit. The domain controller already passes.</li>
            <li>Two Windows severities are marked unverified. Guessing a CAT to look complete is worse than saying the current STIG release is still needed.</li>
          </ul>
          <p>
            The handoff page is supposed to be red. Integration Lab is not ready to leave the people who built it. CAT I
            items are late, an exception expired, the audit regression has no engineer note, WSUS missed its RPO, the
            ESXi restore test is old, and DHCP and vCenter have no runbook.
          </p>
          <p>
            Clocks are calendar days from the current failing streak. A regression restarts the clock. Vulnerability
            categories come from CVSS (7.0 and above is CAT I, 4.0 and above is CAT II) and are separate from STIG
            severities. Both mappings live in <span className="font-mono text-sm">policy/default.json</span> because
            every ISSM writes them down differently.
          </p>
        </section>
      </div>
    </Shell>
  );
}
