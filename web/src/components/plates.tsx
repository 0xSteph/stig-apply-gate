import fs from "node:fs";
import path from "node:path";

function readPlate(name: string) {
  return fs.readFileSync(path.join(process.cwd(), "public", "figures", name), "utf8");
}

export function LabPlate() {
  return (
    <figure className="lab-plate mt-8">
      <div dangerouslySetInnerHTML={{ __html: readPlate("lab-site.svg") }} />
      <figcaption className="mt-3 max-w-3xl text-sm leading-relaxed text-muted-foreground">
        Plate 1. Integration Lab, drawn from the record. The time marks move between the domain controller and ESXi.
        Operations hosts are not on this plate.
      </figcaption>
    </figure>
  );
}

export function GatePlate() {
  return (
    <figure className="mt-2">
      <img
        src="/figures/gate.svg"
        alt="Plate 2. Exports enter the register. The apply gate can release a change into the lab. An operations host stays refused."
      />
      <figcaption className="mt-3 text-sm leading-relaxed text-muted-foreground">
        Plate 2. A change is tried in the lab. The same change stays refused on an operations host.
      </figcaption>
    </figure>
  );
}
