"""Export an operator-sealed, powered-off local VM using VMware OVF Tool."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import re


def validate_template(source):
    """Reject known unsafe export dependencies; cannot inspect guest secrets."""
    text = source.read_text(encoding="utf-8-sig")
    settings = {}
    for line in text.splitlines():
        match = re.fullmatch(r'\s*([\w.:-]+)\s*=\s*"([^"\r\n]*)"\s*', line)
        if match:
            key, value = match.groups()
            key = key.lower()
            if key in settings:
                raise ValueError("duplicate VMX settings")
            settings[key] = value
    if settings.get("checkpoint.vmstate", ""):
        raise ValueError("suspended VM forbidden")
    disks = []
    for key, value in settings.items():
        if key.endswith(".filename") and value.lower().endswith(
            (".vmdk", ".iso", ".flp")
        ):
            if not value.lower().endswith(".vmdk"):
                raise ValueError("detach installation and seed media")
            disk = (source.parent / value).resolve(strict=True)
            if not disk.is_relative_to(source.parent.resolve()):
                raise ValueError("external disk forbidden")
            if re.search(r"-\d{6}\.vmdk$", disk.name, re.I):
                raise ValueError("snapshot disk forbidden")
            disks.append(disk)
    if not disks:
        raise ValueError("boot disk required")


def export_command(tool, source, output):
    source = Path(source).resolve(strict=True)
    output = Path(output).resolve()
    if source.suffix.lower() != ".vmx" or output.suffix.lower() != ".ova":
        raise ValueError("local VMX source and OVA target required")
    if output.exists() or output.with_suffix(".ova.sha256").exists():
        raise FileExistsError("existing release must not be overwritten")
    if list(source.parent.glob("*.lck")):
        raise ValueError("VM appears locked; shut down before exporting")
    if not output.parent.is_dir():
        raise ValueError("output directory must already exist")
    validate_template(source)
    return [str(tool), "--shaAlgorithm=SHA256", str(source), str(output)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ovftool", required=True, type=Path)
    parser.add_argument("--vmx", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--sealed-template",
        action="store_true",
        help="Attest: no deployment data, credentials, fixed IP or active VM",
    )
    args = parser.parse_args()
    if not args.sealed_template:
        parser.error("operator sealing checklist must be completed first")
    tool = args.ovftool.resolve(strict=True)
    command = export_command(tool, args.vmx, args.output)
    subprocess.run(command, check=True)
    target = args.output.resolve(strict=True)
    # Validate package structure/manifest, not boot or appliance functionality.
    subprocess.run([str(tool), "--verifyOnly", str(target)], check=True)
    digest = hashlib.sha256()
    with target.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    target.with_suffix(".ova.sha256").write_text(
        f"{digest.hexdigest()}  {target.name}\n", encoding="ascii"
    )
    print(
        "OVA exported and OVF Tool verification passed. Import/boot/AAA acceptance still required."
    )


if __name__ == "__main__":
    main()
