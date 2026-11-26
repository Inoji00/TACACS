"""Declare launcher-created volumes external in an existing VM deployment."""

import json
import os
from pathlib import Path
import shutil
import tempfile
from uuid import uuid4

import local_appliance as local


def repair(directory):
    item = local.state(directory)
    path = directory / "compose.json"
    if path.is_symlink():
        raise ValueError("compose links forbidden")
    config = json.loads(path.read_text(encoding="utf-8"))
    changed = False
    for key in ("config", "runtime", "provision", "dbsecret", "admin"):
        volume = config["volumes"][key]
        name = item["project"] + "-" + key
        if (
            volume.get("name") != name
            or set(volume) - {"name", "external"}
            or type(volume.get("external", False)) is not bool
        ):
            raise ValueError("unexpected volume configuration")
        local.run(["docker", "volume", "inspect", name])
        changed = changed or not volume.get("external", False)
        volume["external"] = True
    if not changed:
        print("Volume declarations are already external.")
        return
    backup = directory / ("compose.json.before-external-" + uuid4().hex)
    shutil.copy2(path, backup)
    descriptor, temporary = tempfile.mkstemp(prefix=".compose-external-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o777)
        local.run(
            [
                "docker",
                "compose",
                "--project-name",
                item["project"],
                "-f",
                temporary,
                "config",
                "--quiet",
            ]
        )
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    print("External volume declarations updated. Backup: " + backup.name)


if __name__ == "__main__":
    repair(Path(__file__).resolve().parents[1] / "data" / "vm-appliance")
