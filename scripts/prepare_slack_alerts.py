"""Attach protected alert storage to an existing deployment before Web update."""

import json
import os
from pathlib import Path
import shutil
import tempfile
from uuid import uuid4

import local_appliance as local


def prepare(directory):
    item = local.state(directory)
    path = directory / "compose.json"
    if path.is_symlink():
        raise ValueError("compose links forbidden")
    config = json.loads(path.read_text(encoding="utf-8"))
    admin = config["services"]["admin"]
    image = admin["image"]
    expected = {"name": item["project"] + "-alerts", "external": True}
    existing = config.setdefault("volumes", {}).get("alerts")
    if existing is not None and existing != expected:
        raise ValueError("unexpected alert volume declaration")
    mounts = admin["volumes"]
    for mount in mounts:
        if not isinstance(mount, str):
            raise ValueError("unexpected mount format")
        if "/run/tnac-alerts" in mount and mount != "alerts:/run/tnac-alerts":
            raise ValueError("unexpected alert mount")
    local.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            image,
            "python",
            "-c",
            "from tacacs_appliance.alert_storage import AlertStorage",
        ]
    )
    local.run(["docker", "volume", "create", expected["name"]])
    volume = json.loads(
        local.run(["docker", "volume", "inspect", expected["name"]]).stdout
    )[0]
    if volume.get("Driver") != "local" or volume.get("Scope") != "local":
        raise ValueError("local alert volume required")
    local.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "--security-opt",
            "no-new-privileges",
            "--mount",
            "type=volume,source=" + expected["name"] + ",target=/run/tnac-alerts",
            image,
            "python",
            "-c",
            'import os; os.chmod("/run/tnac-alerts",0o700); os.chown("/run/tnac-alerts",10001,10001)',
        ]
    )
    if existing == expected and "alerts:/run/tnac-alerts" in mounts:
        print("Slack alert storage is already attached.")
        return
    config["volumes"]["alerts"] = expected
    if "alerts:/run/tnac-alerts" not in mounts:
        mounts.append("alerts:/run/tnac-alerts")
    backup = directory / ("compose.json.before-slack-" + uuid4().hex)
    shutil.copy2(path, backup)
    descriptor, temporary = tempfile.mkstemp(prefix=".compose-slack-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2)
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
    print("Slack alert storage attached. Backup: " + backup.name)


if __name__ == "__main__":
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise SystemExit("Run as root on Ubuntu.")
    try:
        prepare(local.ROOT / "data" / "vm-appliance")
    except Exception:
        raise SystemExit(
            "Slack storage setup failed. Check Docker, image build and deployment configuration."
        ) from None
