"""Which OpenThread key logic a device runs: [keys.stacks] in config.toml.

The key guard forecast needs each device's stack, and firmware updates
change it, so the table is keyed by Home Assistant's model and firmware
version (sw_version), exactly as HA reports them in the HA map. Devices
HA does not hold (border routers, HomeKit-only locks) are listed by
inventory name instead. Each entry says how the stack is known. Anything
the table does not list is unknown: a firmware update makes a device
unknown until someone checks it, and the forecast says so.
"""

from __future__ import annotations

STACKS = ("current", "old", "unknown")
# reported: the device reports an OpenThread commit; behaviour: its recorded
# switches fit only that logic; assumed: neither, a best guess.
KNOWN = ("reported", "behaviour", "assumed")


def _entry(where: str, value) -> tuple[str, str | None]:
    words = [w.strip() for w in value.split(",")] if isinstance(value, str) else []
    if words == ["unknown"]:
        return "unknown", None
    if len(words) == 2 and words[0] in STACKS[:2] and words[1] in KNOWN:
        return words[0], words[1]
    raise ValueError(f"[keys.stacks] {where} must be \"unknown\" or a stack and how it is known, "
                     f"such as \"old, reported\" (stacks: current, old; known: {', '.join(KNOWN)}), "
                     f"not {value!r}")


def parse(table) -> dict[str, dict]:
    """[keys.stacks] as {"models": {model: {sw_version: (stack, known)}},
    "devices": {inventory name: (stack, known)}}, refusing anything else."""
    if not isinstance(table, dict) or set(table) - {"models", "devices"}:
        raise ValueError("[keys.stacks] takes two tables, models and devices")
    models, devices = table.get("models", {}), table.get("devices", {})
    if not isinstance(models, dict) or not all(isinstance(v, dict) for v in models.values()):
        raise ValueError('[keys.stacks.models] maps a model to its versions: "Model" = { "1.0" = "old, reported" }')
    if not isinstance(devices, dict):
        raise ValueError('[keys.stacks.devices] maps an inventory name to a stack: "Name" = "current, reported"')
    return {"models": {m: {v: _entry(f"{m} {v}", s) for v, s in vs.items()} for m, vs in models.items()},
            "devices": {n: _entry(n, s) for n, s in devices.items()}}


def device_stack(stacks: dict, name: str, ha_map: dict[str, dict]) -> tuple[str, str | None, str]:
    """The stack an inventory device runs, how that is known, and why:
    its name in [keys.stacks.devices] first, then its HA model and
    sw_version (the HA map entry matched to that name)."""
    if name in stacks["devices"]:
        return (*stacks["devices"][name], "listed by name")
    entry = next((e for e in ha_map.values() if e.get("matched") and e.get("name") == name), None)
    if entry is None:
        return "unknown", None, "not in Home Assistant's map and not listed by name"
    model, version = entry.get("model"), entry.get("sw_version")
    if not model or not version:
        return "unknown", None, "Home Assistant reports no model or firmware version"
    versions = stacks["models"].get(model)
    if versions is None:
        return "unknown", None, f"model {model!r} is not in the table"
    if version not in versions:
        listed = ", ".join(versions) or "none"
        return "unknown", None, f"{model} firmware {version} is not checked (the table has {listed})"
    return (*versions[version], f"{model} {version}")
