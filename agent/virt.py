"""
Virtualisation role detection.

The question is not only "is this a VM" but "what part does it play":

    physical      bare metal running no hypervisor
    type1_host    bare metal whose job is running guests - KVM/Proxmox,
                  ESXi, Hyper-V on Server. Its failure takes guests with it.
    type2_host    a desktop or server running a hosted hypervisor alongside
                  everything else - VirtualBox, VMware Workstation, Parallels,
                  Multipass, Docker Desktop
    guest         a virtual machine

That distinction matters operationally. A type 1 host going down takes
twenty guests with it; a type 2 host going down is someone closing a laptop.

Two independent lines of evidence are gathered. Direct detection asks the
system what it is. Hardware evidence asks whether anything physical is
present: fan RPM, CPU temperature, a NIC reporting a real link speed. Bare
metal has those; a VM has none of them, because there is no fan to spin and
no PHY to negotiate a link.

Where the two disagree, both are reported rather than one silently winning.
A host claiming to be physical with no hardware sensors at all is worth
looking at.
"""

import os
import re
import subprocess

# Vendor strings that identify a hypervisor rather than a manufacturer.
DMI_GUESTS = {
    "qemu": "kvm", "kvm": "kvm", "bochs": "kvm", "red hat": "kvm",
    "vmware": "vmware", "innotek": "virtualbox", "oracle": "virtualbox",
    "xen": "xen", "microsoft": "hyperv", "amazon": "aws",
    "google": "gce", "parallels": "parallels", "bhyve": "bhyve",
}

# Processes that mean this machine runs guests, and which kind of hypervisor
# that makes it.
TYPE1_PROCS = {
    "pveproxy": "proxmox", "pvedaemon": "proxmox",
    "libvirtd": "kvm", "virtqemud": "kvm", "qemu-system": "kvm",
    "vmware-hostd": "esxi", "xenstored": "xen", "vmms": "hyperv",
}
TYPE2_PROCS = {
    "VBoxSVC": "virtualbox", "VBoxHeadless": "virtualbox",
    "vmware-vmx": "vmware-workstation", "prl_disp_service": "parallels",
    "com.docker.backend": "docker-desktop", "qemu-system-aarch64": "multipass",
}


def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception:
        return ""


def _dmi(field):
    try:
        return open(f"/sys/class/dmi/id/{field}").read().strip()
    except OSError:
        return ""


def hardware_evidence(psutil_mod, interfaces=None):
    """
    Physical signals. Each is independently weak - a server can have no fan
    sensor exposed - but the absence of all of them is strong.
    """
    temps = fans = 0
    try:
        temps = sum(len(v) for v in (psutil_mod.sensors_temperatures() or {}).values())
    except Exception:
        pass
    try:
        fans = sum(len(v) for v in (psutil_mod.sensors_fans() or {}).values())
    except Exception:
        pass

    battery = None
    try:
        b = psutil_mod.sensors_battery()
        battery = bool(b) if b is not None else None
    except Exception:
        pass

    # A NIC reporting a negotiated speed has a real PHY behind it. Virtual
    # adapters report nothing.
    linked = sum(1 for i in (interfaces or []) if (i.get("speed_mbps") or 0) > 0)

    signals = [temps > 0, fans > 0, linked > 0, bool(battery)]
    return {
        "temp_sensors": temps,
        "fan_sensors": fans,
        "nics_with_link_speed": linked,
        "has_battery": battery,
        "physical_signals": sum(1 for s in signals if s),
    }


def detect_linux():
    virt = _run(["systemd-detect-virt"]).lower()
    vendor = (_dmi("sys_vendor") + " " + _dmi("product_name")).lower()

    guest_of = None
    if virt and virt not in ("none", ""):
        guest_of = virt
    else:
        for needle, name in DMI_GUESTS.items():
            if needle in vendor:
                guest_of = name
                break
        if guest_of is None:
            try:
                if "hypervisor" in open("/proc/cpuinfo").read():
                    guest_of = "unknown"
            except OSError:
                pass

    procs = _run(["ps", "-eo", "comm,args"], timeout=8)
    running = {}
    for needle, name in TYPE1_PROCS.items():
        if re.search(rf"\b{re.escape(needle)}", procs):
            running[name] = "type1"
    for needle, name in TYPE2_PROCS.items():
        if re.search(rf"\b{re.escape(needle)}", procs):
            running.setdefault(name, "type2")

    # KVM loaded but no guests yet still makes this a hypervisor host.
    if os.path.exists("/dev/kvm") and not running:
        running["kvm"] = "type1"

    return guest_of, running


def detect_windows(ps_fn):
    rows = ps_fn(r"""
$ErrorActionPreference='SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
$hv = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
$feat = @(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor |
          Where-Object State -eq 'Enabled').Count
$svcs = @(Get-Service vmms,VBoxSVC,'VMware NAT Service','VMAuthdService' |
          Where-Object Status -eq 'Running' | ForEach-Object Name)
[pscustomobject]@{
  Manufacturer=$cs.Manufacturer; Model=$cs.Model
  HypervisorPresent=$hv; HyperVRole=$feat; Services=$svcs
} | ConvertTo-Json -Depth 3""")
    if not rows:
        return None, {}
    r = rows[0]
    vendor = f"{r.get('Manufacturer','')} {r.get('Model','')}".lower()

    guest_of = None
    for needle, name in DMI_GUESTS.items():
        if needle in vendor:
            guest_of = name
            break
    # HypervisorPresent is true both in a guest and on a Hyper-V host, so it
    # only implies guest when nothing else says otherwise.
    if guest_of is None and r.get("HypervisorPresent") and not r.get("HyperVRole"):
        guest_of = "unknown"

    running = {}
    svcs = r.get("Services") or []
    if isinstance(svcs, str):
        svcs = [svcs]
    if r.get("HyperVRole") or "vmms" in [s.lower() for s in svcs]:
        running["hyperv"] = "type1"
        guest_of = None
    if "VBoxSVC" in svcs:
        running["virtualbox"] = "type2"
    if any("vmware" in s.lower() for s in svcs):
        running["vmware-workstation"] = "type2"
    return guest_of, running


def detect_macos():
    # macOS never runs as a type 1 hypervisor host and is rarely a guest, so
    # the interesting question is only which hosted hypervisors are present.
    procs = _run(["ps", "-axo", "comm"], timeout=8)
    running = {}
    for needle, name in TYPE2_PROCS.items():
        if needle in procs:
            running[name] = "type2"
    if "/Applications/VirtualBox.app" in _run(["ls", "/Applications"]):
        running.setdefault("virtualbox", "type2")

    guest_of = None
    model = _run(["sysctl", "-n", "hw.model"]).lower()
    if any(k in model for k in ("vmware", "parallels", "virtualbox")):
        guest_of = "unknown"
    return guest_of, running


def classify(guest_of, running, evidence):
    """
    Combine the two lines of evidence into a role, and say which signals
    produced it so the answer can be argued with.
    """
    type1 = [k for k, v in running.items() if v == "type1"]
    type2 = [k for k, v in running.items() if v == "type2"]
    physical = evidence.get("physical_signals", 0)

    if guest_of and not type1:
        role = "guest"
    elif type1:
        # A hypervisor host that is itself a guest is nested virtualisation,
        # which is real but rare enough to report as type1 with a note.
        role = "type1_host"
    elif type2:
        role = "type2_host"
    elif physical > 0:
        role = "physical"
    else:
        # No hypervisor, no guest marker, and nothing physical reporting.
        # Most likely a container or a VM whose markers were hidden.
        role = "guest"

    return {
        "role": role,
        "hypervisor": (type1 + type2 or [guest_of])[0] if (type1 or type2 or guest_of) else None,
        "guest_of": guest_of,
        "runs": sorted(running.keys()),
        "nested": bool(guest_of and type1),
        "evidence": evidence,
        # Stated rather than implied: this is inference, and the reasoning
        # should be visible to whoever has to trust it.
        "basis": ("direct detection" if (guest_of or running)
                  else "hardware sensors only"),
    }
