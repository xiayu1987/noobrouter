"""Read-only system collectors from /proc and /sys. Never mutate state."""
import os

from .shell import read

_last_cpu = None


def cpu_percent():
    global _last_cpu
    vals = [int(x) for x in read("/proc/stat").splitlines()[0].split()[1:]]
    idle, total = vals[3] + vals[4], sum(vals)
    prev, _last_cpu = _last_cpu, (idle, total)
    if not prev or total == prev[1]:
        return 0.0
    return round(100.0 * (1 - (idle - prev[0]) / (total - prev[1])), 1)


def meminfo():
    m = {}
    for line in read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        m[k] = int(v.split()[0]) * 1024 if v.split() else 0
    total, avail = m.get("MemTotal", 0), m.get("MemAvailable", 0)
    return {"total": total, "used": total - avail, "available": avail}


def temperature():
    vals = []
    base = "/sys/class/thermal"
    for z in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        t = read(f"{base}/{z}/temp").strip()
        if t.isdigit():
            vals.append(int(t) / 1000)
    return max(vals) if vals else None


def disk(path="/"):
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    return {"total": total, "used": total - free, "free": free}


def conntrack():
    cnt = read("/proc/sys/net/netfilter/nf_conntrack_count").strip() or "0"
    mx = read("/proc/sys/net/netfilter/nf_conntrack_max").strip() or "0"
    return {"count": int(cnt), "max": int(mx)}
