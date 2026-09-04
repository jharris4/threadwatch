"""Find Thread border routers on the LAN over mDNS.

Every Thread border router (Apple TV, HomePod, an OTBR) advertises the
MeshCoP service ``_meshcop._udp`` over mDNS, and the advertisement's TXT
record carries the border router's Thread extended address (``xa``), the
network name (``nn``) and extended PAN id (``xp``), plus vendor and model.
The hostname in the SRV record is stable across reboots; the extended
address of an Apple hub is not. That pair is exactly what naming a
rebooted Apple TV needs, and the recorder asks the LAN itself: no
controller, no token.

mDNS is link-local. On the routers' own subnet the answer comes straight
back; from another VLAN it arrives only if the network reflects mDNS
between them (UniFi's mDNS setting, avahi's reflector), and then only as
a multicast reply, so the browse asks both ways. `threadwatch doctor` and
`threadwatch border-routers` show what this host can see.

Just enough DNS for that: queries, and a parser for PTR, SRV, TXT, A and
AAAA records with name compression.
"""

from __future__ import annotations

import select
import socket
import struct
import time
from typing import Optional

MDNS_GROUP, MDNS_PORT = "224.0.0.251", 5353
SERVICE = "_meshcop._udp.local"
TYPE_A, TYPE_PTR, TYPE_TXT, TYPE_AAAA, TYPE_SRV = 1, 12, 16, 28, 33
CLASS_IN = 1


# ------------------------------------------------------------------ wire

def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(questions: list[tuple[str, int]], unicast_reply: bool = True) -> bytes:
    """A standard query; ``unicast_reply`` sets the QU bit so responders
    answer this socket directly instead of the multicast group."""
    head = struct.pack(">HHHHHH", 0, 0, len(questions), 0, 0, 0)
    qclass = CLASS_IN | (0x8000 if unicast_reply else 0)
    return head + b"".join(encode_name(n) + struct.pack(">HH", t, qclass) for n, t in questions)


def read_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    """A possibly compressed name at ``off``: (name, offset after it)."""
    labels: list[str] = []
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        n = data[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0 == 0xC0:
            if depth > 16:
                raise ValueError("compression loop")
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            tail, _ = read_name(data, ptr, depth + 1)
            return ".".join(labels + ([tail] if tail else [])), off + 2
        off += 1
        labels.append(data[off:off + n].decode("utf-8", errors="replace"))
        off += n


def parse_txt(rdata: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    off = 0
    while off < len(rdata):
        n = rdata[off]
        item = rdata[off + 1:off + 1 + n]
        off += 1 + n
        if not item:
            continue
        k, _, v = item.partition(b"=")
        out[k.decode("ascii", errors="replace").lower()] = v
    return out


def parse_message(data: bytes) -> list[tuple[str, int, object]]:
    """Every resource record in a response as (name, type, value): PTR ->
    target name, SRV -> (port, target), TXT -> {key: bytes}, A/AAAA ->
    address text. Questions are skipped; unknown types are dropped."""
    if len(data) < 12:
        return []
    _id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    out: list[tuple[str, int, object]] = []
    for _ in range(an + ns + ar):
        name, off = read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        rstart = off
        off += rdlen
        if rtype == TYPE_PTR:
            out.append((name, rtype, read_name(data, rstart)[0]))
        elif rtype == TYPE_SRV and len(rdata) >= 6:
            port = struct.unpack(">H", rdata[4:6])[0]
            out.append((name, rtype, (port, read_name(data, rstart + 6)[0])))
        elif rtype == TYPE_TXT:
            out.append((name, rtype, parse_txt(rdata)))
        elif rtype == TYPE_A and len(rdata) == 4:
            out.append((name, rtype, socket.inet_ntoa(rdata)))
        elif rtype == TYPE_AAAA and len(rdata) == 16:
            out.append((name, rtype, socket.inet_ntop(socket.AF_INET6, rdata)))
    return out


# ---------------------------------------------------------------- browse

def _norm_host(name: str) -> str:
    return name.rstrip(".").lower()


def collect_routers(records: list[tuple[str, int, object]], service: str = SERVICE) -> dict[str, dict]:
    """Border routers from a pile of records, keyed by instance name. An
    instance with no SRV or TXT yet is still returned (so the caller can
    ask for the rest); ``ext`` is None until the TXT arrives."""
    service = _norm_host(service)
    instances: dict[str, dict] = {}
    srv: dict[str, tuple[int, str]] = {}
    txt: dict[str, dict] = {}
    addrs: dict[str, list[str]] = {}
    for name, rtype, value in records:
        n = _norm_host(name)
        if rtype == TYPE_PTR and n == service:
            instances.setdefault(_norm_host(str(value)), {"instance": str(value)[:len(str(value)) - len(service) - 1]
                                                          if str(value).lower().endswith("." + service) else str(value)})
        elif rtype == TYPE_SRV:
            srv[n] = value  # type: ignore[assignment]
        elif rtype == TYPE_TXT:
            txt[n] = value  # type: ignore[assignment]
        elif rtype in (TYPE_A, TYPE_AAAA):
            addrs.setdefault(n, []).append(str(value))
    for full, info in instances.items():
        port, target = srv.get(full, (None, None))
        info["hostname"] = _norm_host(target) if target else None
        info["port"] = port
        t = txt.get(full)
        info["ext"] = t["xa"].hex() if t and len(t.get("xa", b"")) == 8 else None
        info["network_name"] = t["nn"].decode("utf-8", errors="replace") if t and "nn" in t else None
        info["ext_pan_id"] = t["xp"].hex() if t and len(t.get("xp", b"")) == 8 else None
        info["vendor"] = t["vn"].decode("utf-8", errors="replace") if t and "vn" in t else None
        info["model"] = t["mn"].decode("utf-8", errors="replace") if t and "mn" in t else None
        info["addresses"] = addrs.get(info["hostname"] or "", [])
        info["complete"] = bool(t) and target is not None
    return instances


def browse(service: str = SERVICE, timeout: float = 3.0, log=lambda m: None) -> list[dict]:
    """Ask the LAN for border routers and wait ``timeout`` seconds for the
    answers. Returns one dict per instance seen: instance, hostname, port,
    ext (the Thread extended address, 16 hex, or None), network_name,
    ext_pan_id, vendor, model, addresses."""
    socks: list[socket.socket] = []
    query_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    query_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    query_sock.bind(("", 0))
    socks.append(query_sock)
    # Responders that recently multicast the same records may answer on the
    # group instead of unicast: listen there too, sharing 5353 with any
    # local mDNS daemon.
    try:
        group_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        group_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            group_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        group_sock.bind(("", MDNS_PORT))
        mreq = socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0")
        group_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        socks.append(group_sock)
    except OSError as exc:
        log(f"mdns: not listening on the multicast group ({exc}); unicast replies only")
    records: list[tuple[str, int, object]] = []
    asked_detail: set[str] = set()
    try:
        # Two queries: one asking for a unicast reply straight to this
        # socket (works on the routers' own subnet), one for the ordinary
        # multicast reply, which is what an mDNS reflector between VLANs can
        # carry back to the group socket.
        query_sock.sendto(build_query([(service, TYPE_PTR)]), (MDNS_GROUP, MDNS_PORT))
        query_sock.sendto(build_query([(service, TYPE_PTR)], unicast_reply=False), (MDNS_GROUP, MDNS_PORT))
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                break
            ready, _, _ = select.select(socks, [], [], min(left, 0.5))
            for s in ready:
                try:
                    data, _ = s.recvfrom(9000)
                except OSError:
                    continue
                try:
                    records.extend(parse_message(data))
                except (ValueError, struct.error):
                    continue
            # Instances announced without their SRV/TXT: ask for those.
            for full, info in collect_routers(records, service).items():
                if not info["complete"] and full not in asked_detail:
                    asked_detail.add(full)
                    query_sock.sendto(build_query([(full, TYPE_SRV), (full, TYPE_TXT)]), (MDNS_GROUP, MDNS_PORT))
    finally:
        for s in socks:
            s.close()
    found = collect_routers(records, service)
    return sorted((dict(v) for v in found.values()), key=lambda r: r["instance"].lower())
