"""Import from Home Assistant: device names and addresses for devices.json,
and the Thread network key for credentials.toml.

One websocket connection to Home Assistant, authenticated with a
long-lived access token, answers everything the recorder needs from a
controller:

  config/device_registry/list   every device HA knows, with the name the
                                user gave it and the integration it came from
  matter/node_diagnostics       for a Matter device: its network type and,
                                for Thread, its IEEE 802.15.4 extended address
  thread/list_datasets          the Thread networks HA holds credentials for
  thread/get_dataset_tlv        one network's Operational Dataset, which
                                carries the network key

No third-party packages: the websocket client below is the few dozen
lines of RFC 6455 a JSON-over-text-frames API needs. The token lives in
config/ha.env (gitignored) as HA_TOKEN, with HA_URL beside it; see
docs/HOME-ASSISTANT.md for creating one. The merge into devices.json is
threadwatch/importer.py, which is also where mDNS border routers join.

The key is never printed. The dataset TLV is parsed in memory, the key is
written to the credentials file at mode 0600, and only "unchanged" or
"written" is reported.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Optional

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DEFAULT_URL = "http://homeassistant.local:8123"


class HAError(RuntimeError):
    """Anything that stops an import: no token, a refused connection, an
    API error. The message says what to do."""


# ----------------------------------------------------------------- env file

def load_env(path: Path) -> dict[str, str]:
    """NAME=value lines; blank lines and # comments ignored; an ``export``
    prefix and surrounding quotes tolerated."""
    out: dict[str, str] = {}
    try:
        text = path.read_text()
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def connection_settings(env_path: Path, url_override: Optional[str] = None) -> tuple[str, str]:
    """(url, token) from the env file, the environment, and the flag, in
    rising precedence for the URL; the token comes from the file or the
    environment. Raises HAError with the setup steps when there is none."""
    env = load_env(env_path)
    token = os.environ.get("HA_TOKEN") or env.get("HA_TOKEN") or ""
    url = url_override or os.environ.get("HA_URL") or env.get("HA_URL") or DEFAULT_URL
    if not token:
        raise HAError(f"no Home Assistant token: put HA_TOKEN=<long-lived access token> in {env_path} "
                      f"(create one at the bottom of your HA profile page; docs/HOME-ASSISTANT.md)")
    return url.rstrip("/"), token


# ---------------------------------------------------------------- websocket

def encode_frame(opcode: int, payload: bytes) -> bytes:
    """One masked client frame (clients must mask; RFC 6455 5.3)."""
    n = len(payload)
    head = bytes([0x80 | opcode])
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return head + mask + masked


class FrameReader:
    """Reassembles messages from a byte stream: fragmentation, ping/pong,
    close. ``recv`` is any callable returning bytes (b"" at EOF)."""

    def __init__(self, recv: Callable[[int], bytes], send: Callable[[bytes], None], initial: bytes = b""):
        self._recv, self._send, self._buf = recv, send, initial

    def _exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._recv(max(4096, n - len(self._buf)))
            if not chunk:
                raise HAError("Home Assistant closed the websocket")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def message(self) -> str:
        """The next text message, replying to pings on the way."""
        parts: list[bytes] = []
        while True:
            b0, b1 = self._exact(2)
            fin, opcode = b0 & 0x80, b0 & 0x0F
            masked, n = b1 & 0x80, b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._exact(8))[0]
            mask = self._exact(4) if masked else b""
            data = self._exact(n)
            if mask:
                data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
            if opcode == 0x9:                      # ping
                self._send(encode_frame(0xA, data))
                continue
            if opcode == 0xA:                      # pong
                continue
            if opcode == 0x8:
                raise HAError("Home Assistant closed the websocket" +
                              (f": {data[2:].decode(errors='replace')}" if len(data) > 2 else ""))
            parts.append(data)
            if fin:
                return b"".join(parts).decode("utf-8", errors="replace")


def ws_connect(url: str, path: str = "/api/websocket", timeout: float = 20.0) -> tuple[socket.socket, bytes]:
    """Open the socket and do the HTTP upgrade. Returns the socket and any
    bytes that arrived after the handshake headers."""
    u = urllib.parse.urlparse(url)
    secure = u.scheme in ("https", "wss")
    host = u.hostname or "homeassistant.local"
    port = u.port or (443 if secure else 80)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise HAError(f"cannot reach Home Assistant at {host}:{port} ({exc}); HA_URL wrong, or not on this network?") from exc
    if secure:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
                  f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise HAError("Home Assistant closed the connection during the websocket handshake")
        buf += chunk
        if len(buf) > 65536:
            raise HAError("websocket handshake: response too large")
    head, rest = buf.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 101 " not in status:
        raise HAError(f"Home Assistant refused the websocket upgrade: {status} (is HA_URL the HA address?)")
    expect = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    if expect not in head.decode(errors="replace"):
        raise HAError("websocket handshake: bad Sec-WebSocket-Accept")
    return sock, rest


class HomeAssistant:
    """A minimal HA websocket API client: authenticate, then call commands
    by type and get the result or an HAError."""

    def __init__(self, url: str, token: str):
        self.url, self._token = url, token
        self._sock: Optional[socket.socket] = None
        self._reader: Optional[FrameReader] = None
        self._next_id = 1

    def connect(self) -> "HomeAssistant":
        sock, rest = ws_connect(self.url)
        self._sock = sock
        self._reader = FrameReader(sock.recv, sock.sendall, rest)
        hello = self._recv_json()
        if hello.get("type") != "auth_required":
            raise HAError(f"unexpected first message from Home Assistant: {hello.get('type')}")
        self._send_json({"type": "auth", "access_token": self._token})
        reply = self._recv_json()
        if reply.get("type") != "auth_ok":
            raise HAError(f"Home Assistant rejected the token ({reply.get('message', reply.get('type'))}); "
                          "create a new long-lived access token and update HA_TOKEN")
        return self

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.sendall(encode_frame(0x8, struct.pack(">H", 1000)))
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> "HomeAssistant":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    def _send_json(self, obj: dict) -> None:
        assert self._sock is not None
        self._sock.sendall(encode_frame(0x1, json.dumps(obj).encode()))

    def _recv_json(self) -> dict:
        assert self._reader is not None
        return json.loads(self._reader.message())

    def call(self, type_: str, **fields: Any) -> Any:
        """Send one command; return its ``result``. Events and other
        traffic that arrive meanwhile are skipped."""
        out = self.call_many([(type_, fields)])[0]
        if isinstance(out, HAError):
            raise out
        return out

    def call_many(self, requests: list[tuple[str, dict]]) -> list[Any]:
        """Send every command at once and collect the results in order,
        each a result or an HAError. Home Assistant answers commands
        concurrently, and matter/node_diagnostics takes it a second or
        more per device, so 45 devices in flight together finish in the
        time of the slowest one instead of the sum."""
        ids: dict[int, int] = {}
        for i, (type_, fields) in enumerate(requests):
            msg_id = self._next_id
            self._next_id += 1
            ids[msg_id] = i
            self._send_json({"id": msg_id, "type": type_, **fields})
        out: list[Any] = [None] * len(requests)
        pending = set(ids)
        while pending:
            reply = self._recv_json()
            msg_id = reply.get("id")
            if msg_id not in pending or reply.get("type") != "result":
                continue
            pending.discard(msg_id)
            i = ids[msg_id]
            if reply.get("success"):
                out[i] = reply.get("result")
            else:
                err = reply.get("error") or {}
                out[i] = HAError(f"{requests[i][0]}: {err.get('message') or err.get('code') or 'failed'}")
        return out


# ------------------------------------------------------------ what to fetch

def normalize_ext(mac: Optional[str]) -> Optional[str]:
    """'aa:bb:cc:dd:ee:ff:00:11' -> 'AABBCCDDEEFF0011'; None unless it is
    a 64-bit address (a Wi-Fi device's 48-bit MAC is not what we want)."""
    if not mac:
        return None
    hexes = "".join(c for c in mac if c in "0123456789abcdefABCDEF")
    return hexes.upper() if len(hexes) == 16 else None


def thread_devices(ha: HomeAssistant, log: Callable[[str], None] = lambda m: None) -> list[dict]:
    """Every Matter-over-Thread device HA knows: name (the user's name when
    set), model, extended address, node id. Devices whose diagnostics HA
    cannot fetch are logged and skipped, not fatal."""
    registry = ha.call("config/device_registry/list") or []
    matter = [dev for dev in registry
              if any(isinstance(i, (list, tuple)) and i and i[0] == "matter" for i in (dev.get("identifiers") or []))]
    log(f"asking Home Assistant about {len(matter)} Matter devices (a few seconds)")
    diags = ha.call_many([("matter/node_diagnostics", {"device_id": dev["id"]}) for dev in matter])
    out: list[dict] = []
    skipped = 0
    for dev, diag in zip(matter, diags):
        name = (dev.get("name_by_user") or dev.get("name") or "").strip()
        if isinstance(diag, HAError):
            log(f"skip {name or dev['id']}: {diag}")
            skipped += 1
            continue
        diag = diag or {}
        if str(diag.get("network_type", "")).lower() != "thread":
            continue
        addr = normalize_ext(diag.get("mac_address"))
        if not addr:
            log(f"skip {name or dev['id']}: Home Assistant reports no extended address for it")
            skipped += 1
            continue
        out.append({"name": name or addr, "model": dev.get("model") or None,
                    "manufacturer": dev.get("manufacturer") or None,
                    "addr": addr, "node_id": diag.get("node_id"), "available": diag.get("available")})
    out.sort(key=lambda d: d["name"].lower())
    if skipped:
        log(f"{skipped} Matter device(s) skipped")
    return out


def parse_dataset_tlv(hex_tlv: str) -> dict:
    """The MeshCoP TLVs of a Thread Operational Dataset, the few we use:
    channel, PAN id, extended PAN id, network name, network key."""
    data = bytes.fromhex(hex_tlv.strip())
    out: dict[str, Any] = {}
    off = 0
    while off + 2 <= len(data):
        t, n = data[off], data[off + 1]
        off += 2
        if n == 255:
            n = struct.unpack(">H", data[off:off + 2])[0]
            off += 2
        val = data[off:off + n]
        off += n
        if t == 0 and n >= 3:
            out["channel"] = struct.unpack(">H", val[1:3])[0]
        elif t == 1 and n == 2:
            out["pan_id"] = struct.unpack(">H", val)[0]
        elif t == 2 and n == 8:
            out["ext_pan_id"] = val.hex()
        elif t == 3:
            out["network_name"] = val.decode("utf-8", errors="replace")
        elif t == 5 and n == 16:
            out["network_key"] = val.hex()
    return out


def select_dataset(datasets: list[dict], dataset_id: Optional[str] = None) -> dict:
    """The preferred dataset, or the only one, or the one asked for."""
    if dataset_id:
        for d in datasets:
            if d.get("dataset_id") == dataset_id:
                return d
        raise HAError(f"no Thread dataset with id {dataset_id}")
    if not datasets:
        raise HAError("Home Assistant holds no Thread dataset: is the Thread integration set up with a border router?")
    preferred = [d for d in datasets if d.get("preferred")]
    if len(preferred) == 1:
        return preferred[0]
    if len(datasets) == 1:
        return datasets[0]
    listing = ", ".join(f"{d.get('network_name')} ({d.get('dataset_id')})" for d in datasets)
    raise HAError(f"several Thread datasets and none preferred: {listing}; pick one with --dataset-id")


def thread_dataset(ha: HomeAssistant, dataset_id: Optional[str] = None) -> dict:
    """Network name, channel, PAN ids and the key of the chosen dataset."""
    listing = ha.call("thread/list_datasets") or {}
    chosen = select_dataset(listing.get("datasets") or [], dataset_id)
    tlv = (ha.call("thread/get_dataset_tlv", dataset_id=chosen["dataset_id"]) or {}).get("tlv")
    if not tlv:
        raise HAError(f"dataset {chosen.get('network_name')} came back without a TLV")
    parsed = parse_dataset_tlv(tlv)
    if len(parsed.get("network_key", "")) != 32:
        raise HAError(f"dataset {chosen.get('network_name')} carries no network key")
    parsed.setdefault("network_name", chosen.get("network_name"))
    parsed["dataset_id"] = chosen["dataset_id"]
    return parsed


# ------------------------------------------------------------- key file

def write_private(path: Path, text: str) -> None:
    """Write a secrets file readable and writable by its owner only (0600:
    private, still editable), replacing atomically."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def current_key(path: Path) -> Optional[str]:
    try:
        import tomllib
        return str(tomllib.loads(path.read_text()).get("credentials", {}).get("network_key", "")).lower() or None
    except Exception:
        return None
