# Optional: Thread credentials for decryption-based analysis

threadwatch works fully without the Thread network key — capture, storm
detection, per-device health, quiet/offline tracking and `why` all run on
cleartext 802.15.4 MAC headers alone. Providing the key unlocks a deeper
layer, used only in analysis (`replay`, `why`) and optional live
enrichment; the ring-buffer capture never needs it.

## What the key adds

| Capability | Without key | With key |
| --- | --- | --- |
| Capture, ring buffer | ✅ | ✅ |
| Traffic-storm / phase-lock detection | ✅ | ✅ |
| Per-device RSSI, ACK rate, poll cadence | ✅ | ✅ |
| Device quiet / returned / offline | ✅ | ✅ |
| Rejoin attempts (Parent/Child ID Request) | infer from beacons | ✅ named, by device |
| Partition / leader changes | ✗ | ✅ |
| SRP / DNS-SD auto-naming | ✗ | ✅ (hints) |
| True packet destinations (inside 6LoWPAN) | next-hop only | ✅ |

Note: even with the Thread key, Matter *application* payloads (e.g. sensor
readings) stay encrypted — Matter has its own layer above Thread. You get
control-plane visibility and message flow, not device data.

## What the key does NOT expose

The key never leaves your capture host, is never logged, and is not
written into pcaps (frames are stored exactly as received; decryption is
applied on read). Frame payloads in the pcaps remain encrypted at rest.

## Setup (kept as safe as practical)

Store the key in a **separate, gitignored, read-only** file — never in
config.toml, never in git. `config/credentials.toml` is gitignored by
this repo.

```bash
# Find your network key (example, via an OTBR REST endpoint on your LAN):
#   GET http://<otbr>:8081/node/dataset/active   -> field "networkKey"
# or from `ot-ctl networkkey` on the border router.

cat > config/credentials.toml <<'TOML'
[credentials]
network_key = "PUT_32_HEX_CHARS_HERE"
TOML
chmod 400 config/credentials.toml
```

Then either rely on the default path (`config/credentials.toml` is picked
up automatically) or point at it explicitly in config.toml:

```toml
[credentials]
file = "credentials.toml"
```

`threadwatch capture` / `replay` will print `credentials: loaded` when
active, and fall back to header-level analysis (with a note) if the file
is missing or malformed. Rotate the key on your Thread network and this
file is stale — update it.

## Decrypting old pcaps in Wireshark

Wireshark can decrypt the ring pcaps too: Preferences → Protocols → IEEE
802.15.4 → Decryption keys → add your key with key type "Thread hash".
Set (Protocols → Thread) the correct security suite. Then MLE, 6LoWPAN
and CoAP dissect in the GUI for any capture, retroactively.
