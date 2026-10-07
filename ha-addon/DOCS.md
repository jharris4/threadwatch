# threadwatch relay

Runs `threadwatch relay` on a Home Assistant OS host: an nRF52840 sniffer
dongle plugged in here is streamed to a threadwatch recorder on another
machine, as one of its radios (SETUP.md in the repository, "A dongle on
another host"). The relay holds no network key and keeps nothing on disk.

A dongle beside the border router's own radio is best on a USB extension
cable, a little away from both the host and the border router's radio.

## Install

From a clone of the repository, on a workstation that can ssh into the
Home Assistant host through a terminal add-on ("Advanced SSH & Web
Terminal" or "Terminal & SSH"):

```bash
bin/push-ha-addon.sh hassio@homeassistant.local           # ssh options may follow, e.g. -p 2222
```

That copies this folder, with the code it runs, to `/addons/threadwatch_relay`.
Then in Home Assistant, Settings > Add-ons > Add-on store, the menu >
Check for updates, and under Local add-ons: threadwatch relay > Install.
The Supervisor builds the image on the host, which takes a few minutes
on a Raspberry Pi.

## Options

| Option | |
| --- | --- |
| Recorder address | The recorder's `host:port`: the `listen` of this radio's `[[record.radios]]` entry there (`source = "tcp"`). Use an IP address: a `.local` name may not resolve inside an add-on. |
| Radio label | This radio's `label` in that entry. |
| Thread channel | The Thread network's channel, 11-26. |
| Dongle | Optional. Empty, the relay uses the one nRF 802.15.4 sniffer plugged into the host; name it when there are two. |

The add-on will not start until the first three are set, and stops
again (see its log) if the relay refuses one of them.

## Running

The log starts with the commit the image was built from, then the
relay's own lines. When the dongle's stream ends (unplugged, sniffer
crashed) or no dongle is found, the relay is started again after 10 s.
On the recorder the radio shows as lost and back like any relay.

## Updating

Run `bin/push-ha-addon.sh` again, then threadwatch relay > Rebuild. The
add-on's version stays the same on purpose: the Supervisor rebuilds a
local add-on only at the same version.
