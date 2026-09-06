# Firmware provenance

- `nrf802154_sniffer_nrf52840dongle.hex` — nRF Sniffer for 802.15.4,
  nRF52840 Dongle (PCA10059) build, from
  https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4
  commit `b69293680ac92aeddc10807314d564e4c929dcd3`.
  sha256 `13f957ca685e47b0c87f5088847dc729a8b7d17432327599bf1b61f3d357800a`
- `sniffer-dfu.zip` — DFU package built from that hex with
  `nrfutil pkg generate --hw-version 52 --sd-req 0x00 --application <hex> --application-version 1`.
  This is what `bin/flash-dongle.sh` flashes.

- `nrfutil.sha256` — sha256 of Nordic's `nrfutil` launcher per target
  triple. `bin/flash-dongle.sh` downloads that binary from a URL with no
  version in it and runs it, so a line here is what pins which build; a
  triple with no line is downloaded unverified and the script says so and
  prints the hash to record. The file explains how to add one.

License: Nordic 5-clause BSD, see ../vendor/LICENSE-nordic.txt.
