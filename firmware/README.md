# Firmware provenance

- `nrf802154_sniffer_nrf52840dongle.hex` — nRF Sniffer for 802.15.4,
  nRF52840 Dongle (PCA10059) build, from
  https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4
  commit `b69293680ac92aeddc10807314d564e4c929dcd3`.
  sha256 `13f957ca685e47b0c87f5088847dc729a8b7d17432327599bf1b61f3d357800a`
- `sniffer-dfu.zip` — DFU package built from that hex with
  `nrfutil pkg generate --hw-version 52 --sd-req 0x00 --application <hex> --application-version 1`.
  This is what `bin/flash-dongle.sh` flashes.

License: Nordic 5-clause BSD, see ../vendor/LICENSE-nordic.txt.
