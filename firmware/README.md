# Firmware provenance

- `nrf802154_sniffer_nrf52840dongle.hex` — nRF Sniffer for 802.15.4,
  nRF52840 Dongle (PCA10059) build, from
  https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4
  commit `b69293680ac92aeddc10807314d564e4c929dcd3`.
  sha256 `13f957ca685e47b0c87f5088847dc729a8b7d17432327599bf1b61f3d357800a`
- `sniffer-dfu.zip` — DFU package built from that hex with
  `nrfutil pkg generate --hw-version 52 --sd-req 0x00 --application <hex> --application-version 1`.
  This is what `bin/flash-dongle.sh` flashes.

- `nrfutil.sha256` — sha256 of Nordic's `nrfutil` launcher, one line per
  architecture, for the build `bin/flash-dongle.sh` names in
  `NRFUTIL_VERSION`. The script downloads that exact build and runs it,
  so these hashes are what say it is the right one. A download that does
  not match is deleted and never made executable, and an architecture
  with no line here is not downloaded at all.

  Nordic keeps every release beside the unversioned `nrfutil` file they
  overwrite, so the pinned build stays fetchable and nobody is left
  unable to get what these hashes expect.

  **To move to a newer nrfutil:** list what Nordic has at
  `https://files.nordicsemi.com/artifactory/swtools/external/nrfutil/executables/<triple>/`,
  pick a version present for all four architectures, set
  `NRFUTIL_VERSION` in `bin/flash-dongle.sh`, then download
  `nrfutil-<triple>-<version>` for each and replace all four hashes:

  ```sh
  B=https://files.nordicsemi.com/artifactory/swtools/external/nrfutil/executables
  V=1.4.0-5515776    # the new version
  for T in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
           aarch64-apple-darwin x86_64-apple-darwin; do
    curl -sSfL "$B/$T/nrfutil-$T-$V" | shasum -a 256 | sed "s|-|$T|"
  done
  ```

  Do this on a machine you trust. A hash taken from a bad download pins
  a bad binary.

License: Nordic 5-clause BSD, see ../vendor/LICENSE-nordic.txt.
