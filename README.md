# mftool

Interactive command-line tool for reading and analyzing **MIFARE Classic 1K** NFC tags via PC/SC readers on Windows.

## Features
It is required to already have valid keys for all of the operations this program offers (except reading a dump file).

- **Sector authentication** — tries KeyA and KeyB across all 16 sectors from a key file
- **Block reading** — table view (all 4 blocks) or detailed single-block view
  - It recognizes the block format (value, data, sector trailer, manifacturer) and decodes Access Conditions
- **Dump** — reads all 64 blocks and saves a standard 1024-byte `.mfd` binary file
  - Keys are injected into the Sector Trailer since they are not readable
- **Read dump** — loads and displays any `.mfd` file without a physical tag

## References

- [MIFARE Classic 1K Datasheet — NXP](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf)
- [ACR122U Application Programming Interface V2.04 — ACS](https://www.acs.com.hk/download-manual/419/API-ACR122U-2.04.pdf)
