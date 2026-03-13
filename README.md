# mftool

Interactive command-line tool for reading and analyzing **MIFARE Classic 1K** NFC tags via PC/SC readers on Windows.

## Features

Most operations require valid authentication keys. The only exception is `readdump`, which works offline on a saved file.

- **connect** — waits up to 5 seconds for a tag and displays UID, ATR and card type
- **send** — sends a raw APDU command and prints the response
- **scan** — tries KeyA and KeyB across all 16 sectors from a key file, prints a table of found keys
- **authenticate** — authenticates a single sector with a specific key (from file or inline hex)
- **read** — reading sectors or a single block
  - Block types recognized: Manufacturer, Sector Trailer, Value Block, Data Block
- **write** — writes 16 bytes to a block
  - Refuses writes to the Manufacturer Block (sector 0, block 0)
  - Checks Access Bits consistency before writing a Sector Trailer (B3); aborts if invalid
- **dump** — reads all 64 blocks and saves a standard 1024-byte `.mfd` binary
  - Known keys are injected into each Sector Trailer (not readable from mifare 1k tag)
- **readdump** — loads and displays any `.mfd` file without a physical tag


## References

- [MIFARE Classic 1K Datasheet — NXP](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf)
- [ACR122U Application Programming Interface V2.04 — ACS](https://www.acs.com.hk/download-manual/419/API-ACR122U-2.04.pdf)
