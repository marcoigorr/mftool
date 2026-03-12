# mftool

Interactive command-line tool for reading and analyzing **MIFARE Classic 1K** NFC tags via PC/SC readers on Windows.

---

## Features

- **Interactive shell**
- **Sectors scanning** — tries KeyA and KeyB across all 16 sectors using a key file
- **Authentication** — per-sector, with inline key, key file, or automatic fallback
- **Block reading** — table view (all 4 blocks) or detailed single-block view
- **Dump** — reads all 64 blocks and saves a standard 1024-byte `.mfd` binary file
  - Keys are injected into the Sector Trailer since they are not readable
- **Read dump** — loads and displays any `.mfd` file without a physical tag

---

## Requirements

| Requirement | Details |
|---|---|
| OS | Windows 10/11 |
| Compiler | MSVC 2022+ (C++17) |
| Hardware | Any PC/SC-compatible NFC reader (tested on ACR122U) |
| SDK | Windows SDK (WinSCard) — included with Visual Studio |

---

## References

- [MIFARE Classic 1K Datasheet — NXP](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf)
- [ACR122U Application Programming Interface V2.04 — ACS](https://www.acs.com.hk/download-manual/419/API-ACR122U-2.04.pdf)
