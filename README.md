<div align="center">

# 🪐 marcoigorr - mftool

Interactive command-line tool for reading, writing, dumping and cloning **MIFARE Classic 1K** NFC tags via PC/SC readers on Windows.

Built with C++17, communicates through the PC/SC layer (WinSCard) and supports both native ACR122U APDUs and PN532 passthrough for advanced operations like cross-sector Value Block transfers.

![License:GNU](https://img.shields.io/static/v1?label=license&message=GNU&color=blue)
[![Latest Release](https://img.shields.io/github/v/release/marcoigorr/mftool)](https://github.com/marcoigorr/mftool/releases/latest)
</div>

## Requirements

- Windows 10/11
- A PC/SC-compatible NFC reader (tested with **ACR122U**)
- Visual Studio 2022+ with the C++ Desktop workload

## Usage

Launch `mftool.exe`. The interactive shell starts automatically and waits for commands.

```
[mftool] :: mifare toolkit
------------------------------------
build:  vx.x
author: marcoigorr
------------------------------------
type 'help' for commands, 'exit' to quit.

mftool >
```

Every command supports `-h` for detailed usage (e.g. `scan -h`, `write -h`).

### Workflow example

```
mftool > connect                        # detect and connect to a tag
mftool :: [uid] > scan                  # find keys for all 16 sectors
mftool :: [uid] > read -s 1             # read all blocks in sector 1
mftool :: [uid] > read -s 1 -b 2        # detailed view of sector 1, block 2
mftool :: [uid] > dump                  # save full tag content to dumps/dump_[uid].mfd
mftool :: [uid] > exit
```

## Commands

`connect` - Wait up to 5 s for a tag, display UID, ATR and card type.

`send` - Send a raw APDU command and print the response.

`scan` - Try KeyA and KeyB for all 16 sectors from a key file.

`authenticate` - Authenticate a single sector (from file or inline key).

`read` - Read an entire sector or a single block with decoded output.

`write` - Write 16 bytes to a block (Access Bits validated on trailers).

`transfer` - Write a Value Block via Restore+Transfer through a staging block.

`dump` - Read all 64 blocks and save a standard 1024-byte `.mfd` binary.

`readdump` - Display a `.mfd` or `.mct` dump file offline (no tag needed).

`clone` - Write a dump file onto a tag, block by block.

`help` - Show the command list.

`exit` - Exit the program.

In the sections below are a detailed explanation for each command:

### connect

Waits up to 5 seconds for a tag on the first available reader. On success, prints the ATR, card type and UID. All subsequent tag commands become available.

### send

```
send <APDU hex bytes>
```

Sends a raw APDU to the tag. Useful for debugging or issuing custom commands.

```
mftool :: [uid] > send FF CA 00 00 04
FF FF FF FF 90 00  Success
```

### scan

```
scan [-k <keyfile>]
```

Iterates all 16 sectors, trying every key in the file for both KeyA and KeyB. Prints a table of found keys. Default key file: `keys/std.keys`.

```
mftool :: [uid] > scan -k keys/std.keys
```

### authenticate

```
authenticate -s <sector> [-k <keyfile>] [-t A|B] [-key <hex>]
```

Authenticates a single sector. Without `-t`, tries KeyA first then KeyB. Use `-key` to supply an inline 6-byte hex key instead of a file.

```
mftool :: [uid] > authenticate -s 4 -key A0A1A2A3A4A5
```

### read

```
read -s <sector> [-b <block>]
```

Without `-b`: prints all 4 blocks of the sector in a table with hex, ASCII and Access Bits.  
With `-b`: detailed decode of a single block — type detection (Manufacturer, Trailer, Value, Data), field breakdown and values.

### write

```
write -s <sector> -b <block> -v <32 hex chars>
```

Writes 16 raw bytes to a block. Refuses writes to the Manufacturer Block (S0/B0). When targeting a Sector Trailer (B3), validates that the Access Bits are internally consistent before writing — invalid Access Bits permanently lock the sector.

```
mftool :: [uid] > write -s 1 -b 0 -v 00112233445566778899AABBCCDDEEFF
```

### transfer

```
transfer -s <sector> -b <block> -v <value> -a <addr> -stg <S:B>
```

Writes a MIFARE Value Block using Restore+Transfer through a staging block.

- **Same sector**: uses the ACR122U native Restore Value Block command (`FF D7`).
- **Cross sector**: uses PN532 passthrough with `RESTORE (C2)` + `TRANSFER (B0)`.

```
mftool :: [uid] > transfer -s 3 -b 0 -v 100 -a 0D -stg 3:2
mftool :: [uid] > transfer -s 3 -b 0 -v 100 -a 0D -stg 2:2   # cross-sector
```

### dump

```
dump
```

Reads all 64 blocks and saves a standard 1024-byte `.mfd` file in the `dumps/` folder. Known keys are injected into each Sector Trailer (KeyA and KeyB are not readable from the tag). Requires all sectors to be authenticated first (`scan`).

### readdump

```
readdump <filename>
```

Displays a dump file from `dumps/` with full decoding: hex, ASCII, Access Bits, Value Blocks. Works offline — no tag or reader needed.

Supported formats:
- `.mfd` — 1024-byte MIFARE binary dump
- `.mct` — MIFARE Classic Tool text format

```
mftool > readdump dump_[uid].mfd
```

### clone

```
clone <filename>
```

Writes a dump file onto the connected tag, block by block. Compares each block against the tag and skips identical ones. For write-protected Value Blocks with Decrement/Transfer/Restore permission, falls back to Restore&Transfer through a staging block. Sector Trailers with invalid Access Bits are skipped. Requires `scan` first.

```
mftool :: [uid] > clone dump_[uid].mfd
```

## Key files

Key files are plain text, one 6-byte hex key per line (12 characters). Lines starting with `#` are comments.

```
# Standard MIFARE keys
FFFFFFFFFFFF
A0A1A2A3A4A5
D3F7D3F7D3F7
000000000000
```

A set of common default keys is provided in `keys/std.keys`.

## References

- [MIFARE Classic 1K Datasheet — NXP](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf)
- [ACR122U API v2.04 — ACS](https://www.acs.com.hk/download-manual/419/API-ACR122U-2.04.pdf)
- [AN1305 — MIFARE Classic as NFC Type MIFARE Tag](https://www.nxp.com/docs/en/application-note/AN1305.pdf)

## License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.
