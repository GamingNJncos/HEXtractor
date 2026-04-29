# HEXtractor

Extracts all partition contents from Symbol/Motorola/Zebra proprietary firmware images (`.hex`, `.bgz`). Handles the full image pipeline: format decode → flat binary → ROMHDR/TOC walk or direct scan → PE reconstruction → file carve fallback. Outputs reconstructed PE binaries, ROM data files at their original CE paths, SHA-256 checksums, and a machine-readable manifest.

Supports WT4090 (PXA270 / CE5), WT41N0 (OMAP4460 / CE7), and any Symbol HEX or BGZ image following the same format conventions.

Huge shout out to KodaSec for a number of helpful items found here https://github.com/KodaSec/wince-decompr
---

## Why This Exists

Symbol/Motorola/Zebra devices have no public hardware documentation. For devices being ported to Linux or otherwise reverse engineered, **the firmware image is the hardware documentation** — and it is locked inside proprietary formats no publicly available tool could parse. I built HEXtractor to kick that door wide open and toss a flash bang in behind it. 


Artifacts recovered through this pipeline have directly produced (for WT4090):

- **Boot sequence** — Monitor bootloader binary extracted from a co-resident HEX partition; RE of the bootstrap revealed the exact XIP path, SDRAM copy mechanics, and B000FF container scan logic needed to write a working Linux shim
- **Display** — LCD timing registers (LCCR0–4, pixel clock, panel parameters) recovered from WinCE registry hives; display functional on first Linux boot
- **GPIO map** — Full GPIO pin assignments for key matrix, SPI, audio, and peripheral alternate functions recovered by cross-referencing 25 extracted DLLs; authoritative pin map used by every driver
- **WiFi** — Chipset identified as PCI device (Prism54 SoftMAC) from WinCE WiFi DLLs; CardBus vs PCMCIA architecture confirmed; saved weeks of wrong-driver debugging
- **Bluetooth** — TI LMX5452 + `hci_ll` protocol confirmed from BT DLLs; BTUART GPIO and BREAK-as-reset identified
- **FPGA/CPLD/PCI bridge** — Register map recovered from `ceddk.dll` RE; CPLD decode-enable sequence and physical addresses recovered from Monitor binary literal pool scan
- **USB** — OTG mode switching and bulk transport protocol from USB DLL RE
- **Power management** — ATmega8535 co-processor on SPI; boot ordering and handshake from PM DLL RE

None of this data exists in (available to me) datasheets, SDKs, or vendor documentation. It lives in the firmware.

**What no other tool does:**
- Parses Symbol's custom Intel HEX extension (record types `82`/`84` + Symbol RLE, control records `A0`/`A1`/`A3`) — standard Intel HEX tools and binwalk cannot
- Handles the BGZ format (gzip + NK.bin bootstrap + ECECT physfirst extraction) — undocumented, no other parser exists publicly
- Extracts all HEX partitions — OS, Monitor bootloader, platform, application, and user-data regions are all co-resident in the same file
- Full PE reconstruction from `e32_rom`/`o32_rom` ROM format — not just carving; headers are rebuilt from the ROM module table
- Graceful fallback chain: TOC walk → direct `e32_rom` scan → PE header carve, so partial or RAMIMAGE variants still yield usable output

---

## Supported Formats

### Symbol HEX (`.hex`)
Symbol's proprietary extension of Intel HEX. Binary payloads are carried in record types `82`/`84` with Symbol RLE inline compression. ASCII control records `A0`/`A1`/`A3` encode partition metadata (partition ID, size, device target, segment addressing). Once decoded and decompressed, the records are assembled into a contiguous flat binary image. The ROMHDR and full TOC are embedded in the flat image — module and file extraction is fully table-driven.

### BGZ (`.bgz`)
A gzip-compressed container holding two concatenated sections:
1. **NK.bin bootstrap** — OMAP4 IBL/SPL code loaded into SRAM at device boot. Contains an `ECECT` block in the first record that encodes `physfirst` (the SDRAM base VA). Ends with a `{0xFFFFFFFF, 0xFFFFFFFF}` terminator for CE7 or `{0x00000000, checksum}` for CE5.
2. **OS flat image** — Raw binary starting immediately after the bootstrap terminator. For CE7 RAMIMAGE variants the ROMHDR is runtime-only (constructed by the NK loader at boot, not stored in the file). For CE7 ROMIMAGE variants (less common) an embedded ROMHDR may be present.

| Format | Extension | CE Version | ROMHDR in file |
|--------|-----------|------------|----------------|
| Symbol HEX | `.hex` | CE 5 / CE 7 | Yes — TOC walk available |
| BGZ (ROMIMAGE) | `.bgz` | CE 7 | Yes — TOC walk available |
| BGZ (RAMIMAGE) | `.bgz` | CE 7 | No — direct e32 scan + PE carve |

---

## Requirements

- Python 3.8+

---

## Usage

```
python HEXtractor.py --input <image> [--out <output_dir>] [--physfirst <VA>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--input` | Yes | Path to `.hex` or `.bgz` source image |
| `--out` | No | Output directory. Default: `extract/<input-stem>/` |
| `--physfirst` | No | Override physfirst VA (hex). BGZ: auto-detected from ECECT when omitted |

> **Note:** HEXtractor will refuse to run if the output directory already exists and is not empty. Remove it before re-running.

---

## Output Structure

```
<out>/
├── _meta/
│   ├── base_image.bin       # Flat partition image
│   ├── manifest.json        # ROMHDR + TOC entries + hashes + format info
│   ├── unpack.log           # Full extraction log
│   ├── sha256sums.txt       # SHA-256 checksums for all extracted files
│   └── compressed_modules/  # Raw blobs for modules that could not be reconstructed as PE
├── Windows/
│   ├── nk.exe               # ROM modules extracted and reconstructed as PE (DLL/EXE)
│   ├── coredll.dll
│   ├── kernel.dll
│   └── ...
└── <wince-path>/            # ROM data files at their original paths
    ├── Windows/
    └── ...
```

---

## Examples

### Extract a Symbol HEX OS image (CE7, OMAP4460)

```bash
python HEXtractor.py --input /path/to/41X0c**BenOS****02.hex
```

Output goes to `extract/41X0c**BenOS****02/` in the current directory — the folder name is derived from the input image filename.

---

### Extract to a custom output directory

```bash
python HEXtractor.py --input /path/to/41X0c**BenOS****02.hex --out /tmp/wt41n0_os
```

---

### Extract a BGZ image with known physfirst

```bash
python HEXtractor.py --input /path/to/41X0c**BenOS****02.bgz --physfirst 0x81168000
```

For BGZ images HEXtractor attempts to auto-detect `physfirst` from the ECECT block in the NK.bin bootstrap. Use `--physfirst` to override or supply it when auto-detection fails.

---

### Extract a CE5 Symbol HEX image (PXA270)

```bash
python HEXtractor.py --input /path/to/CE5_image.hex --out /path/to/output/
```

CE5 images use `e32_imageflags` values `{0x012E, 0x012F, 0x212E, 0x212F}`. HEXtractor handles both CE5 and CE7 imageflags automatically.

---

### Re-run after a failed or partial extraction

```bash
# Remove old output first — HEXtractor will not overwrite
rm -rf extract/41X0c**BenOS****02/

python HEXtractor.py --input /path/to/41X0c**BenOS****02.hex
```

---

## Extraction Flow

Extraction methodology starts with logicial identification of known items and image types, steps through a series of iterative operations, and ends up at banging rocks together to carve out useful data.  It tries to be smart where it can but will fall back to cutting out data with a butter knife if all else fails. 
```
INPUT
  │
  ├─ .hex ──► Parse A0/A1/A3 header records (partition ID, size, segment map)
  │           Decode type 82/84 binary records + Symbol RLE decompression
  │           Assemble into flat binary image
  │
  └─ .bgz ──► gzip decompress
              Find B000FF NK.bin bootstrap magic
              Parse bootstrap records → extract ECECT block → physfirst VA
              OS flat image begins immediately after bootstrap end-marker

              ▼
    ┌─────────────────────────────────┐
    │         ROMHDR SCAN             │
    │  Search flat for valid CE ROM   │
    │  header (ARM/Thumb CPU type,    │
    │  plausible mod/file counts,     │
    │  resolvable TOC name strings)   │
    └────────────────┬────────────────┘
                     │
         ┌───────────┴────────────┐
         │                        │
      FOUND                   NOT FOUND
   (ROMIMAGE)              (RAMIMAGE — BGZ CE7
         │                  runtime-only ROMHDR)
         │                        │
    TOC walk                      ▼
    ├─ Module TOC ──► Read e32_rom + o32_rom sections
    │                 LZX-decompress flagged sections
    │                 Reconstruct PE file
    │                 → Windows/<name>.dll / .exe
    │                 → Windows/<name>.blob  (if PE reconstruction fails)
    │                        │
    └─ File table  ──► Write data files to original CE paths
                       → <out>/<wince-path>/...
                              │
                        physfirst known?
                        (ECECT or --physfirst)
                              │
                    ┌─────────┴──────────┐
                   YES                   NO
                    │                    │
              Direct e32_rom         PE header
              header scan            carve only
              → PE reconstruction
              → .blob fallback
                    │                    │
                    └─────────┬──────────┘
                              │
                     PE header carve
                     (scan flat for MZ/PE,
                      extract any embedded
                      PE files missed above)
                              │
                     FlashFX 3.00 detect
                     (log filesystem blocks
                      if present)

         │                    │
         └──────────┬─────────┘
                    │
            manifest.json
            sha256sums.txt
            unpack.log
```

**What you get depends on the image type:**

| Image type | Module extraction method | Data files |
|---|---|---|
| HEX / BGZ ROMIMAGE | TOC walk → full PE reconstruction | Yes — from file table |
| BGZ RAMIMAGE (physfirst known) | Direct e32_rom scan → PE reconstruction | No (no file table) |
| BGZ RAMIMAGE (physfirst unknown) | PE header carve only | No |

---

## Confirmed Devices / Platforms

| Device | Platform | CE Version | Format |
|--------|----------|------------|--------|
| WT41N0 | OMAP4460 | CE 7 | BGZ / HEX |
| WT4090 | PXA270 | CE 5 | HEX |

Any Symbol/Motorola/Zebra device using the same HEX or BGZ format conventions should work. The WT4090 HEX image carries 7 co-resident partitions (OS, Monitor bootloader, clean platform, clean application, user-data regions) — HEXtractor extracts whichever partition is in the input file.

---

## Notes

- Modules written as `.blob` files failed PE reconstruction. The raw ROM bytes are preserved and can be loaded in a disassembler at the module's `e32_vbase` address.
- The manifest at `_meta/manifest.json` contains the flat file offset and byte range for every module, enabling manual extraction or Ghidra batch import.
- For BGZ RAMIMAGE images (no embedded ROMHDR), HEXtractor falls back to a direct `e32_rom` header scan using the known `physfirst`. This path yields fewer modules than the TOC walk but requires no ROMHDR.
