# cdr500_tool
# Siemens VDO CDR 500(E) EEPROM Utility

An interactive, zero-dependency Python tool designed to inspect, decode, verify, and patch 24C16 I²C EEPROM dumps from Siemens VDO CDR 500 and CDR 500(E) head units (Opel / Vauxhall / GM).

---

## Features

- **XOR PIN Recovery:** Decodes the stored 4-digit security code via 16-bit XOR masking (`0x7E9C`).
- **Dynamic Header Alignment:** Scans for the `5A 11` anchor signature between `0x40` and `0xA0`, automatically compensating for ASCII header variances across hardware revisions.
- **"No Code" Patching:** Modifies security state registers so the unit powers on immediately without prompting for a PIN after battery disconnects.
- **SAFE Lockout Reset:** Restores exhausted code-entry attempts back to the factory maximum (10 attempts / `0x0A`).
- **Custom PIN Assignment:** Encrypts and writes user-selected 4-digit decimal PINs directly into the dump.
- **Real-Time Step Logging:** Outputs live operational feedback (`Reading...`, `Searching for...`, `Encrypting...`, `Verifying...`, `Writing...`).
- **Pre-Flight Checks & Warnings:** Detects redundant operations (e.g., clearing a dump that already has "No Code" set) and non-standard dump sizes.
- **Post-Patch Verification Engine:** Validates patched buffers in memory using the decoding engine prior to touching persistent storage.
- **Safe I/O & Navigation:** Features drag-and-drop file path cleaning, overwrite confirmation prompts, and safe mid-operation cancellation (`q`, `exit`, `cancel`, or `Ctrl+C`).

---

## Technical Specifications

| Parameter | Specification |
| :--- | :--- |
| **Target Units** | Siemens VDO CDR 500 / CDR 500(E) |
| **Supported EEPROM** | 24C16 (I²C Serial EEPROM, 2,048 bytes / 16 Kbit) |
| **Anchor Signature** | `0x5A 0x11` (Located between `0x40` and `0xA0`) |
| **Decryption Mask** | 16-bit XOR Key (`0x7E9C` -> High: `0x7E`, Low: `0x9C`) |
| **Encoding Format** | BCD (Binary-Coded Decimal) |
| **Minimum Valid Span** | Anchor offset + 28 bytes (`base + 0x1B`) |

---

## EEPROM Memory Map

All operational offsets are calculated dynamically relative to the `5A 11` anchor:

| Relative Offset | Span | Description | Normal Value | "No Code" Value |
| :--- | :--- | :--- | :--- | :--- |
| `+0x09` | 1 byte | Encrypted PIN (High Byte) | `PIN[0:2] ^ 0x7E` | `PIN[0:2] ^ 0x7E` |
| `+0x0A` | 1 byte | Encrypted PIN (Low Byte) | `PIN[2:4] ^ 0x9C` | `PIN[2:4] ^ 0x9C` |
| `+0x17` .. `+0x18` | 2 bytes | Pre-Counter State Register | `0x02 0x01` | `0x00 0x00` |
| `+0x19` | 1 byte | Attempt Counter | `0x0A` (10 tries) | `0x0A` (10 tries) |
| `+0x1A` .. `+0x1B` | 2 bytes | Post-Counter State Register | `0x7D 0x01` | `0x00 0x00` |
| Search `0x0F 0x3E 0x80` | +3 offset | Global Anti-Theft Status | `0x02` | `0x00` |

---

## Getting Started

### Prerequisites

- Python 3.7 or newer (fully compatible with Python 3.7 through 3.12+).
- Standard library only — no external dependencies (`pip`) required.
- A raw binary read (`.bin`) from a 24C16 programmer (CH341A, TL866, etc.).

### Installation

```bash
git clone https://github.com/placebomannen/cdr500_tool.git
cd cdr500_tool
```

### Usage
```bash
python cdr500_tool.py
```

---

## Credits & Attribution
* Reverse Engineering & Research: placebomannen
* Software Implementation: placebomannen

---

## Disclaimer
This utility is distributed for educational, research, and diagnostic preservation purposes only. Always create verified, untouched backups of your original EEPROM binary before flashing modified images back to hardware.
