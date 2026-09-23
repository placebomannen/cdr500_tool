#!/usr/bin/env python3
"""Siemens VDO CDR 500(E) EEPROM (24C16) Tool.

This module provides an interactive utility to inspect, decode, and patch
24C16 I2C EEPROM dumps from Siemens VDO CDR 500(E) car radios.

Credits:
    Reverse Engineering & Research: placebomannen
"""

from pathlib import Path
import sys
from typing import Dict, Optional, Tuple, Union

APP_AUTHOR = "placebomannen"
APP_VERSION = "1.0.0"

XOR_KEY_HIGH = 0x7E
XOR_KEY_LOW = 0x9C

EXPECTED_DUMP_SIZE = 2048
MIN_FILE_SIZE = 0x80
MIN_SECURITY_BLOCK_SPAN = 28
ANCHOR_SIGNATURE = b"\x5A\x11"
ANCHOR_SEARCH_START = 0x40
ANCHOR_SEARCH_END = 0xA0


class EEPROMFormatError(ValueError):
  """Raised when EEPROM data layout does not conform to CDR 500 specifications."""

  pass


class OperationCancelled(Exception):
  """Raised when a user voluntarily aborts an interactive input prompt."""

  pass


def find_security_block(data: bytes, verbose: bool = True) -> int:
  """Locates the security configuration block using the 5A 11 anchor signature.

  Args:
      data: Raw binary contents of the EEPROM dump.
      verbose: When True, prints progress messages to stdout.

  Returns:
      The integer start offset of the security configuration block.

  Raises:
      EEPROMFormatError: If the data is too small, the signature is missing,
        or the buffer ends before all security registers can be read.
  """
  if len(data) < MIN_FILE_SIZE:
    raise EEPROMFormatError(
        f"File is too small ({len(data)} bytes). A valid 24C16 EEPROM dump "
        f"must be at least {MIN_FILE_SIZE} bytes (standard is"
        f" {EXPECTED_DUMP_SIZE} bytes)."
    )

  if verbose:
    print(
        f"[*] Searching for security anchor (0x5A 0x11) between"
        f" 0x{ANCHOR_SEARCH_START:02X} and 0x{ANCHOR_SEARCH_END:02X}..."
    )

  pos = data.find(ANCHOR_SIGNATURE, ANCHOR_SEARCH_START, ANCHOR_SEARCH_END)
  if pos == -1:
    raise EEPROMFormatError(
        "Missing security signature (5A 11) between offsets "
        f"0x{ANCHOR_SEARCH_START:02X} and 0x{ANCHOR_SEARCH_END:02X}. "
        "The file is not a supported CDR 500 dump or memory is corrupted."
    )

  if len(data) < pos + MIN_SECURITY_BLOCK_SPAN:
    raise EEPROMFormatError(
        f"Truncated EEPROM dump: Security block found at 0x{pos:02X}, but "
        f"requires at least {MIN_SECURITY_BLOCK_SPAN} bytes ahead (found only"
        f" {len(data) - pos} bytes)."
    )

  if verbose:
    print(f"[+] Located security configuration block at offset 0x{pos:02X}.")

  return pos


def parse_unit_metadata(
    data: bytes, verbose: bool = True
) -> Tuple[str, str]:
  """Extracts the GM catalog number and radio serial number from the header.

  Args:
      data: Raw binary contents of the EEPROM dump.
      verbose: When True, prints progress messages to stdout.

  Returns:
      A tuple containing (part_number, serial_number) as stripped strings.
  """
  if verbose:
    print("[*] Extracting unit metadata and serial information...")

  gm_pos = data.find(b"GM0", 0x10, 0x30)
  if gm_pos != -1 and len(data) >= gm_pos + 14:
    serial = (
        data[gm_pos : gm_pos + 14].decode("ascii", errors="replace").strip()
    )
  elif len(data) >= 0x29:
    serial = data[0x1B:0x29].decode("ascii", errors="replace").strip()
  else:
    serial = "UNKNOWN"

  if len(data) >= 0x0B:
    part_no = data[0x03:0x0B].decode("ascii", errors="replace").strip()
  else:
    part_no = "UNKNOWN"

  return part_no, serial


def decode_cdr500_dump(
    data: bytes, verbose: bool = True
) -> Dict[str, Union[str, int, bool]]:
  """Decodes radio security PIN, remaining attempts, and protection status.

  Args:
      data: Raw binary contents of the EEPROM dump.
      verbose: When True, prints operational steps to stdout.

  Returns:
      A dictionary containing unit metadata, security code, attempt counter,
      and layout validation flags.

  Raises:
      EEPROMFormatError: If the EEPROM structure fails validation checks.
  """
  base = find_security_block(data, verbose=verbose)

  if verbose:
    print("[*] Reading encrypted PIN bytes and applying XOR mask (0x7E9C)...")

  code_high = data[base + 9] ^ XOR_KEY_HIGH
  code_low = data[base + 10] ^ XOR_KEY_LOW
  code = f"{code_high:02X}{code_low:02X}"

  if verbose:
    print(
        "[*] Reading entry attempt counter and security protection"
        " registers..."
    )

  attempts = data[base + 25]
  flag_before = data[base + 23 : base + 25]
  flag_after = data[base + 26 : base + 28]

  is_no_code = (flag_before == b"\x00\x00") and (flag_after == b"\x00\x00")
  part_no, serial = parse_unit_metadata(data, verbose=verbose)

  return {
      "part_number": part_no,
      "serial": serial,
      "code": code,
      "attempts": attempts,
      "is_no_code": is_no_code,
      "valid_bcd": code.isdigit(),
      "base_offset": base,
      "size_warning": len(data) != EXPECTED_DUMP_SIZE,
  }


def patch_dump(
    data: bytes,
    reset_attempts: bool = False,
    new_code: Optional[str] = None,
    disable_code: bool = False,
    enable_code: bool = False,
) -> bytearray:
  """Applies requested modifications to the EEPROM binary buffer.

  Args:
      data: Original binary EEPROM dump.
      reset_attempts: When True, resets attempt counter back to 10 (0x0A).
      new_code: Optional 4-digit decimal string to set as the new PIN.
      disable_code: When True, configures the dump for 'No Code' operation.
      enable_code: When True, restores active code entry security checks.

  Returns:
      A modified bytearray ready to be written to a file.

  Raises:
      EEPROMFormatError: If the security structure is invalid.
      ValueError: If new_code is not a valid 4-digit decimal string.
  """
  buf = bytearray(data)
  print("[*] Initializing buffer and searching for security registers...")
  base = find_security_block(buf, verbose=False)

  if reset_attempts:
    print(
        f"[*] Resetting attempt counter at offset 0x{base + 25:02X} to 10"
        " (0x0A)..."
    )
    buf[base + 25] = 0x0A

  if new_code is not None:
    if len(new_code) != 4 or not new_code.isdigit():
      raise ValueError(
          f"Invalid code '{new_code}'. PIN must consist of exactly 4 decimal"
          " digits (0000-9999)."
      )

    val_high = int(new_code[0:2], 16) ^ XOR_KEY_HIGH
    val_low = int(new_code[2:4], 16) ^ XOR_KEY_LOW
    print(
        f"[*] Encrypting PIN {new_code} -> (0x{val_high:02X} 0x{val_low:02X})..."
    )
    print(
        f"[*] Writing encrypted PIN to offsets 0x{base + 9:02X} and"
        f" 0x{base + 10:02X}..."
    )
    buf[base + 9] = val_high
    buf[base + 10] = val_low

  if disable_code:
    print(
        "[*] Clearing security flag registers (setting 'No Code'"
        " status)..."
    )
    buf[base + 23 : base + 25] = b"\x00\x00"
    buf[base + 26 : base + 28] = b"\x00\x00"
    buf[base + 25] = 0x0A

    print(
        "[*] Searching for early anti-theft config block (0x0F 0x3E"
        " 0x80)..."
    )
    early_cfg = buf.find(b"\x0F\x3E\x80", 0x30, base)
    if early_cfg != -1 and early_cfg + 3 < len(buf):
      print(
          "[*] Disabling global anti-theft flag at offset"
          f" 0x{early_cfg + 3:02X}..."
      )
      buf[early_cfg + 3] = 0x00

  elif enable_code:
    print("[*] Setting active security flags (0x0201 / 0x7D01)...")
    buf[base + 23 : base + 25] = b"\x02\x01"
    buf[base + 26 : base + 28] = b"\x7D\x01"
    buf[base + 25] = 0x0A

    print(
        "[*] Searching for early anti-theft config block (0x0F 0x3E"
        " 0x80)..."
    )
    early_cfg = buf.find(b"\x0F\x3E\x80", 0x30, base)
    if early_cfg != -1 and early_cfg + 3 < len(buf):
      print(
          "[*] Activating global anti-theft flag at offset"
          f" 0x{early_cfg + 3:02X}..."
      )
      buf[early_cfg + 3] = 0x02

  return buf


def prompt_file_path(prompt_text: str) -> Path:
  """Prompts user for an existing file path, handling quotes and abort signals.

  Args:
      prompt_text: Message displayed to user.

  Returns:
      A validated Path object pointing to an existing file.

  Raises:
      OperationCancelled: If the user inputs an exit command or interrupts.
  """
  while True:
    try:
      raw_in = input(prompt_text).strip().strip("'\"")
    except (KeyboardInterrupt, EOFError):
      print("\n[!] Input aborted by user.")
      raise OperationCancelled()

    if raw_in.lower() in ("q", "quit", "exit", "cancel"):
      raise OperationCancelled()

    if not raw_in:
      print("No path provided. Please try again (or 'q' to return to menu).")
      continue

    try:
      p = Path(raw_in)
      if p.is_file():
        return p
      if p.is_dir():
        print(f"Error: '{p}' is a directory, not a file.")
        continue
      print(f"Error: File not found at '{p}'. Check the path and try again.")
    except OSError as err:
      print(f"Error: Invalid filesystem path syntax: {err}")


def prompt_save_path(default_name: str) -> Path:
  """Prompts user for destination path with collision and validity checks.

  Args:
      default_name: Suggested fallback filename.

  Returns:
      A Path object pointing to the confirmed save location.

  Raises:
      OperationCancelled: If the user inputs an exit command or interrupts.
  """
  while True:
    try:
      raw_in = (
          input(f"Save as [{default_name}] (or 'q' to cancel): ")
          .strip()
          .strip("'\"")
      )
    except (KeyboardInterrupt, EOFError):
      print("\n[!] Input aborted by user.")
      raise OperationCancelled()

    if raw_in.lower() in ("q", "quit", "exit", "cancel"):
      raise OperationCancelled()

    target_str = default_name if not raw_in else raw_in

    try:
      chosen_path = Path(target_str)

      if chosen_path.is_dir():
        print(
            f"Error: '{chosen_path}' is a directory. Please provide a file"
            " name."
        )
        continue

      if chosen_path.exists():
        try:
          confirm = (
              input(
                  f"Warning: '{chosen_path}' already exists. Overwrite? (y/N): "
              )
              .strip()
              .lower()
          )
        except (KeyboardInterrupt, EOFError):
          print("\n[!] Input aborted by user.")
          raise OperationCancelled()

        if confirm != "y":
          print("Please choose a different filename.")
          continue

      return chosen_path

    except OSError as err:
      print(f"Error: Invalid path syntax: {err}")


def prompt_code() -> str:
  """Prompts user for a 4-digit decimal PIN.

  Returns:
      A validated 4-character string of decimal digits.

  Raises:
      OperationCancelled: If the user inputs an exit command or interrupts.
  """
  while True:
    try:
      code = (
          input("Enter new 4-digit code (0000-9999, or 'q' to cancel): ")
          .strip()
          .strip("'\"")
      )
    except (KeyboardInterrupt, EOFError):
      print("\n[!] Input aborted by user.")
      raise OperationCancelled()

    if code.lower() in ("q", "quit", "exit", "cancel"):
      raise OperationCancelled()

    if len(code) == 4 and code.isdigit():
      return code
    print("Invalid format. The code must consist of exactly 4 decimal digits.")


def display_info(info: Dict[str, Union[str, int, bool]], filename: str):
  """Prints decoded metadata and diagnostic status to the terminal.

  Args:
      info: Dictionary generated by decode_cdr500_dump().
      filename: Source filename used for presentation.
  """
  print("\n" + "=" * 56)
  print(f" FILE: {filename}")
  print("=" * 56)
  print(f" Serial Number:       {info['serial']}")
  print(f" GM Part Number:      {info['part_number']}")
  print(f" Stored Code:         {info['code']}")
  print(f" Attempts Left:       {info['attempts']}")

  if info["is_no_code"]:
    print(" Code Protection:     DISABLED (No Code - Unit starts without PIN)")
  else:
    print(" Code Protection:     ACTIVE (PIN required upon power loss)")

  if not info["valid_bcd"]:
    print(" Integrity Status:    CORRUPT - Stored code contains non-BCD digits")
  elif info["attempts"] == 0:
    print(" Lockout Status:      LOCKED (Display shows 'SAFE' - Reset required)")
  else:
    print(" Operational Status:  OK")

  if info["size_warning"]:
    print(
        " Hardware Warning:    Dump size is not 2048 bytes (Verify reader"
        " dump)"
    )

  print("=" * 56 + "\n")


def safe_commit_patch(out_path: Path, patched_data: bytearray):
  """Validates modified buffer integrity and writes it safely to disk.

  Args:
      out_path: Destination file path.
      patched_data: Modified EEPROM bytearray.
  """
  print("[*] Verifying patched data in memory before writing to disk...")
  try:
    verification = decode_cdr500_dump(patched_data, verbose=False)
    print("[+] In-memory verification passed.")
  except EEPROMFormatError as err:
    print(
        f"\n[FATAL ERROR] Post-patch validation failed: {err}\nAborting write to"
        " protect EEPROM integrity.\n"
    )
    return

  print(f"[*] Writing {len(patched_data)} bytes to '{out_path}'...")
  try:
    out_path.write_bytes(patched_data)
    print(f"\n[SUCCESS] Patched dump written to: {out_path}")
    print(
        f"          Verification: Code={verification['code']}, "
        f"Attempts={verification['attempts']}, "
        f"NoCode={verification['is_no_code']}\n"
    )
  except PermissionError:
    print(f"\n[ERROR] Permission denied: Unable to write to '{out_path}'.\n")
  except OSError as err:
    print(f"\n[ERROR] Filesystem error while writing to '{out_path}': {err}\n")


def menu_read_dump():
  """Handles reading and displaying dump metadata."""
  try:
    filepath = prompt_file_path("\nDrag and drop your .bin file here: ")
    print(f"\n[*] Reading file '{filepath.name}' ({filepath.stat().st_size} bytes)...")
    data = filepath.read_bytes()
    info = decode_cdr500_dump(data, verbose=True)
    display_info(info, filepath.name)
  except OperationCancelled:
    print("[*] Operation cancelled.\n")
  except EEPROMFormatError as err:
    print(f"\n[ERROR] Header validation failed: {err}\n")
  except PermissionError:
    print("\n[ERROR] Permission denied: Unable to read file.\n")
  except OSError as err:
    print(f"\n[ERROR] Filesystem error: {err}\n")


def menu_disable_code():
  """Handles patching a dump to disable code protection."""
  try:
    filepath = prompt_file_path(
        "\nDrag and drop the dump to disable code on: "
    )
    print(f"\n[*] Reading file '{filepath.name}'...")
    data = filepath.read_bytes()
    info = decode_cdr500_dump(data, verbose=False)
    display_info(info, filepath.name)

    if info["is_no_code"]:
      print("[!] Notice: Code requirement is already disabled in this dump.")
      try:
        cont = input("Continue and patch anyway? (y/N): ").strip().lower()
      except (KeyboardInterrupt, EOFError):
        print("\n[*] Operation cancelled.\n")
        return
      if cont != "y":
        print("[*] Operation cancelled.\n")
        return

    out_default = f"{filepath.stem}_nocode.bin"
    out_path = prompt_save_path(out_default)

    patched = patch_dump(data, disable_code=True)
    safe_commit_patch(out_path, patched)

  except OperationCancelled:
    print("[*] Operation cancelled.\n")
  except (EEPROMFormatError, ValueError) as err:
    print(f"\n[ERROR] Modification aborted: {err}\n")
  except PermissionError:
    print("\n[ERROR] Permission denied: Unable to access file.\n")
  except OSError as err:
    print(f"\n[ERROR] Filesystem error: {err}\n")


def menu_enable_code():
  """Handles patching a dump to re-enable code protection."""
  try:
    filepath = prompt_file_path("\nDrag and drop the dump to enable code on: ")
    print(f"\n[*] Reading file '{filepath.name}'...")
    data = filepath.read_bytes()
    info = decode_cdr500_dump(data, verbose=False)
    display_info(info, filepath.name)

    if not info["is_no_code"]:
      print("[!] Notice: Code protection is already active in this dump.")
      try:
        cont = input("Continue and patch anyway? (y/N): ").strip().lower()
      except (KeyboardInterrupt, EOFError):
        print("\n[*] Operation cancelled.\n")
        return
      if cont != "y":
        print("[*] Operation cancelled.\n")
        return

    out_default = f"{filepath.stem}_code_enabled.bin"
    out_path = prompt_save_path(out_default)

    patched = patch_dump(data, enable_code=True)
    safe_commit_patch(out_path, patched)

  except OperationCancelled:
    print("[*] Operation cancelled.\n")
  except (EEPROMFormatError, ValueError) as err:
    print(f"\n[ERROR] Modification aborted: {err}\n")
  except PermissionError:
    print("\n[ERROR] Permission denied: Unable to access file.\n")
  except OSError as err:
    print(f"\n[ERROR] Filesystem error: {err}\n")


def menu_reset_attempts():
  """Handles resetting the attempt counter back to 10."""
  try:
    filepath = prompt_file_path("\nDrag and drop the locked dump here: ")
    print(f"\n[*] Reading file '{filepath.name}'...")
    data = filepath.read_bytes()
    info = decode_cdr500_dump(data, verbose=False)
    display_info(info, filepath.name)

    if info["attempts"] == 10:
      print(
          "[!] Notice: Attempt counter is already at the maximum value of 10."
      )
      try:
        cont = input("Continue and patch anyway? (y/N): ").strip().lower()
      except (KeyboardInterrupt, EOFError):
        print("\n[*] Operation cancelled.\n")
        return
      if cont != "y":
        print("[*] Operation cancelled.\n")
        return

    out_default = f"{filepath.stem}_reset.bin"
    out_path = prompt_save_path(out_default)

    patched = patch_dump(data, reset_attempts=True)
    safe_commit_patch(out_path, patched)

  except OperationCancelled:
    print("[*] Operation cancelled.\n")
  except (EEPROMFormatError, ValueError) as err:
    print(f"\n[ERROR] Reset failed: {err}\n")
  except PermissionError:
    print("\n[ERROR] Permission denied: Unable to access file.\n")
  except OSError as err:
    print(f"\n[ERROR] Filesystem error: {err}\n")


def menu_change_code():
  """Handles setting a custom security PIN."""
  try:
    filepath = prompt_file_path("\nDrag and drop the dump to modify: ")
    print(f"\n[*] Reading file '{filepath.name}'...")
    data = filepath.read_bytes()
    info = decode_cdr500_dump(data, verbose=False)
    display_info(info, filepath.name)

    new_code = prompt_code()
    if str(info["code"]) == new_code:
      print(f"[!] Notice: Dump already contains PIN {new_code}.")

    out_default = f"{filepath.stem}_code_{new_code}.bin"
    out_path = prompt_save_path(out_default)

    patched = patch_dump(data, new_code=new_code)
    safe_commit_patch(out_path, patched)

  except OperationCancelled:
    print("[*] Operation cancelled.\n")
  except (EEPROMFormatError, ValueError) as err:
    print(f"\n[ERROR] Code change failed: {err}\n")
  except PermissionError:
    print("\n[ERROR] Permission denied: Unable to access file.\n")
  except OSError as err:
    print(f"\n[ERROR] Filesystem error: {err}\n")


def menu_show_credits():
  """Displays program metadata and research attribution."""
  print("\n" + "=" * 56)
  print("                   CREDITS & ABOUT")
  print("=" * 56)
  print(" Tool:                Siemens VDO CDR 500(E) EEPROM Utility")
  print(f" Version:             {APP_VERSION}")
  print(f" Reverse Engineering: {APP_AUTHOR}")
  print(" Target Architecture: 24C16 (I2C EEPROM, 2048 bytes)")
  print(" Decryption Method:   16-bit XOR Masking (0x7E9C)")
  print(" Key Operations:      Decryption, Counter Reset, 'No Code' Patch")
  print("=" * 56 + "\n")


def main():
  """Main loop dispatching menu commands."""
  while True:
    print("-" * 56)
    print("    SIEMENS VDO CDR 500(E) - EEPROM TOOL (24C16)")
    print(f"        Research & Reverse Engineering: {APP_AUTHOR}")
    print("-" * 56)
    print("1. Read code, status, and No Code state")
    print("2. Disable code requirement (Patch to 'No Code')")
    print("3. Enable code requirement (Restore code prompt)")
    print("4. Reset SAFE lock / counter (Restore 10 attempts)")
    print("5. Change stored radio code")
    print("6. About & Credits")
    print("7. Exit")
    print("-" * 56)

    try:
      choice = input("Select an option (1-7): ").strip()
    except (KeyboardInterrupt, EOFError):
      print("\n\nExiting tool.")
      sys.exit(0)

    if choice == "1":
      menu_read_dump()
    elif choice == "2":
      menu_disable_code()
    elif choice == "3":
      menu_enable_code()
    elif choice == "4":
      menu_reset_attempts()
    elif choice == "5":
      menu_change_code()
    elif choice == "6":
      menu_show_credits()
    elif choice == "7" or choice.lower() in ("q", "exit", "quit"):
      print("Exiting tool.")
      sys.exit(0)
    else:
      print("Invalid option. Please choose a number between 1 and 7.\n")


if __name__ == "__main__":
  main()