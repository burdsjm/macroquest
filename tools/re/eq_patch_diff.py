#!/usr/bin/env python3
"""
EQ Patch Diff Tool

Compares two eqgame.exe binaries to identify what changed between patches.
Works standalone (no Ghidra/IDA needed) for quick triage after an EQ update.

Capabilities:
  - Extract and compare build version strings
  - Compare PE section layouts
  - Find functions that moved by matching byte patterns from the symbol DB
  - Generate a migration report showing which symbols need address updates

Usage:
    python3 eq_patch_diff.py <old_eqgame.exe> <new_eqgame.exe> [--db symbols.json]
    python3 eq_patch_diff.py --extract-version <eqgame.exe>
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PEInfo:
    """Parsed PE header information."""
    path: str
    sha256: str
    size: int
    image_base: int
    entry_point: int
    sections: list = field(default_factory=list)
    build_date: str = ""
    build_time: str = ""


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


def parse_pe(filepath: str) -> Optional[PEInfo]:
    """Parse minimal PE header info from an executable."""
    with open(filepath, "rb") as f:
        data = f.read()

    sha = hashlib.sha256(data).hexdigest()
    size = len(data)

    # DOS header
    if data[:2] != b"MZ":
        print(f"ERROR: {filepath} is not a valid PE file")
        return None

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # PE signature
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        print(f"ERROR: Invalid PE signature in {filepath}")
        return None

    # COFF header
    coff_offset = e_lfanew + 4
    machine, num_sections, _, _, _, optional_header_size, _ = struct.unpack_from(
        "<HHIIIHH", data, coff_offset
    )

    # Optional header
    opt_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, opt_offset)[0]

    if magic == 0x20B:  # PE32+ (64-bit)
        image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
        entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
    elif magic == 0x10B:  # PE32 (32-bit)
        image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
        entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
    else:
        print(f"ERROR: Unknown PE optional header magic: 0x{magic:x}")
        return None

    # Section headers
    section_offset = opt_offset + optional_header_size
    sections = []
    for i in range(num_sections):
        s_off = section_offset + i * 40
        s_name = data[s_off:s_off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        s_vsize, s_va, s_rawsize, s_rawoff = struct.unpack_from("<IIII", data, s_off + 8)
        sections.append(Section(s_name, s_va, s_vsize, s_rawoff, s_rawsize))

    info = PEInfo(
        path=filepath, sha256=sha, size=size,
        image_base=image_base, entry_point=entry_point, sections=sections,
    )

    # Extract version strings using the same pattern as MQ's GetEQGameVersionStrings
    info.build_date, info.build_time = extract_version_strings(data, info)

    return info


def extract_version_strings(data: bytes, pe: PEInfo) -> tuple:
    """
    Extract EQ build date/time from the binary.
    Searches for "Starting Ev" then follows x64 lea instructions backward
    to find the date and time string addresses.
    """
    # Find "Starting Ev" marker
    marker = b"Starting Ev"
    pos = data.find(marker)
    if pos == -1:
        return ("", "")

    # For 64-bit: search for the lea instruction sequence that references this string
    # Pattern: 4C 8D 05 xx xx xx xx  48 8D 15 xx xx xx xx  48 8D 0D xx xx xx xx
    #          lea r8, [time]        lea rdx, [date]        lea rcx, [fmt_str]

    # Convert physical offset to RVA
    marker_rva = physical_to_rva(pos, pe.sections)
    if marker_rva is None:
        return ("", "")

    pattern = bytes([0x4C, 0x8D, 0x05])  # lea r8, [rip+...]

    for i in range(len(data) - 21):
        if (data[i] == 0x4C and data[i+1] == 0x8D and data[i+2] == 0x05 and
            data[i+7] == 0x48 and data[i+8] == 0x8D and data[i+9] == 0x15 and
            data[i+14] == 0x48 and data[i+15] == 0x8D and data[i+16] == 0x0D):

            # Check if the lea rcx points to our "Starting Ev" string
            inst_rva = physical_to_rva(i, pe.sections)
            if inst_rva is None:
                continue

            # lea rcx displacement at offset 17-20
            rcx_disp = struct.unpack_from("<i", data, i + 17)[0]
            rcx_target_rva = inst_rva + 17 + 4 + rcx_disp

            if rcx_target_rva != marker_rva:
                continue

            # Found it! Now extract date and time
            # lea rdx, [date] at offset 10-13
            rdx_disp = struct.unpack_from("<i", data, i + 10)[0]
            date_rva = inst_rva + 10 + 4 + rdx_disp
            date_offset = rva_to_physical(date_rva, pe.sections)

            # lea r8, [time] at offset 3-6
            r8_disp = struct.unpack_from("<i", data, i + 3)[0]
            time_rva = inst_rva + 3 + 4 + r8_disp
            time_offset = rva_to_physical(time_rva, pe.sections)

            if date_offset and time_offset:
                build_date = read_cstring(data, date_offset)
                build_time = read_cstring(data, time_offset)
                return (build_date, build_time)

    return ("", "")


def physical_to_rva(offset: int, sections: list) -> Optional[int]:
    """Convert a physical file offset to an RVA."""
    for s in sections:
        if s.raw_offset <= offset < s.raw_offset + s.raw_size:
            return s.virtual_address + (offset - s.raw_offset)
    return None


def rva_to_physical(rva: int, sections: list) -> Optional[int]:
    """Convert an RVA to a physical file offset."""
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + s.virtual_size:
            return s.raw_offset + (rva - s.virtual_address)
    return None


def read_cstring(data: bytes, offset: int, max_len: int = 64) -> str:
    """Read a null-terminated string from binary data."""
    end = data.find(b"\x00", offset, offset + max_len)
    if end == -1:
        end = offset + max_len
    return data[offset:end].decode("ascii", errors="replace")


def find_pattern(data: bytes, pattern_str: str, sections: list,
                 start_rva: int = 0) -> Optional[int]:
    """
    Find a byte pattern with ?? wildcards in the binary.
    Returns the RVA of the match, or None.
    """
    parts = pattern_str.strip().split()
    if not parts:
        return None

    # Build search bytes and mask
    search_bytes = []
    mask = []
    for p in parts:
        if p == "??":
            search_bytes.append(0)
            mask.append(False)
        else:
            search_bytes.append(int(p, 16))
            mask.append(True)

    pat_len = len(search_bytes)

    # Search through executable sections
    for section in sections:
        if not (section.name in (".text", ".code", "CODE") or
                section.virtual_address <= start_rva < section.virtual_address + section.virtual_size):
            # Only search code sections or the section containing start_rva
            if section.name not in (".text",):
                continue

        s_start = section.raw_offset
        s_end = s_start + section.raw_size - pat_len

        for i in range(s_start, s_end):
            match = True
            for j in range(pat_len):
                if mask[j] and data[i + j] != search_bytes[j]:
                    match = False
                    break
            if match:
                rva = physical_to_rva(i, sections)
                if rva is not None:
                    return rva

    return None


def compare_binaries(old_pe: PEInfo, new_pe: PEInfo, db_path: Optional[str] = None):
    """Compare two EQ binaries and report differences."""

    print("=" * 70)
    print("EQ Patch Diff Report")
    print("=" * 70)
    print()
    print(f"OLD: {old_pe.path}")
    print(f"  Build:    {old_pe.build_date} {old_pe.build_time}")
    print(f"  SHA256:   {old_pe.sha256[:16]}...")
    print(f"  Size:     {old_pe.size:,} bytes")
    print(f"  Base:     0x{old_pe.image_base:x}")
    print()
    print(f"NEW: {new_pe.path}")
    print(f"  Build:    {new_pe.build_date} {new_pe.build_time}")
    print(f"  SHA256:   {new_pe.sha256[:16]}...")
    print(f"  Size:     {new_pe.size:,} bytes")
    print(f"  Base:     0x{new_pe.image_base:x}")
    print()

    # Section comparison
    print("SECTION COMPARISON:")
    print(f"  {'Name':<10} {'Old VA':>12} {'Old Size':>12} {'New VA':>12} {'New Size':>12} {'Delta':>10}")
    print("  " + "-" * 68)

    old_sections = {s.name: s for s in old_pe.sections}
    new_sections = {s.name: s for s in new_pe.sections}
    all_section_names = sorted(set(list(old_sections.keys()) + list(new_sections.keys())))

    for name in all_section_names:
        old_s = old_sections.get(name)
        new_s = new_sections.get(name)
        if old_s and new_s:
            delta = new_s.virtual_size - old_s.virtual_size
            delta_str = f"+{delta}" if delta > 0 else str(delta)
            print(f"  {name:<10} 0x{old_s.virtual_address:>8x}   {old_s.virtual_size:>10}   "
                  f"0x{new_s.virtual_address:>8x}   {new_s.virtual_size:>10}   {delta_str:>10}")
        elif new_s:
            print(f"  {name:<10} {'(new)':>12}   {'':>10}   0x{new_s.virtual_address:>8x}   {new_s.virtual_size:>10}")
        elif old_s:
            print(f"  {name:<10} 0x{old_s.virtual_address:>8x}   {old_s.virtual_size:>10}   {'(removed)':>12}")

    # Pattern-based symbol migration
    if db_path and os.path.exists(db_path):
        print()
        print("SYMBOL MIGRATION (pattern-based):")
        print(f"  {'Symbol':<45} {'Old RVA':>12} {'New RVA':>12} {'Status':>10}")
        print("  " + "-" * 80)

        with open(db_path, "r") as f:
            db = json.load(f)

        with open(old_pe.path, "rb") as f:
            old_data = f.read()
        with open(new_pe.path, "rb") as f:
            new_data = f.read()

        found = 0
        moved = 0
        lost = 0

        for name, info in db.get("functions", {}).items():
            pattern = info.get("pattern", "")
            old_addr = info.get("address", "")
            pat_offset = info.get("pattern_offset", 0)

            if not pattern:
                continue

            new_rva = find_pattern(new_data, pattern, new_pe.sections)
            if new_rva is not None:
                new_rva += pat_offset
                new_addr = f"0x{new_rva:x}"
                if old_addr and old_addr != new_addr:
                    print(f"  {name:<45} {old_addr:>12} {new_addr:>12} {'MOVED':>10}")
                    moved += 1
                else:
                    found += 1
            else:
                print(f"  {name:<45} {old_addr:>12} {'???':>12} {'LOST':>10}")
                lost += 1

        print()
        print(f"  Found at same address: {found}")
        print(f"  Moved to new address:  {moved}")
        print(f"  Pattern not found:     {lost} (need manual RE)")

    # Version string comparison
    print()
    if old_pe.build_date != new_pe.build_date or old_pe.build_time != new_pe.build_time:
        print("VERSION CHANGED: eqlib needs __ExpectedVersionDate and __ExpectedVersionTime updated")
        print(f"  Old: \"{old_pe.build_date}\" \"{old_pe.build_time}\"")
        print(f"  New: \"{new_pe.build_date}\" \"{new_pe.build_time}\"")
    else:
        print("VERSION UNCHANGED (same build)")

    if old_pe.image_base != new_pe.image_base:
        print()
        print(f"IMAGE BASE CHANGED: 0x{old_pe.image_base:x} -> 0x{new_pe.image_base:x}")
        print("  EQGamePreferredAddress must be updated in ProcessList.cpp and eqlib!")

    print()


def extract_version_only(filepath: str):
    """Just extract and print the version strings."""
    pe = parse_pe(filepath)
    if pe:
        print(f"File:  {pe.path}")
        print(f"Build: {pe.build_date} {pe.build_time}")
        print(f"SHA256: {pe.sha256}")
        print(f"Size: {pe.size:,}")
        print(f"Base: 0x{pe.image_base:x}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare EQ binaries to identify patch changes"
    )
    parser.add_argument("old_exe", nargs="?", help="Path to old eqgame.exe")
    parser.add_argument("new_exe", nargs="?", help="Path to new eqgame.exe")
    parser.add_argument("--db", help="Path to MQ symbol database (eq_symbols.json)")
    parser.add_argument("--extract-version", metavar="EXE",
                        help="Just extract version info from a single exe")
    args = parser.parse_args()

    if args.extract_version:
        extract_version_only(args.extract_version)
        return

    if not args.old_exe or not args.new_exe:
        parser.error("Both old and new eqgame.exe paths are required (or use --extract-version)")

    old_pe = parse_pe(args.old_exe)
    new_pe = parse_pe(args.new_exe)

    if not old_pe or not new_pe:
        sys.exit(1)

    compare_binaries(old_pe, new_pe, args.db)


if __name__ == "__main__":
    main()
