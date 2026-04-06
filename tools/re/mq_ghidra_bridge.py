# MacroQuest Ghidra Bridge - Import/Export MQ symbols to/from Ghidra projects
# @author MacroQuest Contributors
# @category MacroQuest
# @keybinding
# @menupath Tools.MacroQuest.Bridge
# @toolbar
#
# Run inside Ghidra's Script Manager against an eqgame.exe binary.
# Supports two modes:
#   1. IMPORT: Load known MQ symbols from eq_symbols.json into the Ghidra project
#              (labels, comments, function signatures, bookmarks)
#   2. EXPORT: Export current Ghidra analysis back to eq_symbols.json
#              (discovered addresses, xrefs, patterns)
#
# This script uses the Ghidra Python (Jython) API. It will NOT run under
# standard CPython -- it requires Ghidra's script environment.

from __future__ import print_function
import json
import os
import hashlib
import time

# Ghidra imports (available when running inside Ghidra)
try:
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.address import AddressSet
    from ghidra.app.util.opinion import ElfLoader
    from ghidra.util.task import ConsoleTaskMonitor
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Default path relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else "."
DEFAULT_DB_PATH = os.path.join(SCRIPT_DIR, "eq_symbols.json")

# MQ symbol categories and their colors for Ghidra bookmarks
CATEGORY_COLORS = {
    "memcheck":     "Red",
    "module_enum":  "Orange",
    "process_enum": "Orange",
    "compression":  "Yellow",
    "rendering":    "Blue",
    "input":        "Cyan",
    "ui":           "Green",
    "spell":        "Magenta",
    "chat":         "Green",
    "player":       "Cyan",
    "keybind":      "Blue",
    "login":        "Yellow",
    "display":      "Blue",
    "inventory":    "Green",
    "version":      "Red",
    "other":        "White",
}

# The complete list of MQ symbols we track. This is the bridge between
# eqlib's __DoubleUnderscore names and what we find in eqgame.exe.
MQ_KNOWN_SYMBOLS = {
    # --- Anti-cheat / Memory checking ---
    "__MemChecker0":        {"category": "memcheck",     "sig": "int __cdecl(unsigned char* buffer, size_t count)"},
    "__MemChecker1":        {"category": "memcheck",     "sig": "int __cdecl(unsigned char* buffer, size_t count, int key)"},
    "__MemChecker4":        {"category": "memcheck",     "sig": "int __stdcall(unsigned char* buffer, size_t* count)"},
    "__EncryptPad0":        {"category": "memcheck",     "sig": "uint32_t[256]"},

    # --- Module/Process enumeration (hooked to hide MQ) ---
    "__ModuleList":         {"category": "module_enum",  "sig": "BOOL WINAPI(HANDLE, HMODULE*, DWORD, DWORD*)"},
    "__ProcessList":        {"category": "process_enum", "sig": "BOOL WINAPI(DWORD*, DWORD, DWORD*)"},

    # --- Compression ---
    "__compress_block":     {"category": "compression",  "sig": "uint64_t __cdecl(uint64_t ctx)"},
    "__decompress_block":   {"category": "compression",  "sig": "uint64_t __cdecl(uint64_t ctx)"},

    # --- Version strings ---
    "__ActualVersionDate":  {"category": "version",      "sig": "const char*"},
    "__ActualVersionTime":  {"category": "version",      "sig": "const char*"},

    # --- Rendering ---
    "CRender__RenderScene":       {"category": "rendering", "sig": "void __thiscall(void)"},
    "CRender__RenderBlind":       {"category": "rendering", "sig": "void __thiscall(void)"},
    "CRender__UpdateDisplay":     {"category": "rendering", "sig": "void __thiscall(void)"},
    "CRender__ResetDevice":       {"category": "rendering", "sig": "void __thiscall(bool)"},

    # --- Display ---
    "CDisplay__RealRender_World":  {"category": "display",  "sig": "void __thiscall(void)"},
    "CDisplay__GetClickedActor":   {"category": "display",  "sig": "void __thiscall(int, int, bool, CVector3&, CVector3&)"},
    "CDisplay__ZoneMainUI":        {"category": "display",  "sig": "void __thiscall(void)"},
    "CDisplay__PreZoneMainUI":     {"category": "display",  "sig": "void __thiscall(void)"},
    "CDisplay__CleanGameUI":       {"category": "display",  "sig": "void __thiscall(void)"},
    "CDisplay__ReloadUI":          {"category": "display",  "sig": "void __thiscall(bool, bool)"},
    "CDisplay__InitCharSelectUI":  {"category": "display",  "sig": "void __thiscall(void)"},
    "CDisplay__RestartUI":         {"category": "display",  "sig": "void __thiscall(bool, bool)"},

    # --- Input ---
    "__ProcessMouseEvents":          {"category": "input", "sig": "void __cdecl(void)"},
    "__HandleMouseWheel":            {"category": "input", "sig": "void __cdecl(int)"},
    "__ProcessKeyboardEvents":       {"category": "input", "sig": "void __cdecl(void)"},
    "__WndProc":                     {"category": "input", "sig": "LRESULT __stdcall(HWND, UINT, WPARAM, LPARAM)"},
    "KeypressHandler__HandleKeyDown": {"category": "keybind", "sig": "int __thiscall(unsigned int, int, int)"},
    "KeypressHandler__HandleKeyUp":   {"category": "keybind", "sig": "int __thiscall(unsigned int, int, int)"},
    "KeypressHandler__ClearCommandStateArray": {"category": "keybind", "sig": "void __thiscall(void)"},

    # --- UI ---
    "CXWndManager__DrawWindows":     {"category": "ui", "sig": "int __thiscall(void)"},

    # --- Chat ---
    "CEverQuest__DoTellWindow":       {"category": "chat", "sig": "void __thiscall(char*, char*, char*, void*, int, bool)"},
    "CEverQuest__UPCNotificationFlush": {"category": "chat", "sig": "void __thiscall(void)"},
    "CEverQuest__OutputTextToLog":    {"category": "chat", "sig": "void __thiscall(const char*)"},
    "CEverQuest__InterpretCmd":       {"category": "chat", "sig": "void __thiscall(PlayerClient*, const char*)"},
    "CEverQuest__SetGameState":       {"category": "chat", "sig": "void __thiscall(int)"},

    # --- Player ---
    "PlayerClient__SetNameSpriteState": {"category": "player", "sig": "int __thiscall(bool)"},
    "PlayerClient__SetNameSpriteTint":  {"category": "player", "sig": "bool __thiscall(void)"},

    # --- Spell ---
    "Spellmanager__LoadTextSpells":   {"category": "spell", "sig": "bool __thiscall(char*, char*, EQ_Spell*)"},
    "CSpellDisplayWnd__UpdateStrings": {"category": "spell", "sig": "void __thiscall(void)"},
    "CItemDisplayWnd__UpdateStrings": {"category": "spell", "sig": "void __thiscall(void)"},
    "CItemDisplayWnd__SetItem":       {"category": "spell", "sig": "void __thiscall(ItemPtr, bool)"},

    # --- Inventory ---
    "CFindItemWnd__WndNotification":  {"category": "inventory", "sig": "int __thiscall(CXWnd*, unsigned int, void*)"},
    "CFindItemWnd__Update":           {"category": "inventory", "sig": "void __thiscall(void)"},
    "CBarterSearchWnd__WndNotification": {"category": "inventory", "sig": "int __thiscall(CXWnd*, unsigned int, void*)"},
    "CBarterSearchWnd__UpdateInventoryList": {"category": "inventory", "sig": "void __thiscall(void)"},
    "CBarterWnd__WndNotification":    {"category": "inventory", "sig": "int __thiscall(CXWnd*, unsigned int, void*)"},

    # --- Login ---
    "EQMain__LoginController__GiveTime": {"category": "login", "sig": "void __thiscall(void)"},
    "EQMain__WndProc":               {"category": "login", "sig": "LRESULT __stdcall(HWND, UINT, WPARAM, LPARAM)"},

    # --- Frame/Game ---
    "__ProcessGameEvents":           {"category": "other", "sig": "void __cdecl(void)"},
    "__ThrottleFrameRate":           {"category": "other", "sig": "void __cdecl(void)"},
    "__GetGaugeValueFromEQ":         {"category": "other", "sig": "int __cdecl(int, EQ_Spell*, unsigned char*)"},
    "__ShowSpell_x":                 {"category": "other", "sig": "void __cdecl(int)"},
    "CTargetWnd__RefreshTargetBuffs": {"category": "other", "sig": "void __thiscall(BYTE*)"},
    "__DoesFileExist":               {"category": "other", "sig": "bool __cdecl(const char*)"},
    "__XMLRead":                     {"category": "other", "sig": "int __cdecl(const char*, const char*, void*)"},

    # --- Text ---
    "CTextureFont__DrawWrappedText":  {"category": "ui", "sig": "int __thiscall(const CXStr&, const CXRect&, const CXRect&, COLORREF, uint16_t, int)"},
    "CTextureFont__DrawWrappedText1": {"category": "ui", "sig": "int __thiscall(const CXStr&, int, int, int, const CXRect&, COLORREF, uint16_t, int)"},
    "CTextureFont__DrawWrappedText2": {"category": "ui", "sig": "int __thiscall(CTextureFont*, const CXStr&, int, int, int, int, COLORREF, uint16_t, int)"},

    # --- Graphics primitives ---
    "C2DPrimitiveManager__AddCachedText": {"category": "rendering", "sig": "void __thiscall(void)"},
    "C2DPrimitiveManager__Render":   {"category": "rendering", "sig": "void __thiscall(void)"},
    "CParticleSystem__Render":       {"category": "rendering", "sig": "void __thiscall(void)"},
    "CParticleSystem__CreateSpellEmitter": {"category": "rendering", "sig": "void __thiscall(void)"},

    # --- Loading ---
    "EQ_LoadingS__Array_x":          {"category": "other", "sig": "void*"},
}


# ---------------------------------------------------------------------------
# Ghidra helper functions (only callable inside Ghidra)
# These functions reference Ghidra APIs and will fail if called outside
# the Ghidra script environment. They are only invoked from the
# GHIDRA_AVAILABLE guard at the bottom of this file.
# ---------------------------------------------------------------------------

def get_image_base():
    """Get the image base address of the current program."""
    return currentProgram.getImageBase()


def addr(rva_str):
    """Convert an RVA hex string to an Address object."""
    rva = int(rva_str, 16)
    return get_image_base().add(rva)


def addr_to_rva(address):
    """Convert a Ghidra Address to an RVA hex string."""
    rva = address.subtract(get_image_base())
    return "0x{:x}".format(rva)


def get_function_at(address):
    """Get the Function object at an address, or None."""
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionAt(address)


def get_or_create_function(address, name):
    """Get existing function or create one at the address."""
    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionAt(address)
    if func is None:
        from ghidra.app.cmd.function import CreateFunctionCmd
        cmd = CreateFunctionCmd(address)
        cmd.applyTo(currentProgram, ConsoleTaskMonitor.DUMMY)
        func = fm.getFunctionAt(address)
    return func


def set_label(address, name):
    """Set a primary label at the given address."""
    st = currentProgram.getSymbolTable()
    st.createLabel(address, name, SourceType.USER_DEFINED)


def set_comment(address, comment, comment_type=None):
    """Set a comment at the given address."""
    if comment_type is None:
        comment_type = CodeUnit.EOL_COMMENT
    listing = currentProgram.getListing()
    cu = listing.getCodeUnitAt(address)
    if cu is not None:
        cu.setComment(comment_type, comment)


def set_bookmark(address, category, description):
    """Add a bookmark at the given address."""
    bm = currentProgram.getBookmarkManager()
    bm.setBookmark(address, "Analysis", category, description)


def get_xrefs_to(address):
    """Get all cross-references to an address."""
    ref_mgr = currentProgram.getReferenceManager()
    refs = ref_mgr.getReferencesTo(address)
    result = []
    for ref in refs:
        from_addr = ref.getFromAddress()
        fm = currentProgram.getFunctionManager()
        func = fm.getFunctionContaining(from_addr)
        if func:
            result.append(func.getName())
        else:
            result.append(addr_to_rva(from_addr))
    return result


def get_xrefs_from(func):
    """Get all functions called by a function."""
    result = []
    if func is None:
        return result
    body = func.getBody()
    ref_mgr = currentProgram.getReferenceManager()
    addr_iter = body.getAddresses(True)
    while addr_iter.hasNext():
        a = addr_iter.next()
        for ref in ref_mgr.getReferencesFrom(a):
            if ref.getReferenceType().isCall():
                fm = currentProgram.getFunctionManager()
                target_func = fm.getFunctionAt(ref.getToAddress())
                if target_func:
                    result.append(target_func.getName())
                else:
                    result.append(addr_to_rva(ref.getToAddress()))
    return list(set(result))


def extract_pattern(address, length=32):
    """Extract a byte pattern from an address, wildcarding relocation targets."""
    mem = currentProgram.getMemory()
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    pattern_bytes = []
    i = 0
    while i < length:
        a = address.add(i)
        # Check if this byte is part of a relocation/reference operand
        inst = listing.getInstructionAt(a)
        refs = ref_mgr.getReferencesFrom(a)

        byte_val = mem.getByte(a) & 0xFF

        # If this instruction has a reference from here, wildcard the operand bytes
        if inst is not None and len(list(refs)) > 0:
            # Wildcard the operand displacement (typically 4 bytes for x64 RIP-relative)
            pattern_bytes.append("??")
            # Skip ahead through the operand
            op_start = a
            for j in range(1, 4):
                if i + j < length:
                    pattern_bytes.append("??")
            i += 4
            continue

        pattern_bytes.append("{:02X}".format(byte_val))
        i += 1

    return " ".join(pattern_bytes[:length])


# ---------------------------------------------------------------------------
# Import: Load symbols from JSON into Ghidra
# ---------------------------------------------------------------------------

def import_symbols(db_path=DEFAULT_DB_PATH):
    """Import MQ symbol database into current Ghidra project."""
    if not GHIDRA_AVAILABLE:
        print("ERROR: Must be run inside Ghidra")
        return

    if not os.path.exists(db_path):
        print("No symbol database found at: {}".format(db_path))
        print("Run EXPORT first on a known-good eqgame.exe to create the database.")
        return

    with open(db_path, "r") as f:
        db = json.load(f)

    print("=" * 60)
    print("MQ Symbol Import")
    print("  Database version: {} {}".format(
        db["metadata"].get("eq_build_date", "?"),
        db["metadata"].get("eq_build_time", "?")))
    print("=" * 60)

    imported = 0
    skipped = 0

    from ghidra.program.model.listing import CodeUnit

    # Import functions
    for name, info in db.get("functions", {}).items():
        rva = info.get("address")
        if not rva:
            skipped += 1
            continue

        try:
            a = addr(rva)
            func = get_or_create_function(a, name)
            set_label(a, name)

            # Add category bookmark
            cat = info.get("category", "other")
            conf = info.get("confidence", "?")
            set_bookmark(a, "MQ_" + cat, "[{}] {}".format(conf, name))

            # Add signature as comment
            sig = info.get("signature", "")
            notes = info.get("notes", "")
            comment = "MQ: {} | {}".format(sig, notes) if notes else "MQ: {}".format(sig)
            set_comment(a, comment, CodeUnit.PLATE_COMMENT)

            # Add pattern as repeatable comment for future matching
            pat = info.get("pattern", "")
            if pat:
                set_comment(a, "Pattern: {}".format(pat), CodeUnit.REPEATABLE_COMMENT)

            imported += 1
        except Exception as e:
            print("  WARN: Failed to import {}: {}".format(name, e))
            skipped += 1

    # Import globals
    for name, info in db.get("globals", {}).items():
        rva = info.get("address")
        if not rva:
            skipped += 1
            continue

        try:
            a = addr(rva)
            set_label(a, name)
            cat = info.get("category", "global")
            set_bookmark(a, "MQ_global", name)

            type_str = info.get("type", "")
            if type_str:
                set_comment(a, "MQ Global: {} {}".format(type_str, name), CodeUnit.PLATE_COMMENT)

            imported += 1
        except Exception as e:
            print("  WARN: Failed to import global {}: {}".format(name, e))
            skipped += 1

    print("\nImported: {}  Skipped: {}".format(imported, skipped))
    print("Bookmarks added under MQ_* categories for easy filtering.")


# ---------------------------------------------------------------------------
# Export: Extract current Ghidra analysis to JSON
# ---------------------------------------------------------------------------

def export_symbols(db_path=DEFAULT_DB_PATH):
    """Export current analysis to MQ symbol database."""
    if not GHIDRA_AVAILABLE:
        print("ERROR: Must be run inside Ghidra")
        return

    # Build metadata
    prog_name = currentProgram.getName()
    exe_path = currentProgram.getExecutablePath()

    # Try to find version strings in the binary
    build_date = ""
    build_time = ""

    # Search for "Starting Ev" to find version string area (same logic as MQ loader)
    mem = currentProgram.getMemory()
    search_bytes = bytearray(b"Starting Ev")
    found = mem.findBytes(get_image_base(), search_bytes, None, True, ConsoleTaskMonitor.DUMMY)
    if found:
        print("Found version string reference at: {}".format(found))

    db = {
        "metadata": {
            "eq_build_date": build_date,
            "eq_build_time": build_time,
            "eq_exe_sha256": "",
            "image_base": "0x{:x}".format(get_image_base().getOffset()),
            "analyst": "ghidra_export",
            "date": time.strftime("%Y-%m-%d"),
            "notes": "Exported from Ghidra analysis of {}".format(prog_name),
        },
        "functions": {},
        "globals": {},
    }

    # Look for MQ-labeled symbols (from previous import or manual labeling)
    st = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()

    exported_funcs = 0
    exported_globals = 0

    # Export all symbols that match MQ naming conventions
    for sym in st.getAllSymbols(True):
        name = sym.getName()

        # Match eqlib naming: __Name or ClassName__MethodName
        is_mq_sym = (name in MQ_KNOWN_SYMBOLS or
                     name.startswith("__") or
                     "__" in name[1:])

        if not is_mq_sym:
            continue

        address = sym.getAddress()
        rva = addr_to_rva(address)
        func = fm.getFunctionAt(address)

        if func is not None:
            # It's a function
            entry = {
                "address": rva,
                "category": MQ_KNOWN_SYMBOLS.get(name, {}).get("category", "other"),
                "confidence": "confirmed" if name in MQ_KNOWN_SYMBOLS else "medium",
                "signature": MQ_KNOWN_SYMBOLS.get(name, {}).get("sig", ""),
                "xrefs_from": get_xrefs_to(address)[:20],
                "xrefs_to": get_xrefs_from(func)[:20],
            }

            # Extract byte pattern
            try:
                entry["pattern"] = extract_pattern(address)
            except Exception:
                pass

            # Preserve notes from plate comment
            listing = currentProgram.getListing()
            cu = listing.getCodeUnitAt(address)
            if cu:
                plate = cu.getComment(CodeUnit.PLATE_COMMENT)
                if plate and not plate.startswith("MQ:"):
                    entry["notes"] = plate

            db["functions"][name] = entry
            exported_funcs += 1
        else:
            # It's a global variable
            entry = {
                "address": rva,
                "confidence": "confirmed" if name in MQ_KNOWN_SYMBOLS else "medium",
                "type": MQ_KNOWN_SYMBOLS.get(name, {}).get("sig", ""),
            }
            if name in MQ_KNOWN_SYMBOLS:
                entry["category"] = MQ_KNOWN_SYMBOLS[name].get("category", "other")

            db["globals"][name] = entry
            exported_globals += 1

    # Write the database
    with open(db_path, "w") as f:
        json.dump(db, f, indent=2, sort_keys=True)

    print("=" * 60)
    print("MQ Symbol Export")
    print("  Output: {}".format(db_path))
    print("  Functions: {}".format(exported_funcs))
    print("  Globals:   {}".format(exported_globals))
    print("=" * 60)


# ---------------------------------------------------------------------------
# Diff: Compare two symbol databases to see what moved
# ---------------------------------------------------------------------------

def diff_databases(old_path, new_path):
    """Compare two symbol databases and report what changed."""
    with open(old_path, "r") as f:
        old_db = json.load(f)
    with open(new_path, "r") as f:
        new_db = json.load(f)

    print("=" * 70)
    print("EQ Patch Diff: {} -> {}".format(
        old_db["metadata"].get("eq_build_date", "?"),
        new_db["metadata"].get("eq_build_date", "?")))
    print("=" * 70)

    # Diff functions
    old_funcs = old_db.get("functions", {})
    new_funcs = new_db.get("functions", {})

    all_names = sorted(set(list(old_funcs.keys()) + list(new_funcs.keys())))

    moved = []
    added = []
    removed = []
    unchanged = []

    for name in all_names:
        in_old = name in old_funcs
        in_new = name in new_funcs

        if in_old and in_new:
            old_addr = old_funcs[name].get("address", "")
            new_addr = new_funcs[name].get("address", "")
            if old_addr != new_addr:
                moved.append((name, old_addr, new_addr))
            else:
                unchanged.append(name)
        elif in_new and not in_old:
            added.append((name, new_funcs[name].get("address", "")))
        elif in_old and not in_new:
            removed.append((name, old_funcs[name].get("address", "")))

    if moved:
        print("\nMOVED ({} functions):".format(len(moved)))
        for name, old_a, new_a in moved:
            cat = old_funcs.get(name, {}).get("category", "?")
            print("  [{:12s}] {:45s} {} -> {}".format(cat, name, old_a, new_a))

    if added:
        print("\nADDED ({} functions):".format(len(added)))
        for name, a in added:
            print("  {:45s} {}".format(name, a))

    if removed:
        print("\nREMOVED ({} functions):".format(len(removed)))
        for name, a in removed:
            print("  {:45s} {} (NEEDS RE-DISCOVERY)".format(name, a))

    print("\nUNCHANGED: {} functions".format(len(unchanged)))
    print("\nSUMMARY: {} moved, {} added, {} removed, {} unchanged".format(
        len(moved), len(added), len(removed), len(unchanged)))

    return moved, added, removed


# ---------------------------------------------------------------------------
# Entry point (when run as Ghidra script)
# ---------------------------------------------------------------------------

if GHIDRA_AVAILABLE:
    choices = ["Import symbols into Ghidra",
               "Export symbols from Ghidra",
               "Diff two symbol databases"]

    choice = askChoice("MQ Ghidra Bridge", "Select operation:", choices, choices[0])

    if choice == choices[0]:
        path = askFile("Select MQ symbol database", "Import")
        if path:
            import_symbols(str(path))
        else:
            import_symbols()

    elif choice == choices[1]:
        path = askFile("Save MQ symbol database", "Export")
        if path:
            export_symbols(str(path))
        else:
            export_symbols()

    elif choice == choices[2]:
        old = askFile("Select OLD symbol database", "Open")
        new = askFile("Select NEW symbol database", "Open")
        if old and new:
            diff_databases(str(old), str(new))
else:
    # Running outside Ghidra -- provide CLI for diff mode
    import sys
    if len(sys.argv) >= 4 and sys.argv[1] == "diff":
        diff_databases(sys.argv[2], sys.argv[3])
    else:
        print("MacroQuest Ghidra Bridge")
        print()
        print("Inside Ghidra: Run via Script Manager")
        print("CLI diff mode: python mq_ghidra_bridge.py diff old.json new.json")
        print()
        print("Tracked symbols: {}".format(len(MQ_KNOWN_SYMBOLS)))
        for cat in sorted(set(v["category"] for v in MQ_KNOWN_SYMBOLS.values())):
            count = sum(1 for v in MQ_KNOWN_SYMBOLS.values() if v["category"] == cat)
            print("  {:15s}: {:3d}".format(cat, count))
