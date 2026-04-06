#!/usr/bin/env python3
"""
MacroQuest EQ EXE Patching Security Verification Tool

Performs static analysis on the MacroQuest codebase to identify security
vulnerabilities in the eqgame.exe injection and patching mechanisms.
Reports findings with severity, file locations, and remediation guidance.

Usage:
    python3 tools/verify_eq_patching.py [--verbose]
"""

import os
import re
import sys
import argparse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    severity: Severity
    title: str
    file_path: str
    line_number: int
    description: str
    code_snippet: str
    remediation: str
    cwe_id: Optional[str] = None


@dataclass
class AuditReport:
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0

    def add(self, finding: Finding):
        self.findings.append(finding)

    def summary(self):
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def find_repo_root():
    """Walk up from script location to find the repo root."""
    path = Path(__file__).resolve().parent.parent
    if (path / ".git").exists():
        return path
    # fallback
    path = Path.cwd()
    while path != path.parent:
        if (path / ".git").exists():
            return path
        path = path.parent
    return Path.cwd()


def read_file_lines(filepath: Path) -> list:
    """Read file and return numbered lines (1-indexed)."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except (OSError, IOError):
        return []


def get_snippet(lines: list, line_num: int, context: int = 2) -> str:
    """Extract a code snippet around the given line number."""
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>>" if i == line_num - 1 else "   "
        snippet_lines.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")
    return "\n".join(snippet_lines)


# ---------------------------------------------------------------------------
# Individual vulnerability checks
# ---------------------------------------------------------------------------

def check_missing_null_terminator_writeprocessmemory(lines, filepath, report):
    """
    BUG: WriteProcessMemory with std::string::data()/length() does not include
    the null terminator. SetDllDirectoryA and LoadLibraryA require null-terminated
    strings. The remote buffer may contain leftover data from a previous write,
    causing the wrong string to be read.
    """
    for i, line in enumerate(lines, 1):
        if "WriteProcessMemory" in line and ".data()" in line and ".length()" in line:
            report.add(Finding(
                severity=Severity.CRITICAL,
                title="Missing null terminator in WriteProcessMemory",
                file_path=str(filepath),
                line_number=i,
                description=(
                    "WriteProcessMemory is called with std::string::data() and "
                    "std::string::length(), which does NOT include the null terminator. "
                    "The remote API functions (SetDllDirectoryA, LoadLibraryA) require "
                    "null-terminated strings. If the second write (LoadLibraryA path) is "
                    "shorter than the first write (SetDllDirectoryA path), leftover bytes "
                    "from the first write will corrupt the string, potentially causing "
                    "LoadLibraryA to load an unintended DLL (DLL hijacking vector)."
                ),
                code_snippet=get_snippet(lines, i),
                remediation=(
                    "Use `.length() + 1` instead of `.length()` to include the null "
                    "terminator, OR zero the buffer with a separate WriteProcessMemory "
                    "call before each write. Also consider using `.c_str()` which is "
                    "guaranteed to be null-terminated."
                ),
                cwe_id="CWE-170",
            ))


def check_virtualalloc_null_check(lines, filepath, report):
    """
    BUG: VirtualAllocEx return value is not checked for NULL before use.
    If allocation fails, WriteProcessMemory and CreateRemoteThread will
    operate on address 0 in the target process.
    """
    for i, line in enumerate(lines, 1):
        if "VirtualAllocEx" in line and "=" in line:
            # Look ahead for a null check within the next 5 lines
            has_check = False
            for j in range(i, min(i + 6, len(lines))):
                if "pRemoteBuffer" in lines[j] and ("nullptr" in lines[j] or "NULL" in lines[j] or "!pRemote" in lines[j]):
                    has_check = True
                    break
            if not has_check and "pRemoteBuffer" in line:
                report.add(Finding(
                    severity=Severity.HIGH,
                    title="No null check on VirtualAllocEx return value",
                    file_path=str(filepath),
                    line_number=i,
                    description=(
                        "VirtualAllocEx can return NULL if memory allocation fails in the "
                        "target process. The return value is used directly in subsequent "
                        "WriteProcessMemory and CreateRemoteThread calls without validation. "
                        "This could cause writes to address 0 in the target process, leading "
                        "to a crash or exploitable condition."
                    ),
                    code_snippet=get_snippet(lines, i),
                    remediation=(
                        "Check if pRemoteBuffer is nullptr after VirtualAllocEx. If null, "
                        "log the error, close the process handle, and return FailedRetry."
                    ),
                    cwe_id="CWE-252",
                ))


def check_getprocaddress_null_deref(lines, filepath, report):
    """
    BUG: GetProcAddress results are used without null checks.
    If the exported symbol doesn't exist, this causes a null pointer dereference.
    """
    for i, line in enumerate(lines, 1):
        if "GetProcAddress" in line and ("gszVersion" in line or "gszTime" in line):
            # Check if the next few lines validate the pointer
            has_check = False
            for j in range(i, min(i + 4, len(lines))):
                if "nullptr" in lines[j] or "NULL" in lines[j] or "if (" in lines[j]:
                    has_check = True
                    break
            if not has_check:
                report.add(Finding(
                    severity=Severity.HIGH,
                    title="Unchecked GetProcAddress for version string export",
                    file_path=str(filepath),
                    line_number=i,
                    description=(
                        "GetProcAddress is called for exported symbols 'gszVersion' and "
                        "'gszTime' from mq2main.dll, and the return value is immediately "
                        "cast and passed to strcpy_s without null checking. If the export "
                        "doesn't exist (e.g., corrupted or tampered DLL), this dereferences "
                        "a null pointer, crashing the launcher."
                    ),
                    code_snippet=get_snippet(lines, i),
                    remediation=(
                        "Check the return value of GetProcAddress before using it. If null, "
                        "report a meaningful error about the DLL being incompatible."
                    ),
                    cwe_id="CWE-476",
                ))


def check_remote_ops_loop_bug(lines, filepath, report):
    """
    BUG: In GetRemoteModuleHandle, the inner lowercase loop increments 'i'
    (the outer loop variable) instead of 'j', causing an infinite loop AND
    corrupting the outer loop iteration.
    """
    for i, line in enumerate(lines, 1):
        # Look for the pattern: for (size_t j = 0; ... ; ++i)  -- where inner loop increments outer var
        if re.search(r'for\s*\(\s*size_t\s+j\s*=\s*0\s*;.*;\s*\+\+i\s*\)', line):
            report.add(Finding(
                severity=Severity.CRITICAL,
                title="Inner loop increments wrong variable (infinite loop + out-of-bounds)",
                file_path=str(filepath),
                line_number=i,
                description=(
                    "The inner loop that converts module names to lowercase uses "
                    "`for (size_t j = 0; ModuleNameBuffer[j] != '\\0'; ++i)` -- it "
                    "increments `i` (the OUTER loop counter for module iteration) instead "
                    "of `j`. This causes: (1) an infinite loop because `j` never advances, "
                    "(2) corruption of the outer loop counter causing out-of-bounds access "
                    "to ModuleArray[], and (3) the module name is never actually lowercased. "
                    "This function is called during remote unload operations."
                ),
                code_snippet=get_snippet(lines, i, context=4),
                remediation="Change `++i` to `++j` in the inner for-loop.",
                cwe_id="CWE-835",
            ))


def check_remote_ops_off_by_one(lines, filepath, report):
    """
    BUG: Loop uses `i <= NumModules` instead of `i < NumModules`, reading
    one element past the end of the allocated array.
    """
    for i, line in enumerate(lines, 1):
        if re.search(r'i\s*<=\s*NumModules', line) and "for" in line:
            report.add(Finding(
                severity=Severity.HIGH,
                title="Off-by-one: loop reads past end of module array",
                file_path=str(filepath),
                line_number=i,
                description=(
                    "The module enumeration loop uses `i <= NumModules` as the condition, "
                    "but valid indices are 0 through NumModules-1. When i == NumModules, "
                    "ModuleArray[i] reads one element past the end of the heap-allocated "
                    "array, causing undefined behavior (heap buffer over-read)."
                ),
                code_snippet=get_snippet(lines, i),
                remediation="Change `i <= NumModules` to `i < NumModules`.",
                cwe_id="CWE-193",
            ))


def check_unterminated_string_from_process_memory(lines, filepath, report):
    """
    BUG: Reading a spawn struct from remote process and casting a fixed offset
    to char* without ensuring null termination within the buffer bounds.
    """
    for i, line in enumerate(lines, 1):
        if "spawnstruct" in line and "return" in line and "(char*)" in line:
            report.add(Finding(
                severity=Severity.MEDIUM,
                title="Potentially unterminated string from remote process memory",
                file_path=str(filepath),
                line_number=i,
                description=(
                    "A spawn struct is read from the remote EQ process and the character "
                    "name at offset 0xa4 is returned as a char*. The buffer is 0xe4 bytes "
                    "total, leaving only 64 bytes (0xe4 - 0xa4 = 0x40) for the name. If the "
                    "remote memory contains no null byte in that range, std::string "
                    "construction will read out of bounds. The buffer IS zero-initialized, "
                    "but if ReadProcessMemory fills it completely, the last byte might not "
                    "be null."
                ),
                code_snippet=get_snippet(lines, i),
                remediation=(
                    "Explicitly null-terminate the buffer: `spawnstruct[0xe3] = 0;` before "
                    "returning the string, or use `std::string((char*)&spawnstruct[0xa4], "
                    "strnlen((char*)&spawnstruct[0xa4], 0x40))`."
                ),
                cwe_id="CWE-170",
            ))


def check_hardcoded_addresses(lines, filepath, report):
    """
    INFO: Hardcoded preferred base addresses for ASLR offset calculation.
    Not a bug per se, but worth documenting.
    """
    for i, line in enumerate(lines, 1):
        if "EQGamePreferredAddress" in line and "constexpr" in line:
            report.add(Finding(
                severity=Severity.INFO,
                title="Hardcoded EQ preferred base address for ASLR calculation",
                file_path=str(filepath),
                line_number=i,
                description=(
                    "The preferred image base address for eqgame.exe is hardcoded. This is "
                    "used to calculate ASLR offsets when reading remote process memory. If "
                    "EQ changes its preferred base address in an update, this will silently "
                    "compute wrong offsets, causing reads from incorrect memory locations."
                ),
                code_snippet=get_snippet(lines, i),
                remediation=(
                    "Consider reading the preferred base address from the PE optional "
                    "header of eqgame.exe at runtime instead of hardcoding it."
                ),
                cwe_id="CWE-547",
            ))


def check_security_attributes_inheritable(lines, filepath, report):
    """
    The SECURITY_ATTRIBUTES struct is created with bInheritHandle = TRUE,
    meaning the remote thread handle can be inherited by child processes.
    """
    for i, line in enumerate(lines, 1):
        if "SECURITY_ATTRIBUTES" in line and "TRUE" in line and "sa" in line:
            # Only flag in injection context
            found_remote_thread = False
            for j in range(i, min(i + 20, len(lines))):
                if "CreateRemoteThread" in lines[j]:
                    found_remote_thread = True
                    break
            if found_remote_thread:
                report.add(Finding(
                    severity=Severity.LOW,
                    title="Remote thread handle created as inheritable",
                    file_path=str(filepath),
                    line_number=i,
                    description=(
                        "SECURITY_ATTRIBUTES is configured with bInheritHandle = TRUE for "
                        "the CreateRemoteThread call. This means child processes of the "
                        "launcher can inherit the remote thread handle, which could be used "
                        "to manipulate the EQ process if a child process is compromised."
                    ),
                    code_snippet=get_snippet(lines, i),
                    remediation=(
                        "Use bInheritHandle = FALSE unless handle inheritance is "
                        "specifically needed. In this case it is not."
                    ),
                    cwe_id="CWE-732",
                ))


def check_anticheat_bypass_mechanisms(lines, filepath, report):
    """
    Document the anti-cheat bypass mechanisms for the security report.
    These are the memory integrity check detours.
    """
    for i, line in enumerate(lines, 1):
        if "memcheck0" in line and "int memcheck0(" in line:
            report.add(Finding(
                severity=Severity.INFO,
                title="EQ memory integrity check bypass (memcheck0)",
                file_path=str(filepath),
                line_number=i,
                description=(
                    "memcheck0 is a detour that intercepts EverQuest's CRC32-based memory "
                    "integrity checking. When EQ scans memory regions that overlap with "
                    "MacroQuest's detours/patches, this function returns a hash computed "
                    "from the ORIGINAL bytes rather than the patched bytes, effectively "
                    "hiding the modifications from EQ's anti-cheat."
                ),
                code_snippet=get_snippet(lines, i, context=5),
                remediation=(
                    "This is the core anti-detection mechanism. EQ's anti-cheat could "
                    "detect this by: (1) checking integrity of the memcheck functions "
                    "themselves, (2) using a kernel-mode driver for integrity checks, "
                    "(3) randomizing check function addresses, (4) implementing timing-based "
                    "detection of detour overhead."
                ),
            ))
        if "FindModules_Detour" in line and "BOOL WINAPI FindModules_Detour" in line:
            report.add(Finding(
                severity=Severity.INFO,
                title="Module enumeration filtering (DLL hiding)",
                file_path=str(filepath),
                line_number=i,
                description=(
                    "FindModules_Detour intercepts EnumProcessModulesEx to filter out "
                    "MacroQuest-related DLLs from the results. When EQ's anti-cheat "
                    "enumerates loaded modules, MQ modules are hidden from the list. "
                    "Similarly, Module32Next and process enumeration are filtered."
                ),
                code_snippet=get_snippet(lines, i, context=3),
                remediation=(
                    "EQ could detect this by: (1) directly walking the PEB loader data "
                    "structures instead of using Win32 APIs, (2) using NtQueryVirtualMemory "
                    "to scan for mapped DLLs, (3) checking for detours on the enumeration "
                    "functions themselves, (4) using a kernel driver to enumerate modules."
                ),
            ))


def check_remote_thread_no_error_handling(lines, filepath, report):
    """
    CreateRemoteThread return value not checked in DoInject.
    """
    in_doinject = False
    for i, line in enumerate(lines, 1):
        if "DoInject" in line and "static" in line:
            in_doinject = True
        if in_doinject and "CreateRemoteThread" in line:
            # Check if return value is validated
            has_check = False
            for j in range(i, min(i + 3, len(lines))):
                if "if" in lines[j] and ("hRemoteThread" in lines[j] or "!hRemote" in lines[j]):
                    has_check = True
                    break
            if not has_check:
                report.add(Finding(
                    severity=Severity.MEDIUM,
                    title="CreateRemoteThread return value not validated in DoInject",
                    file_path=str(filepath),
                    line_number=i,
                    description=(
                        "CreateRemoteThread can fail (returning NULL) if the target process "
                        "is protected, has exited, or security software blocks it. The return "
                        "value is not checked before calling WaitForSingleObject, which would "
                        "then wait on an invalid handle. The injection is reported as successful "
                        "even if thread creation failed."
                    ),
                    code_snippet=get_snippet(lines, i),
                    remediation=(
                        "Check if hRemoteThread is non-null after CreateRemoteThread. If null, "
                        "clean up the remote buffer and return an appropriate error result."
                    ),
                    cwe_id="CWE-252",
                ))
                # Only flag the first occurrence in DoInject to avoid duplicates
                break


def check_dll_path_no_validation(lines, filepath, report):
    """
    The injected DLL path is constructed from the current working directory
    without validation that the file actually exists or is signed.
    """
    for i, line in enumerate(lines, 1):
        if "GetInjecteePath" in line and ("string" in line or "return" in line) and "injecteePath" in line:
            report.add(Finding(
                severity=Severity.MEDIUM,
                title="Injected DLL path not validated before injection",
                file_path=str(filepath),
                line_number=i,
                description=(
                    "GetInjecteePath constructs the path to mq2main.dll from the current "
                    "working directory. There is no check that the file exists, is a valid "
                    "PE, or has a valid signature before injecting it into eqgame.exe. An "
                    "attacker who can place a malicious mq2main.dll in the working directory "
                    "(or modify the search path) could achieve code execution inside EQ."
                ),
                code_snippet=get_snippet(lines, i),
                remediation=(
                    "Validate that the DLL file exists and optionally verify a code "
                    "signature or checksum before injection. Use an absolute path derived "
                    "from the launcher's own directory rather than cwd."
                ),
                cwe_id="CWE-426",
            ))


# ---------------------------------------------------------------------------
# Main scanning logic
# ---------------------------------------------------------------------------

TARGET_FILES = {
    "src/loader/ProcessList.cpp": [
        check_missing_null_terminator_writeprocessmemory,
        check_virtualalloc_null_check,
        check_getprocaddress_null_deref,
        check_unterminated_string_from_process_memory,
        check_hardcoded_addresses,
        check_security_attributes_inheritable,
        check_remote_thread_no_error_handling,
        check_dll_path_no_validation,
    ],
    "src/loader/RemoteOps.cpp": [
        check_remote_ops_loop_bug,
        check_remote_ops_off_by_one,
    ],
    "src/main/MQDetourAPI.cpp": [
        check_anticheat_bypass_mechanisms,
    ],
}


def run_audit(repo_root: Path, verbose: bool = False) -> AuditReport:
    report = AuditReport()

    for rel_path, checks in TARGET_FILES.items():
        filepath = repo_root / rel_path
        if not filepath.exists():
            if verbose:
                print(f"  [SKIP] {rel_path} (not found)")
            continue

        lines = read_file_lines(filepath)
        report.files_scanned += 1
        report.lines_scanned += len(lines)

        if verbose:
            print(f"  [SCAN] {rel_path} ({len(lines)} lines, {len(checks)} checks)")

        for check_fn in checks:
            check_fn(lines, rel_path, report)

    return report


def print_report(report: AuditReport):
    severity_colors = {
        Severity.CRITICAL: "\033[91m",  # Red
        Severity.HIGH: "\033[93m",      # Yellow
        Severity.MEDIUM: "\033[33m",    # Orange-ish
        Severity.LOW: "\033[36m",       # Cyan
        Severity.INFO: "\033[37m",      # White
    }
    reset = "\033[0m"
    bold = "\033[1m"

    print(f"\n{'='*80}")
    print(f"{bold}MacroQuest EQ EXE Patching - Security Verification Report{reset}")
    print(f"{'='*80}\n")
    print(f"Files scanned: {report.files_scanned}")
    print(f"Lines scanned: {report.lines_scanned}")
    print(f"Total findings: {len(report.findings)}\n")

    summary = report.summary()
    print("Severity breakdown:")
    for sev in Severity:
        count = summary.get(sev, 0)
        if count > 0:
            color = severity_colors.get(sev, "")
            print(f"  {color}{sev.value:10s}{reset}: {count}")
    print()

    # Sort findings by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                      Severity.LOW: 3, Severity.INFO: 4}
    sorted_findings = sorted(report.findings, key=lambda f: severity_order[f.severity])

    for idx, finding in enumerate(sorted_findings, 1):
        color = severity_colors.get(finding.severity, "")
        print(f"{'-'*80}")
        print(f"{bold}Finding #{idx}: {color}[{finding.severity.value}]{reset} {bold}{finding.title}{reset}")
        print(f"  File: {finding.file_path}:{finding.line_number}")
        if finding.cwe_id:
            print(f"  CWE:  {finding.cwe_id}")
        print()
        print(f"  Description:")
        for line in finding.description.split(". "):
            print(f"    {line.strip()}.")
        print()
        print(f"  Code:")
        for line in finding.code_snippet.split("\n"):
            print(f"    {line}")
        print()
        print(f"  Remediation:")
        for line in finding.remediation.split(". "):
            print(f"    {line.strip()}.")
        print()

    # Print executive summary
    print(f"{'='*80}")
    print(f"{bold}EXECUTIVE SUMMARY{reset}")
    print(f"{'='*80}\n")

    crit_count = summary.get(Severity.CRITICAL, 0)
    high_count = summary.get(Severity.HIGH, 0)

    if crit_count > 0:
        print(f"{severity_colors[Severity.CRITICAL]}{bold}"
              f"  {crit_count} CRITICAL vulnerabilities require immediate attention.{reset}\n")

    print("  Key issues for the developer:")
    print()
    print("  1. NULL TERMINATOR BUG (CRITICAL): WriteProcessMemory calls in DoInject()")
    print("     do not write the null terminator for strings passed to SetDllDirectoryA")
    print("     and LoadLibraryA in the remote process. This can cause DLL path corruption")
    print("     and is a potential DLL hijacking vector.")
    print()
    print("  2. INFINITE LOOP BUG (CRITICAL): GetRemoteModuleHandle() has an inner loop")
    print("     that increments the wrong variable (++i instead of ++j), causing an")
    print("     infinite loop and out-of-bounds array access. This affects remote unload.")
    print()
    print("  3. MISSING ERROR CHECKS (HIGH): VirtualAllocEx, GetProcAddress, and")
    print("     CreateRemoteThread return values are not validated, leading to null")
    print("     pointer dereferences and operations on invalid handles.")
    print()
    print("  4. ANTI-CHEAT BYPASS (INFO): The detour system hides patches from EQ's")
    print("     memory integrity checks by returning original bytes during CRC scans.")
    print("     Module enumeration APIs are also hooked to hide MQ DLLs.")
    print()

    # Return exit code
    if crit_count > 0:
        return 2
    if high_count > 0:
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Verify security of MacroQuest eqgame.exe patching code"
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed scanning progress")
    args = parser.parse_args()

    repo_root = find_repo_root()

    if args.verbose:
        print(f"Repository root: {repo_root}")
        print(f"Scanning target files...\n")

    report = run_audit(repo_root, verbose=args.verbose)
    exit_code = print_report(report)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
