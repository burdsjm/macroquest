# MacroQuest EQ EXE Patching - Security Audit Report

## Overview

This report documents the security analysis of MacroQuest's eqgame.exe
injection and patching mechanisms. The audit covers the DLL injection pipeline,
remote process operations, memory patching/detour system, and anti-cheat bypass
techniques.

**Files Analyzed:**
- `src/loader/ProcessList.cpp` - DLL injection, process enumeration, remote unload
- `src/loader/RemoteOps.cpp` - Remote module handle/proc address resolution
- `src/main/MQDetourAPI.cpp` - Memory integrity check detours, module hiding
- `src/main/MacroQuest.cpp` - DllMain entry point, initialization
- `src/loader/ProcessMonitor.cpp` - WMI/ToolHelp process monitoring

**Scan Results: 3 CRITICAL, 4 HIGH, 2 MEDIUM, 2 LOW, 5 INFO**

Run the automated scanner: `python3 tools/verify_eq_patching.py --verbose`

---

## CRITICAL Findings

### 1. Missing Null Terminator in Remote String Writes (CWE-170)

**File:** `src/loader/ProcessList.cpp:1035,1041`

The `DoInject()` function writes DLL path strings into the remote eqgame.exe
process using `WriteProcessMemory` with `std::string::data()` and
`std::string::length()`. The `.length()` method does NOT include the null
terminator.

```cpp
// Line 1035 - missing null terminator
WriteProcessMemory(hEQGame.get(), pRemoteBuffer,
    injecteeDirectory.data(), injecteeDirectory.length(), nullptr);

// Line 1041 - same issue
WriteProcessMemory(hEQGame.get(), pRemoteBuffer,
    injectee.data(), injectee.length(), nullptr);
```

**Impact:** `SetDllDirectoryA` and `LoadLibraryA` in the remote process expect
null-terminated strings. Both writes reuse the same 1024-byte buffer. If the
second string (DLL path for `LoadLibraryA`) is shorter than the first (directory
path for `SetDllDirectoryA`), leftover bytes from the first write will remain,
corrupting the DLL path. This is a **DLL hijacking vector** - an attacker could
craft conditions where `LoadLibraryA` loads an unintended DLL.

**Fix:** Use `.length() + 1` or `.c_str()` with `strlen() + 1`:
```cpp
WriteProcessMemory(hEQGame.get(), pRemoteBuffer,
    injecteeDirectory.c_str(), injecteeDirectory.length() + 1, nullptr);
```

### 2. Infinite Loop + Out-of-Bounds in GetRemoteModuleHandle (CWE-835)

**File:** `src/loader/RemoteOps.cpp:87`

The inner lowercase-conversion loop increments `i` (the **outer** loop counter)
instead of `j` (the **inner** loop counter):

```cpp
for (DWORD i = 0; i <= NumModules; ++i)  // outer loop
{
    GetModuleBaseName(hProcess, ModuleArray[i], ModuleNameBuffer, ...);
    
    for (size_t j = 0; ModuleNameBuffer[j] != '\0'; ++i)  // BUG: ++i not ++j
    {
        if (ModuleNameBuffer[j] >= 'A' && ModuleNameBuffer[j] <= 'Z')
            ModuleNameBuffer[j] += 0x20;
    }
```

**Impact:** Three simultaneous problems:
1. `j` never advances, creating an **infinite loop** (if the first char is not null)
2. `i` is corrupted, causing **out-of-bounds heap reads** on `ModuleArray[]`
3. The module name is never actually lowercased, so **case-sensitive comparison always fails**

This function is called during `ForceRemoteUnloadMQ2()` to find modules in a
remote process. The bug means remote unload via this path will hang or crash.

**Fix:** Change `++i` to `++j` on line 87.

### 3. Off-by-One in Module Enumeration Loop (CWE-193)

**File:** `src/loader/RemoteOps.cpp:80`

```cpp
for (DWORD i = 0; i <= NumModules; ++i)
```

The loop condition `i <= NumModules` iterates one element past the end of the
`ModuleArray` (valid indices are 0 to NumModules-1). This is a **heap buffer
over-read**.

**Fix:** Change `i <= NumModules` to `i < NumModules`.

---

## HIGH Findings

### 4. No Null Check on VirtualAllocEx (CWE-252)

**File:** `src/loader/ProcessList.cpp:1028`

`VirtualAllocEx` can return NULL if allocation fails. The return value is used
directly in `WriteProcessMemory` and `CreateRemoteThread` without validation.

### 5. Unchecked GetProcAddress for Version Strings (CWE-476)

**File:** `src/loader/ProcessList.cpp:988,990`

`GetProcAddress` results for `gszVersion` and `gszTime` are cast to `char*` and
passed to `strcpy_s` without null checking. A corrupted or incompatible
`mq2main.dll` will cause a null pointer dereference crash.

### 6. CreateRemoteThread Return Not Validated (CWE-252)

**File:** `src/loader/ProcessList.cpp:1036`

`CreateRemoteThread` can return NULL. `WaitForSingleObject` is then called on
the invalid handle, and the injection is reported as successful regardless.

---

## MEDIUM Findings

### 7. Unterminated String from Remote Process Memory (CWE-170)

**File:** `src/loader/ProcessList.cpp:893`

Character name read from a spawn struct at offset 0xa4 is returned as `char*`
with no guarantee of null termination within the 64-byte remaining buffer.

### 8. DLL Path Not Validated Before Injection (CWE-426)

**File:** `src/loader/ProcessList.cpp:646`

The injected DLL path is derived from `cwd` with no existence/signature check.
An attacker placing a malicious `mq2main.dll` in the working directory achieves
code execution in eqgame.exe.

---

## Anti-Cheat Bypass Analysis (INFO)

### How MacroQuest Hides from EQ's Anti-Cheat

MacroQuest implements a sophisticated multi-layer concealment system:

**Layer 1 - Memory Integrity Check Bypass (`MQDetourAPI.cpp:219-288`)**

EQ uses CRC32-based memory integrity checking (memcheck0, memcheck1, memcheck4)
to verify that game code hasn't been modified. MacroQuest detours these functions
so that when EQ scans memory regions containing MQ patches, the hash is computed
from the **original unmodified bytes** rather than the patched bytes.

**Layer 2 - Module Enumeration Hiding (`MQDetourAPI.cpp:303-343`)**

MacroQuest hooks `EnumProcessModulesEx`, `Module32Next`, and
`EnumProcesses` to filter MQ-related DLLs and processes from the results. When
EQ's anti-cheat enumerates loaded modules, it never sees MQ DLLs.

**Layer 3 - Decompression Block Suppression (`MQDetourAPI.cpp:292-298`)**

During memcheck4 operations, the decompression block function is suppressed
(returns 0) to prevent anti-cheat from analyzing decompressed code regions.

### Recommendations for EQ Developer

To detect these bypasses, the EQ developer could:

1. **Check integrity of integrity-check functions** - Verify that memcheck0/1/4
   themselves haven't been detoured by comparing their first bytes against known
   good values
2. **Use kernel-mode integrity checking** - A kernel driver can read process
   memory without going through user-mode APIs that can be hooked
3. **Walk PEB directly** - Instead of using `EnumProcessModules`, walk the
   `PEB->Ldr->InLoadOrderModuleList` linked list directly to find hidden modules
4. **Use `NtQueryVirtualMemory`** - Scan the address space for mapped images
   that don't appear in the module list
5. **Timing-based detection** - Detoured functions have measurable overhead from
   the trampoline; statistical timing analysis can detect them
6. **Randomize check function addresses** - Make memcheck function locations
   unpredictable so they can't be found and detoured at known offsets

---

## Verification

Run the automated scanner to verify these findings:

```bash
python3 tools/verify_eq_patching.py --verbose
```

Exit codes: 0 = clean, 1 = HIGH findings, 2 = CRITICAL findings
