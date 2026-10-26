/*
 * Warden - src/monitor/hooks.c
 *
 * Minimal x64 inline-hook engine:
 *   - a conservative length-disassembler (LDE) understands the common
 *     compiler-generated prologue instructions (push/mov/sub/xor/lea/
 *     endbr64/nops + RIP-relative lea/mov);
 *   - a 14-byte absolute jump  (ff 25 00000000 + 8-byte address) is
 *     written over the prologue;
 *   - the original instructions are relocated into a trampoline that
 *     ends with a jump back to target+prologueLen;
 *   - RIP-relative instructions inside the trampoline get their disp32
 *     fixed up.
 *
 * If the LDE hits an unsupported instruction before 14 bytes, the hook
 * for that function is skipped (logged as debug) - analysis quality
 * degrades but the target is never destabilised.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "hooks.h"
#include "monitor.h"
#include "../common/warden.h"
#include "../common/util.h"
#include "../common/log.h"

/* NTSTATUS: user-mode windows.h does not always pull in ntdef.h, and
 * MinGW keeps it in winternl.h.  Guarded fallback keeps both toolchains
 * (MSVC on CI, MinGW for local checks) resolving the same type.        */
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

#define JMP_STUB_SIZE 14
#define MAX_PROLOGUE  64

typedef struct _HOOK {
    const char *name;
    void  *target;
    void  *hookFn;
    void  *trampoline;     /* call this to invoke the original */
    BOOL   installed;
} HOOK;

/* ------------------------------------------------------------------ */
/* length disassembler (conservative, x64)                             */
/* Returns instruction length in bytes, or 0 when unsupported.          */
/* ripRel != NULL receives the disp32 offset position for RIP-relative  */
/* instructions that need relocation.                                   */
/* ------------------------------------------------------------------ */

static unsigned lde_len(const unsigned char *p, unsigned *ripRelOff)
{
    unsigned i = 0;
    unsigned rex = 0, opsz = 0;
    unsigned char op;

    if (ripRelOff) *ripRelOff = 0xFFFFFFFFu;

    /* endbr64/endbr32: F3 0F 1E FA / F3 0F 1E FB (Win11 prologues) */
    if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E &&
        (p[3] == 0xFA || p[3] == 0xFB))
        return 4;

    /* prefixes */
    for (;;) {
        unsigned char b = p[i];
        if (b == 0x66) { opsz = 1; i++; continue; }
        if (b == 0x67 || b == 0x2E || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 || b == 0x36) { i++; continue; }
        if (b == 0xF3 || b == 0xF2) { i++; continue; }
        if ((b & 0xF0) == 0x40) { rex = b; i++; continue; }   /* REX */
        break;
    }

    /* multi-byte nops / hint-nops: 0F 18..1F /r */
    if (p[i] == 0x0F && p[i + 1] >= 0x18 && p[i + 1] <= 0x1F) {
        unsigned char modrm = p[i + 2];
        unsigned mod = modrm >> 6, rm = modrm & 7;
        unsigned len = 3;
        if (rex) len++;
        if (mod == 3) return 0;
        if (mod == 1) len += 1;
        else if (mod == 2) len += 4;
        else if (mod == 0 && rm == 5) len += 4;
        return len;
    }

    op = p[i];

    switch (op) {
    case 0x90: /* nop */
        return i + 1;
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57: /* push r64 */
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F: /* pop r64 */
        return i + 1;
    case 0x6A: /* push imm8 */
        return i + 2;
    case 0x68: /* push imm32 */
        return i + 5;
    case 0xE8: /* call rel32 - relocatable */
        if (ripRelOff) *ripRelOff = i + 1;
        return i + 5;
    case 0xE9: case 0xEB: /* jmp - unsupported mid-prologue */
        return 0;
    default:
        break;
    }

    /* mov r64,r64 / mov r64,rm64 (89/8B) with modrm */
    if (op == 0x89 || op == 0x8B || op == 0x85 || op == 0x31 || op == 0x33 ||
        op == 0x8D || op == 0x03 || op == 0x2B || op == 0x23 || op == 0x0B ||
        op == 0x63 || op == 0x39 || op == 0x3B) {
        unsigned char modrm = p[i + 1];
        unsigned mod = modrm >> 6, rm = modrm & 7, reg = (modrm >> 3) & 7;
        unsigned len = i + 2;
        int ripRel = 0;

        if (rex && (rex & 1)) { /* REX.B extends rm - fine */ (void)reg; }

        if (mod == 3) return len;
        if (mod == 0 && rm == 5) {              /* [rip+disp32] */
            if (op == 0x8D || op == 0x8B || op == 0x03 || op == 0x2B ||
                op == 0x23 || op == 0x0B || op == 0x63 || op == 0x3B) {
                if (ripRelOff) *ripRelOff = len;
                ripRel = 1;
            }
            return ripRel ? len + 4 : len + 4;
        }
        if (rm == 4) {                          /* SIB byte */
            unsigned char sib = p[len];
            unsigned base = sib & 7;
            len++;
            if (mod == 0 && base == 5) len += 4;
            else if (mod == 1) len += 1;
            else if (mod == 2) len += 4;
            return len;
        }
        if (mod == 1) len += 1;
        else if (mod == 2) len += 4;
        return len;
    }

    /* 48 C7 /r mov r64, imm32 (mod=11) */
    if (op == 0xC7) {
        unsigned char modrm = p[i + 1];
        if ((modrm >> 6) == 3) return i + 2 + 4;
        return 0;
    }

    /* 48 81 /5 sub rsp, imm32 ; 48 83 /5 sub rsp, imm8 handled by /r below */
    if (op == 0x81 || op == 0x83) {
        unsigned char modrm = p[i + 1];
        unsigned mod = modrm >> 6, rm = modrm & 7;
        unsigned len = i + 2;
        if (mod == 3) return len + (op == 0x81 ? 4 : 1);
        if (rm == 4) { len++; }
        if (mod == 1) len += 1;
        else if (mod == 2) len += 4;
        return len + (op == 0x81 ? 4 : 1);
    }

    /* F6/F7 test */
    if (op == 0xF7) {
        unsigned char modrm = p[i + 1];
        if ((modrm >> 6) == 3) return i + 2 + 4;
        return 0;
    }

    return 0; /* unsupported */
}

/* Decode the whole prologue: returns total bytes consumed (>= need) or 0 */
static unsigned lde_prologue(const unsigned char *code, unsigned need,
                             unsigned *relCount,
                             unsigned relOffs[MAX_PROLOGUE / 2])
{
    unsigned off = 0, n = 0;
    *relCount = 0;
    while (off < need) {
        unsigned rel = 0xFFFFFFFFu;
        unsigned len = lde_len(code + off, &rel);
        if (len == 0) return 0;
        if (off + len > MAX_PROLOGUE) return 0;
        if (rel != 0xFFFFFFFFu) {
            if (*relCount >= MAX_PROLOGUE / 2) return 0;
            relOffs[(*relCount)++] = off + rel;
        }
        off += len;
    }
    return off;
}

/* ------------------------------------------------------------------ */
/* trampoline allocation + patching                                    */
/* ------------------------------------------------------------------ */

static void *alloc_trampoline(BYTE *nearby)
{
    SYSTEM_INFO si;
    ULONG_PTR lo, hi, addr;
    GetSystemInfo(&si);
    lo = (ULONG_PTR)si.lpMinimumApplicationAddress;
    hi = (ULONG_PTR)si.lpMaximumApplicationAddress;
    addr = (ULONG_PTR)nearby;
    for (; lo < hi; lo += si.dwAllocationGranularity) {
        void *p = (void *)((addr + 0x10000000ull) & ~0xFFFFFull);
        p = VirtualAlloc(p, 0x1000, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
        if (p) return p;
        addr += 0x10000000ull;
        if (addr > hi) addr = lo;
    }
    return NULL;
}

static BOOL write_jump(BYTE *at, void *dest)
{
    DWORD old;
    BYTE stub[JMP_STUB_SIZE] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0,0,0,0,0,0,0,0
    };
    void *addr = dest;
    memcpy(stub + 6, &addr, 8);
    if (!VirtualProtect(at, JMP_STUB_SIZE, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;
    memcpy(at, stub, JMP_STUB_SIZE);
    FlushInstructionCache(GetCurrentProcess(), at, JMP_STUB_SIZE);
    VirtualProtect(at, JMP_STUB_SIZE, old, &old);
    return TRUE;
}

static BOOL install_one(HOOK *h)
{
    BYTE *target = (BYTE *)h->target;
    unsigned char orig[MAX_PROLOGUE];
    unsigned relCount = 0;
    unsigned relOffs[MAX_PROLOGUE / 2];
    unsigned prologLen;
    BYTE *tram;
    DWORD old;
    unsigned u;

    __try {
        memcpy(orig, target, MAX_PROLOGUE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    prologLen = lde_prologue(orig, JMP_STUB_SIZE, &relCount, relOffs);
    if (prologLen == 0) {
        wlog_event("hook_skip", SC_INFO, "debug", h->name,
                   NULL, "hook skipped (prologue not relocatable): %s",
                   h->name);
        return FALSE;
    }

    tram = (BYTE *)alloc_trampoline(target);
    if (!tram) return FALSE;

    /* copy relocated prologue */
    memcpy(tram, orig, prologLen);
    for (u = 0; u < relCount; u++) {
        /* RIP-relative: RIP after instruction = target + off + 4
         * new RIP in trampoline    = tram    + off + 4 */
        BYTE *site = tram + relOffs[u];
        INT32 disp;
        INT64 newDisp;
        memcpy(&disp, site, 4);
        newDisp = (INT64)disp +
                  ((INT64)(target + relOffs[u]) - (INT64)(tram + relOffs[u]));
        disp = (INT32)newDisp;
        if ((INT64)disp != newDisp) {
            wlog_event("hook_skip", SC_INFO, "debug", h->name, NULL,
                       "hook skipped (disp32 overflow): %s", h->name);
            return FALSE;
        }
        memcpy(site, &disp, 4);
    }
    /* jump back */
    if (!write_jump(tram + prologLen, target + prologLen)) return FALSE;

    /* patch target */
    if (!VirtualProtect(target, JMP_STUB_SIZE, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;
    {
        BYTE stub[JMP_STUB_SIZE];
        void *dest = (void *)h->hookFn;
        stub[0] = 0xFF; stub[1] = 0x25;
        stub[2] = stub[3] = stub[4] = stub[5] = 0;
        memcpy(stub + 6, &dest, 8);
        memcpy(target, stub, JMP_STUB_SIZE);
        FlushInstructionCache(GetCurrentProcess(), target, JMP_STUB_SIZE);
    }
    VirtualProtect(target, JMP_STUB_SIZE, old, &old);

    h->trampoline = tram;
    h->installed = TRUE;
    mon_register_patch_range((DWORD64)target, JMP_STUB_SIZE);
    mon_register_patch_range((DWORD64)tram, 0x100);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* hook bodies                                                         */
/* ------------------------------------------------------------------ */

typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef NTSTATUS (NTAPI *PFN_LdrLoadDll)(PWSTR, PULONG,
                                         void *uni, void **);
typedef LPVOID (WINAPI *PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static PFN_LoadLibraryExW  orig_LoadLibraryExW;
static PFN_LdrLoadDll      orig_LdrLoadDll;
static PFN_VirtualAlloc    orig_VirtualAlloc;
static PFN_VirtualProtect  orig_VirtualProtect;
static PFN_CreateProcessW  orig_CreateProcessW;

static HMODULE WINAPI hk_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    HMODULE h = orig_LoadLibraryExW(name, file, flags);
    if (name && *name) {
        char key[180];
        WideCharToMultiByte(CP_UTF8, 0, name, -1, key, 180, NULL, NULL);
        if (mon_once(key))
            wlog_event("loadlib", SC_INFO, "debug", NULL, NULL,
                       "LoadLibraryExW(\"%ls\", 0x%lx)", name, flags);
    }
    return h;
}

typedef struct _MIN_UNI {
    USHORT Len;
    USHORT Max;
    PVOID  Buf;
} MIN_UNI;

static NTSTATUS NTAPI hk_LdrLoadDll(PWSTR path, PULONG flags,
                                    void *uni, void **handle)
{
    NTSTATUS st = orig_LdrLoadDll(path, flags, uni, handle);
    MIN_UNI *u = (MIN_UNI *)uni;
    if (u && u->Buf && u->Len && u->Len < 520) {
        wchar_t buf[260];
        __try {
            memcpy(buf, u->Buf, u->Len);
            buf[u->Len / sizeof(wchar_t)] = 0;
            {
                char key[260];
                WideCharToMultiByte(CP_UTF8, 0, buf, -1, key, 260, NULL, NULL);
                if (mon_once(key))
                    wlog_event("ldr_load", SC_INFO, "debug", NULL, NULL,
                               "LdrLoadDll(\"%ls\") -> 0x%08lx", buf,
                               (unsigned long)st);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    return st;
}

static LPVOID WINAPI hk_VirtualAlloc(LPVOID base, SIZE_T size, DWORD type,
                                     DWORD protect)
{
    LPVOID p = orig_VirtualAlloc(base, size, type, protect);
    if (p && (type & MEM_COMMIT) &&
        ((protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)) {
        char key[40];
        char data[200];
        _snprintf_s(key, sizeof(key), _TRUNCATE, "va-%llx",
                    (unsigned long long)(ULONG_PTR)p);
        if (mon_once(key)) {
            _snprintf_s(data, sizeof(data), _TRUNCATE,
                        "\"base\":\"0x%llx\",\"size\":%lu,\"protect\":\"RWX\"",
                        (unsigned long long)(ULONG_PTR)p, (unsigned long)size);
            wlog_event("valloc_exec", SC_VALLOC_EXEC, "warn", key, data,
                       "VirtualAlloc committed RWX memory at 0x%llx"
                       " (%lu bytes)",
                       (unsigned long long)(ULONG_PTR)p, (unsigned long)size);
        }
    }
    return p;
}

static BOOL WINAPI hk_VirtualProtect(LPVOID addr, SIZE_T size, DWORD newProt,
                                     PDWORD oldProt)
{
    BOOL ok = orig_VirtualProtect(addr, size, newProt, oldProt);
    if (ok && (newProt == PAGE_EXECUTE_READWRITE ||
               newProt == PAGE_EXECUTE_READ ||
               newProt == PAGE_EXECUTE)) {
        char key[40];
        char data[200];
        _snprintf_s(key, sizeof(key), _TRUNCATE, "vp-%llx",
                    (unsigned long long)(ULONG_PTR)addr);
        if (mon_once(key)) {
            _snprintf_s(data, sizeof(data), _TRUNCATE,
                        "\"address\":\"0x%llx\",\"size\":%lu,"
                        "\"newProtect\":\"0x%lx\"",
                        (unsigned long long)(ULONG_PTR)addr,
                        (unsigned long)size, newProt);
            wlog_event("vprotect_exec", SC_VPROTECT_RWX, "warn", key, data,
                       "VirtualProtect raised protection to executable"
                       " (0x%lx) at 0x%llx", newProt,
                       (unsigned long long)(ULONG_PTR)addr);
        }
    }
    return ok;
}

static BOOL WINAPI hk_CreateProcessW(LPCWSTR app, LPWSTR cmd,
    LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
    DWORD cflags, LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si,
    LPPROCESS_INFORMATION pi)
{
    BOOL ok = orig_CreateProcessW(app, cmd, pa, ta, inherit, cflags, env,
                                  cwd, si, pi);
    if (ok && pi) {
        char key[40];
        char data[700];
        char *cmdA = NULL;
        _snprintf_s(key, sizeof(key), _TRUNCATE, "cp-%lu", pi->dwProcessId);
        if (mon_once(key)) {
            if (cmd) wu_w2utf8(cmd, &cmdA);
            _snprintf_s(data, sizeof(data), _TRUNCATE,
                        "\"childPid\":%lu,\"cmdline\":\"%s\","
                        "\"suspended\":%s",
                        pi->dwProcessId, cmdA ? cmdA : "",
                        (cflags & CREATE_SUSPENDED) ? "true" : "false");
            wlog_event("childproc", SC_CHILDPROC, "info", key, data,
                       "child process %lu created: %s%s",
                       pi->dwProcessId, cmdA ? cmdA : "",
                       (cflags & CREATE_SUSPENDED) ? " (suspended)" : "");
            warden_free(cmdA);
        }
    }
    return ok;
}

/* ------------------------------------------------------------------ */

static HOOK g_hooks[] = {
    { "ntdll!LdrLoadDll",      NULL, (void *)hk_LdrLoadDll,     NULL, FALSE },
    { "kernelbase!LoadLibraryExW", NULL, (void *)hk_LoadLibraryExW, NULL, FALSE },
    { "kernelbase!VirtualAlloc",   NULL, (void *)hk_VirtualAlloc,   NULL, FALSE },
    { "kernelbase!VirtualProtect", NULL, (void *)hk_VirtualProtect, NULL, FALSE },
    { "kernelbase!CreateProcessW", NULL, (void *)hk_CreateProcessW, NULL, FALSE },
    { NULL, NULL, NULL, NULL, FALSE }
};

void hooks_install_all(void)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKb = GetModuleHandleW(L"kernelbase.dll");
    DWORD i;
    int installed = 0;

    if (!hNtdll || !hKb) {
        wlog_event("hooks_error", SC_INFO, "warn", NULL, NULL,
                   "hook init failed: ntdll/kernelbase not resolvable");
        return;
    }

    g_hooks[0].target = (void *)GetProcAddress(hNtdll, "LdrLoadDll");
    g_hooks[1].target = (void *)GetProcAddress(hKb, "LoadLibraryExW");
    g_hooks[2].target = (void *)GetProcAddress(hKb, "VirtualAlloc");
    g_hooks[3].target = (void *)GetProcAddress(hKb, "VirtualProtect");
    g_hooks[4].target = (void *)GetProcAddress(hKb, "CreateProcessW");

    for (i = 0; g_hooks[i].name; i++) {
        if (!g_hooks[i].target) continue;
        if (install_one(&g_hooks[i])) {
            installed++;
            wlog_event("hook_installed", SC_INFO, wlog_verbose() ? "info"
                       : "debug", g_hooks[i].name, NULL,
                       "hook installed: %s", g_hooks[i].name);
        }
    }

    /* publish trampolines */
    orig_LdrLoadDll     = (PFN_LdrLoadDll)g_hooks[0].trampoline;
    orig_LoadLibraryExW = (PFN_LoadLibraryExW)g_hooks[1].trampoline;
    orig_VirtualAlloc   = (PFN_VirtualAlloc)g_hooks[2].trampoline;
    orig_VirtualProtect = (PFN_VirtualProtect)g_hooks[3].trampoline;
    orig_CreateProcessW = (PFN_CreateProcessW)g_hooks[4].trampoline;

    wlog_event("hooks_ready", SC_INFO, "ok", NULL,
               NULL, "telemetry hooks active: %lu / 5",
               (unsigned long)installed);
}
