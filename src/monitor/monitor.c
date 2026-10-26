/*
 * Warden - src/monitor/monitor.c
 * Monitor core: one-time init, thread orchestration, self-registration,
 * reaper thread for clean shutdown logging.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monitor.h"
#include "../common/warden.h"
#include "../common/util.h"
#include "../common/log.h"
#include "scanner.h"
#include "integrity.h"
#include "hooks.h"

static volatile LONG g_started = 0;
static DWORD64 g_selfBase64 = 0;
static DWORD   g_selfSize  = 0;

/* patch ranges installed by our own hook engine (integrity must skip) */
#define MAX_PATCH_RANGES 64
typedef struct _PATCH_RANGE { DWORD64 addr; DWORD cb; } PATCH_RANGE;
static PATCH_RANGE g_ranges[MAX_PATCH_RANGES];
static DWORD g_rangeCount = 0;
static CRITICAL_SECTION g_rangeCs;
static BOOL g_rangeCsInit = FALSE;

/* one-shot keys */
#define MAX_ONCE 64
static char g_once[MAX_ONCE][48];
static DWORD g_onceCount = 0;
static CRITICAL_SECTION g_onceCs;
static BOOL g_onceCsInit = FALSE;

static HANDLE g_scanThread   = NULL;
static HANDLE g_integThread  = NULL;
static HANDLE g_reaperThread = NULL;
static DWORD  g_scanMs       = 1500;
static DWORD  g_flags        = WF_ALL;

DWORD64 mon_self_base(void) { return g_selfBase64; }
DWORD   mon_self_size(void) { return g_selfSize; }

BOOL mon_module_info_from_addr(DWORD64 addr, DWORD64 *base, DWORD *size)
{
    HMODULE hMod = NULL;
    MODULEINFO mi;
    if (!base || !size) return FALSE;
    *base = 0; *size = 0;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)(ULONG_PTR)addr, &hMod) || !hMod)
        return FALSE;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
        return FALSE;
    *base = (DWORD64)mi.lpBaseOfDll;
    *size = mi.SizeOfImage;
    return TRUE;
}

BOOL mon_once(const char *key)
{
    DWORD i;
    BOOL fresh = FALSE;
    if (!g_onceCsInit) return FALSE;
    EnterCriticalSection(&g_onceCs);
    for (i = 0; i < g_onceCount; i++)
        if (!strcmp(g_once[i], key)) { LeaveCriticalSection(&g_onceCs); return FALSE; }
    if (g_onceCount < MAX_ONCE) {
        strncpy_s(g_once[g_onceCount], 48, key, _TRUNCATE);
        g_onceCount++;
        fresh = TRUE;
    }
    LeaveCriticalSection(&g_onceCs);
    return fresh;
}

void mon_register_patch_range(DWORD64 addr, DWORD cb)
{
    if (!g_rangeCsInit) return;
    EnterCriticalSection(&g_rangeCs);
    if (g_rangeCount < MAX_PATCH_RANGES) {
        g_ranges[g_rangeCount].addr = addr;
        g_ranges[g_rangeCount].cb = cb;
        g_rangeCount++;
    }
    LeaveCriticalSection(&g_rangeCs);
}

DWORD mon_patch_range_count(void)
{
    DWORD n;
    if (!g_rangeCsInit) return 0;
    EnterCriticalSection(&g_rangeCs);
    n = g_rangeCount;
    LeaveCriticalSection(&g_rangeCs);
    return n;
}

BOOL mon_patch_range_at(DWORD idx, DWORD64 *addr, DWORD *cb)
{
    BOOL ok = FALSE;
    if (!g_rangeCsInit) return FALSE;
    EnterCriticalSection(&g_rangeCs);
    if (idx < g_rangeCount) {
        *addr = g_ranges[idx].addr;
        *cb = g_ranges[idx].cb;
        ok = TRUE;
    }
    LeaveCriticalSection(&g_rangeCs);
    return ok;
}

BOOL mon_is_patch_range(DWORD64 addr, DWORD cb)
{
    DWORD i;
    if (!g_rangeCsInit) return FALSE;
    EnterCriticalSection(&g_rangeCs);
    for (i = 0; i < g_rangeCount; i++) {
        if (addr < g_ranges[i].addr + g_ranges[i].cb &&
            addr + cb > g_ranges[i].addr) {
            LeaveCriticalSection(&g_rangeCs);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_rangeCs);
    return FALSE;
}

BOOL mon_is_self_region(DWORD64 addr, DWORD cb)
{
    if (!g_selfBase64) return FALSE;
    return addr < g_selfBase64 + g_selfSize &&
           addr + cb > g_selfBase64;
}

/* ------------------------------------------------------------------ */
/* config resolution (env fallbacks for profiler-only mode)            */
/* ------------------------------------------------------------------ */

static DWORD env_dw_hex(const wchar_t *name, DWORD def)
{
    wchar_t buf[32];
    DWORD n = GetEnvironmentVariableW(name, buf, 32);
    if (n == 0 || n >= 32) return def;
    return wcstoul(buf, NULL, 16);
}

static DWORD env_dw_dec(const wchar_t *name, DWORD def)
{
    wchar_t buf[32];
    DWORD n = GetEnvironmentVariableW(name, buf, 32);
    if (n == 0 || n >= 32) return def;
    return wcstoul(buf, NULL, 10);
}

/* ------------------------------------------------------------------ */
/* reaper: wait for process exit, flush, close                         */
/* ------------------------------------------------------------------ */

static DWORD WINAPI reaper_thread(LPVOID arg)
{
    (void)arg;
    WaitForSingleObject(GetCurrentProcess(), INFINITE);
    wlog_event("done", SC_INFO, "info", NULL,
               NULL, "target exiting - monitor shutting down");
    Sleep(150);
    wlog_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* startup                                                             */
/* ------------------------------------------------------------------ */

static DWORD WINAPI scan_entry(LPVOID arg)   { (void)arg; scanner_run(g_scanMs);  return 0; }
static DWORD WINAPI integ_entry(LPVOID arg)  { (void)arg; integrity_run(g_scanMs * 2); return 0; }

void mon_start(const WARDEN_CTX *ctx)
{
    wchar_t pipeName[128] = {0};
    wchar_t dir[300] = {0};
    wchar_t tmpRoot[520];

    /* single-shot guard */
    if (InterlockedCompareExchange(&g_started, 1, 0) != 0)
        return;

    if (ctx && ctx->cbSize == sizeof(WARDEN_CTX)) {
        g_flags  = ctx->flags;
        g_scanMs = ctx->scanMs ? ctx->scanMs : 1500;
        wcsncpy_s(pipeName, 128, ctx->pipe, _TRUNCATE);
        wcsncpy_s(dir, 300, ctx->dir, _TRUNCATE);
    } else {
        /* profiler-driven mode: read env */
        wchar_t buf[300];
        DWORD n;
        g_flags  = env_dw_hex(ENV_FLAGS, WF_ALL);
        g_scanMs = env_dw_dec(ENV_SCANMS, 1500);
        if (!g_scanMs) g_scanMs = 1500;
        n = GetEnvironmentVariableW(ENV_PIPE, pipeName, 128);
        (void)n;
        n = GetEnvironmentVariableW(ENV_DIR, buf, 300);
        if (n && n < 300) wcsncpy_s(dir, 300, buf, _TRUNCATE);
        if (!dir[0]) {
            GetTempPathW(520, tmpRoot);
            _snwprintf_s(dir, 300, _TRUNCATE, L"%s%s\\self_%lu",
                         tmpRoot, WARDEN_TEMP_ROOT, GetCurrentProcessId());
            wu_mkdirs(dir);
        }
    }

    if (!g_rangeCsInit) {
        InitializeCriticalSection(&g_rangeCs);
        g_rangeCsInit = TRUE;
    }
    if (!g_onceCsInit) {
        InitializeCriticalSection(&g_onceCs);
        g_onceCsInit = TRUE;
    }

    /* self registration (handles manual-mapped DLL absent from the PEB) */
    {
        HMODULE hSelf = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)&mon_start, &hSelf) && hSelf) {
            MODULEINFO mi;
            if (GetModuleInformation(GetCurrentProcess(), hSelf,
                                     &mi, sizeof(mi))) {
                g_selfBase64 = (DWORD64)mi.lpBaseOfDll;
                g_selfSize   = mi.SizeOfImage;
            }
        }
    }

    wlog_init(pipeName[0] ? pipeName : NULL, dir[0] ? dir : NULL, g_flags);

    {
        char data[160];
        _snprintf_s(data, sizeof(data), _TRUNCATE,
                    "\"flags\":%lu,\"scanMs\":%lu,\"pid\":%lu",
                    g_flags, g_scanMs, GetCurrentProcessId());
        wlog_event("ready", SC_INFO, "ok", NULL, data,
                   "Warden monitor active (x64) - watching .NET runtime," 
                   " memory and integrity");
    }

    if (g_flags & WF_HOOKS)
        hooks_install_all();

    g_scanThread  = CreateThread(NULL, 0, scan_entry, NULL, 0, NULL);
    g_integThread = CreateThread(NULL, 0, integ_entry, NULL, 0, NULL);
    g_reaperThread = CreateThread(NULL, 0, reaper_thread, NULL, 0, NULL);
}
