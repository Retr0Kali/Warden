/*
 * Warden - x64 .NET runtime sentinel for malware analysts
 * src/common/warden.h - shared definitions between launcher and monitor DLL
 *
 * MIT License - see LICENSE in repository root.
 * Authorized-lab analysis use only. See README.md disclaimer.
 */
#ifndef WARDEN_H
#define WARDEN_H

#include <windows.h>

/* ------------------------------------------------------------------ */
/* Brand / version                                                     */
/* ------------------------------------------------------------------ */
#define WARDEN_VERSION       "1.0.0"
#define WARDEN_BRAND_A       "Warden"
#define WARDEN_BRAND_W       L"Warden"

/* Named pipe namespace used for the live event feed */
#define WARDEN_PIPE_PREFIX   L"\\\\.\\pipe\\Warden\\"
#define WARDEN_PIPE_FMT      L"\\\\.\\pipe\\Warden\\%lu-%lu"

/* Subdirectory layout under %TEMP% */
#define WARDEN_TEMP_ROOT     L"Warden"
#define WARDEN_DUMP_SUBDIR   L"dumps"

/* ------------------------------------------------------------------ */
/* Environment variables handed from launcher to monitor               */
/* ------------------------------------------------------------------ */
#define ENV_PIPE      L"WARDEN_PIPE"       /* live feed pipe name          */
#define ENV_DIR       L"WARDEN_DIR"        /* session directory            */
#define ENV_FLAGS     L"WARDEN_FLAGS"      /* hex capability bitmask       */
#define ENV_SCANMS    L"WARDEN_SCANMS"     /* scanner interval, ms         */
#define ENV_ROOTPID   L"WARDEN_ROOTPID"    /* root target pid (information)*/

/* CLR profiler env vars (registry-free, .NET Framework 4+)            */
#define ENV_COR_ENABLE  L"COR_ENABLE_PROFILING"
#define ENV_COR_CLSID   L"COR_PROFILER"
#define ENV_COR_PATH64  L"COR_PROFILER_PATH_64"
/* .NET Core / 5+ equivalents (best effort; see docs limitations)      */
#define ENV_CC_ENABLE   L"CORECLR_ENABLE_PROFILING"
#define ENV_CC_CLSID    L"CORECLR_PROFILER"
#define ENV_CC_PATH64   L"CORECLR_PROFILER_PATH_64"

/* COM CLSID of the Warden ICorProfilerCallback coclass                */
#define WARDEN_PROFILER_CLSID_A  "{7C1E6B4A-9A2D-4E8B-B1F3-3C5A7D9E2F41}"
#define WARDEN_PROFILER_CLSID_W  L"{7C1E6B4A-9A2D-4E8B-B1F3-3C5A7D9E2F41}"

/* ------------------------------------------------------------------ */
/* Monitor capability flags (launcher -> monitor via WARDEN_FLAGS)     */
/* ------------------------------------------------------------------ */
#define WF_DUMP        0x00000001u  /* dump discovered PE images       */
#define WF_HOOKS       0x00000002u  /* install inline API hooks        */
#define WF_INTEGRITY   0x00000004u  /* AMSI/ETW/CLR live-vs-disk check */
#define WF_VERBOSE     0x00000008u  /* extra telemetry                 */
#define WF_ALL         0x0000000Fu

/* ------------------------------------------------------------------ */
/* Context block written by launcher, consumed by monitor InitWarden   */
/* ------------------------------------------------------------------ */
typedef struct _WARDEN_CTX {
    DWORD cbSize;              /* sizeof(WARDEN_CTX), sanity check      */
    DWORD flags;               /* WF_* bitmask                          */
    DWORD scanMs;              /* scanner interval in ms                */
    DWORD rootPid;             /* root target process id                */
    WCHAR pipe[128];           /* live feed pipe name                   */
    WCHAR dir[300];            /* session directory                     */
} WARDEN_CTX;

/* Exported by monitor DLL (see src/warden.def) */
typedef void (WINAPI *PFN_INITWARDEN)(LPVOID lpParam);
#define WARDEN_INIT_EXPORT "InitWarden"

/* ------------------------------------------------------------------ */
/* Threat scoring weights (monitor emits "w", launcher aggregates)     */
/* ------------------------------------------------------------------ */
#define SC_INFO               0
#define SC_INMEMORY_MODULE   25   /* CLR module with no image base     */
#define SC_DYNAMIC_MODULE    25   /* Reflection.Emit dynamic module    */
#define SC_EXEC_MZ           30   /* private executable MZ image       */
#define SC_SHELLCODE         15   /* exec region, no PE, high entropy  */
#define SC_HIDDEN_IMAGE      35   /* MEM_IMAGE absent from PEB list    */
#define SC_AMSI_TAMPER       50   /* amsi.dll bytes differ from disk   */
#define SC_ETW_TAMPER        50   /* ntdll EtwEventWrite tampered      */
#define SC_CLR_TAMPER        30   /* clr.dll data/strings patched      */
#define SC_BYPASS_BONUS      10   /* known bypass byte signature match */
#define SC_CHILDPROC          5   /* target spawned a child process    */
#define SC_VALLOC_EXEC        5   /* RWX/RX private allocation         */
#define SC_VPROTECT_RWX      10   /* protection raised to RWX/RX       */

/* Verdict thresholds applied by launcher on the aggregate score       */
#define VERDICT_THRESHOLD_SUSPICIOUS 25
#define VERDICT_THRESHOLD_MALICIOUS  60

#define VERDICT_CLEAN      0
#define VERDICT_SUSPICIOUS 1
#define VERDICT_MALICIOUS  2
#define EXITCODE_ERROR     3

/* Protocol sanity */
#define WARDEN_CTX_MAGIC   0x57415244u   /* 'WARD' */

#endif /* WARDEN_H */
