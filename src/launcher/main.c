/*
 * Warden - src/launcher/main.c
 *
 * Launcher flow:
 *   1. parse arguments, resolve target (exe/bat/cmd/ps1)
 *   2. create session dir  %TEMP%\Warden\<ts>\  (+ dumps\)
 *   3. set CLR profiler environment variables (registry-free)
 *   4. CreateProcessW(target) suspended
 *   5. inject monitor DLL (classic | apc | manual | none)
 *   6. named-pipe server streams live events, waits for READY
 *   7. resume main thread, wait for exit
 *   8. finalise score/verdict, write reports, map exit code
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/warden.h"
#include "../common/util.h"
#include "inject.h"
#include "report.h"

#pragma warning(disable : 4996)

typedef struct _OPTS {
    INJECT_MODE inject;
    BOOL  noInject;
    BOOL  noProfiler;
    BOOL  noHooks;
    BOOL  noDump;
    BOOL  quiet;
    BOOL  verbose;
    DWORD scanMs;
    wchar_t dllPath[MAX_PATH];
    wchar_t sessionDir[600];
    wchar_t target[MAX_PATH];
    wchar_t extra[1024];
} OPTS;

static void usage(void)
{
    printf(
"===================================================================\n"
" Warden v%s - x64 .NET runtime sentinel for malware analysts\n"
"===================================================================\n"
"USAGE:\n"
"  Warden.exe [options] <target.exe|bat|cmd|ps1> [-- target args...]\n\n"
"OPTIONS:\n"
"  --inject <classic|apc|manual>  injection technique (default classic)\n"
"  --no-inject                    profiler-only monitoring, no injection\n"
"  --no-profiler                  do not set CLR profiler env vars\n"
"  --no-hooks                     monitor runs without inline API hooks\n"
"  --no-dump                      monitor does not dump PE images\n"
"  --scan-ms <N>                  memory scanner interval (default 1500)\n"
"  --dir <PATH>                   override session directory\n"
"  --dll <PATH>                   override monitor DLL path (Warden.dll)\n"
"  --quiet                        reserved (live echo is always shown)\n"
"  --verbose                      extra telemetry from the monitor\n"
"  --help                         this text\n\n"
"EXAMPLES:\n"
"  Warden.exe suspicious.bat\n"
"  Warden.exe --inject manual payload.exe\n"
"  Warden.exe --scan-ms 500 report.ps1 -- -NoExit\n\n"
"EXIT CODES: 0 clean | 1 suspicious | 2 malicious | 3 error\n",
        WARDEN_VERSION);
}

static BOOL parse_args(int argc, wchar_t **argv, OPTS *o, BOOL *help)
{
    int i;
    BOOL afterDD = FALSE;
    int targetSeen = 0;

    memset(o, 0, sizeof(*o));
    o->inject = INJ_CLASSIC;
    o->scanMs = 1500;

    for (i = 1; i < argc; i++) {
        wchar_t *a = argv[i];
        if (!afterDD && !wcscmp(a, L"--help")) { *help = TRUE; return TRUE; }
        else if (!afterDD && !wcscmp(a, L"--")) { afterDD = TRUE; }
        else if (!afterDD && !wcscmp(a, L"--inject")) {
            if (++i >= argc) return FALSE;
            if (!wcscmp(argv[i], L"classic")) o->inject = INJ_CLASSIC;
            else if (!wcscmp(argv[i], L"apc")) o->inject = INJ_APC;
            else if (!wcscmp(argv[i], L"manual")) o->inject = INJ_MANUAL;
            else return FALSE;
        }
        else if (!afterDD && !wcscmp(a, L"--no-inject"))   o->noInject = TRUE;
        else if (!afterDD && !wcscmp(a, L"--no-profiler")) o->noProfiler = TRUE;
        else if (!afterDD && !wcscmp(a, L"--no-hooks"))    o->noHooks = TRUE;
        else if (!afterDD && !wcscmp(a, L"--no-dump"))     o->noDump = TRUE;
        else if (!afterDD && !wcscmp(a, L"--quiet"))       o->quiet = TRUE;
        else if (!afterDD && !wcscmp(a, L"--verbose"))     o->verbose = TRUE;
        else if (!afterDD && !wcscmp(a, L"--scan-ms")) {
            if (++i >= argc) return FALSE;
            o->scanMs = (DWORD)wcstoul(argv[i], NULL, 10);
            if (o->scanMs < 100 || o->scanMs > 60000) return FALSE;
        }
        else if (!afterDD && !wcscmp(a, L"--dir")) {
            if (++i >= argc) return FALSE;
            wcsncpy_s(o->sessionDir, 600, argv[i], _TRUNCATE);
        }
        else if (!afterDD && !wcscmp(a, L"--dll")) {
            if (++i >= argc) return FALSE;
            wcsncpy_s(o->dllPath, MAX_PATH, argv[i], _TRUNCATE);
        }
        else {
            if (!afterDD && targetSeen == 0) {
                wcsncpy_s(o->target, MAX_PATH, a, _TRUNCATE);
                targetSeen++;
            } else {
                size_t len = wcslen(o->extra);
                _snwprintf_s(o->extra + len, 1024 - len, _TRUNCATE,
                             L"%ls%ls", targetSeen ? L" " : L"", a);
                if (!afterDD) targetSeen++;
            }
        }
    }
    return targetSeen >= 1;
}

/* ------------------------------------------------------------------ */
/* environment helpers                                                 */
/* ------------------------------------------------------------------ */

static void set_env_dw(const wchar_t *name, DWORD value)
{
    wchar_t buf[32];
    _snwprintf_s(buf, 32, _TRUNCATE, L"%lu", value);
    SetEnvironmentVariableW(name, buf);
}

static void setup_profiler_env(const wchar_t *dllPath)
{
    SetEnvironmentVariableW(ENV_COR_ENABLE, L"1");
    SetEnvironmentVariableW(ENV_COR_CLSID, WARDEN_PROFILER_CLSID_W);
    SetEnvironmentVariableW(ENV_COR_PATH64, dllPath);
    /* .NET Core / 5+ best effort (see docs limitations) */
    SetEnvironmentVariableW(ENV_CC_ENABLE, L"1");
    SetEnvironmentVariableW(ENV_CC_CLSID, WARDEN_PROFILER_CLSID_W);
    SetEnvironmentVariableW(ENV_CC_PATH64, dllPath);
}

static void build_session_dir(OPTS *o)
{
    wchar_t temp[520];
    wchar_t stamp[64];
    SYSTEMTIME st;

    if (o->sessionDir[0]) return;
    GetTempPathW(520, temp);
    GetLocalTime(&st);
    _snwprintf_s(stamp, 64, _TRUNCATE, L"%04u%02u%02u_%02u%02u%02u_p%lu",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId());
    _snwprintf_s(o->sessionDir, 600, _TRUNCATE, L"%s%s\\%s",
                 temp, WARDEN_TEMP_ROOT, stamp);
}

static void resolve_target_command(const OPTS *o, wchar_t *cmd, DWORD cap,
                                   const wchar_t **fileType)
{
    const wchar_t *ext = wcsrchr(o->target, L'.');
    wchar_t q[MAX_PATH + 2];

    _snwprintf_s(q, MAX_PATH + 2, _TRUNCATE, L"\"%s\"", o->target);
    *fileType = L"exe";
    if (ext && (!_wcsicmp(ext, L".bat") || !_wcsicmp(ext, L".cmd"))) {
        *fileType = L"bat/cmd script";
        _snwprintf_s(cmd, cap, _TRUNCATE, L"cmd.exe /c %ls %ls", q, o->extra);
    } else if (ext && !_wcsicmp(ext, L".ps1")) {
        *fileType = L"powershell script";
        _snwprintf_s(cmd, cap, _TRUNCATE,
            L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File %ls %ls",
            q, o->extra);
    } else {
        _snwprintf_s(cmd, cap, _TRUNCATE, L"%ls %ls", q, o->extra);
    }
}

static void console_enable_vt(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

/* ------------------------------------------------------------------ */
/* overlapped pipe server: connector + reader in one thread            */
/* ------------------------------------------------------------------ */

typedef struct _PIPE_CTX {
    HANDLE  hPipe;
    WARDEN_REPORT *rep;
    volatile LONG ready;
    volatile LONG stop;
} PIPE_CTX;

static void feed_lines(PIPE_CTX *pc, char *buf, DWORD got)
{
    char *ctxTok = NULL;
    char *line;
    buf[got] = 0;
    line = strtok_s(buf, "\n", &ctxTok);
    while (line) {
        if (*line) {
            rep_feed(pc->rep, line);
            if (strstr(line, "\"ev\":\"ready\""))
                InterlockedExchange(&pc->ready, 1);
        }
        line = strtok_s(NULL, "\n", &ctxTok);
    }
}

static DWORD WINAPI pipe_thread(LPVOID arg)
{
    PIPE_CTX *pc = (PIPE_CTX *)arg;
    OVERLAPPED ov;
    char buf[8192];
    BOOL connected = FALSE;

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) return 0;

    /* wait for the monitor to connect (bounded) */
    if (ConnectNamedPipe(pc->hPipe, &ov) ||
        GetLastError() == ERROR_PIPE_CONNECTED) {
        connected = TRUE;
    } else if (GetLastError() == ERROR_IO_PENDING) {
        DWORD w = WaitForSingleObject(ov.hEvent, 20000);
        if (w == WAIT_OBJECT_0) {
            DWORD br = 0;
            if (!GetOverlappedResult(pc->hPipe, &ov, &br, FALSE) &&
                GetLastError() != ERROR_PIPE_CONNECTED)
                connected = FALSE;
            else
                connected = TRUE;
        } else {
            CancelIoEx(pc->hPipe, &ov);
            connected = FALSE;
        }
    }

    if (!connected) {
        CloseHandle(ov.hEvent);
        return 0;   /* no live feed; monitor still logs to files */
    }

    while (!pc->stop) {
        DWORD got = 0;
        ResetEvent(ov.hEvent);
        if (!ReadFile(pc->hPipe, buf, sizeof(buf) - 1, &got, &ov)) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                if (WaitForSingleObject(ov.hEvent, 15000) != WAIT_OBJECT_0) {
                    CancelIoEx(pc->hPipe, &ov);
                    break;
                }
                if (!GetOverlappedResult(pc->hPipe, &ov, &got, FALSE))
                    break;
            } else {
                break;  /* broken pipe - monitor finished */
            }
        }
        if (got == 0) break;
        feed_lines(pc, buf, got);
    }
    CloseHandle(ov.hEvent);
    return 0;
}

/* ------------------------------------------------------------------ */

int wmain(int argc, wchar_t **argv)
{
    OPTS o;
    BOOL help = FALSE;
    wchar_t cmd[2200];
    wchar_t pipeName[128];
    wchar_t dumpDir[660];
    const wchar_t *fileType = L"exe";
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WARDEN_CTX ctx;
    PIPE_CTX pc;
    HANDLE hPipeThread = NULL;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    WARDEN_REPORT *rep;
    DWORD64 dllRemote = 0;
    DWORD startTick, endTick;
    DWORD exitCode = 0;
    int verdict;
    DWORD flags;
    BOOL isWow64 = FALSE;
    BOOL pipeOk = FALSE;

    if (!parse_args(argc, argv, &o, &help) || help) {
        if (!help) printf("[!] bad arguments\n\n");
        usage();
        return help ? 0 : EXITCODE_ERROR;
    }
    if (!o.target[0]) { usage(); return EXITCODE_ERROR; }

    console_enable_vt();

    {
        wchar_t full[MAX_PATH];
        if (GetFullPathNameW(o.target, MAX_PATH, full, NULL))
            wcsncpy_s(o.target, MAX_PATH, full, _TRUNCATE);
    }
    if (o.dllPath[0]) {
        wchar_t full[MAX_PATH];
        if (GetFullPathNameW(o.dllPath, MAX_PATH, full, NULL))
            wcsncpy_s(o.dllPath, MAX_PATH, full, _TRUNCATE);
    } else {
        wchar_t selfDir[MAX_PATH];
        GetModuleFileNameW(NULL, selfDir, MAX_PATH);
        {
            wchar_t *slash = wcsrchr(selfDir, L'\\');
            if (slash) *(slash + 1) = 0;
            _snwprintf_s(o.dllPath, MAX_PATH, _TRUNCATE,
                         L"%sWarden.dll", selfDir);
        }
    }

    if (GetFileAttributesW(o.target) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] target not found: %ls\n", o.target);
        return EXITCODE_ERROR;
    }
    if (GetFileAttributesW(o.dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] monitor DLL not found: %ls (build it with build.bat)\n",
               o.dllPath);
        return EXITCODE_ERROR;
    }

    IsWow64Process(GetCurrentProcess(), &isWow64);
    if (isWow64) {
        printf("[!] 32-bit launcher context detected - Warden is x64-only\n");
        return EXITCODE_ERROR;
    }

    build_session_dir(&o);
    _snwprintf_s(dumpDir, 660, _TRUNCATE, L"%s\\%s", o.sessionDir,
                 WARDEN_DUMP_SUBDIR);
    if (!wu_mkdirs(o.sessionDir) || !wu_mkdirs(dumpDir)) {
        printf("[!] cannot create session directory: %ls\n", o.sessionDir);
        return EXITCODE_ERROR;
    }

    resolve_target_command(&o, cmd, 2200, &fileType);

    flags = 0;
    if (!o.noDump) flags |= WF_DUMP;
    if (!o.noHooks) flags |= WF_HOOKS;
    flags |= WF_INTEGRITY;
    if (o.verbose) flags |= WF_VERBOSE;

    _snwprintf_s(pipeName, 128, _TRUNCATE, WARDEN_PIPE_FMT,
                 GetCurrentProcessId(), GetTickCount());

    memset(&ctx, 0, sizeof(ctx));
    ctx.cbSize  = sizeof(ctx);
    ctx.flags   = flags;
    ctx.scanMs  = o.scanMs;
    ctx.rootPid = 0;
    wcsncpy_s(ctx.pipe, 128, pipeName, _TRUNCATE);
    wcsncpy_s(ctx.dir, 300, o.sessionDir, _TRUNCATE);

    printf("[*] Warden v%s session\n", WARDEN_VERSION);
    printf("    target  : %ls\n", o.target);
    printf("    type    : %ls\n", fileType);
    printf("    inject  : %ls\n",
           o.noInject ? L"none (profiler-only)" :
           o.inject == INJ_CLASSIC ? L"classic (CreateRemoteThread)" :
           o.inject == INJ_APC     ? L"early-APC" : L"manual-map");
    printf("    session : %ls\n", o.sessionDir);
    printf("    dll     : %ls\n", o.dllPath);

    if (!o.noProfiler)
        setup_profiler_env(o.dllPath);
    else {
        SetEnvironmentVariableW(ENV_COR_ENABLE, L"0");
        SetEnvironmentVariableW(ENV_CC_ENABLE, L"0");
    }
    SetEnvironmentVariableW(ENV_PIPE, pipeName);
    SetEnvironmentVariableW(ENV_DIR, o.sessionDir);
    set_env_dw(ENV_FLAGS, flags);
    set_env_dw(ENV_SCANMS, o.scanMs);
    set_env_dw(ENV_ROOTPID, GetCurrentProcessId());

    /* --- create suspended target ------------------------------------ */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                        NULL, NULL, &si, &pi)) {
        printf("[!] CreateProcessW failed: %lu\n", GetLastError());
        return EXITCODE_ERROR;
    }
    IsWow64Process(pi.hProcess, &isWow64);
    if (isWow64) {
        printf("[!] target is 32-bit (WoW64) - Warden supports x64 targets only\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return EXITCODE_ERROR;
    }
    ctx.rootPid = pi.dwProcessId;
    printf("[*] target pid %lu created suspended\n", pi.dwProcessId);

    /* --- pipe server (starts immediately, monitor connects later) ---- */
    hPipe = CreateNamedPipeW(pipeName,
                             PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                             PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE |
                             PIPE_WAIT,
                             1, 8192, 8192, 0, NULL);
    rep = rep_create();
    pc.hPipe = hPipe;
    pc.rep = rep;
    pc.ready = 0;
    pc.stop = 0;
    if (hPipe != INVALID_HANDLE_VALUE) {
        pipeOk = TRUE;
        hPipeThread = CreateThread(NULL, 0, pipe_thread, &pc, 0, NULL);
    } else {
        printf("[!] pipe creation failed (%lu) - file logs only\n",
               GetLastError());
    }

    /* --- inject ------------------------------------------------------ */
    startTick = GetTickCount();
    if (!o.noInject) {
        printf("[*] injecting monitor (%ls mode)...\n",
               o.inject == INJ_CLASSIC ? L"classic" :
               o.inject == INJ_APC ? L"apc" : L"manual");
        if (!inj_inject(o.inject, pi.hProcess, pi.hThread, o.dllPath,
                        &ctx, &dllRemote)) {
            printf("[!] injection failed (gle=%lu) - continuing with"
                   " profiler telemetry only\n", GetLastError());
        }
    } else {
        printf("[*] profiler-only mode: monitor loads via CLR env vars\n");
    }

    /* --- wait for READY then resume ---------------------------------- */
    if (pipeOk) {
        DWORD waited = 0;
        while (!pc.ready && waited < (o.noInject ? 20000 : 15000)) {
            Sleep(100);
            waited += 100;
        }
        if (pc.ready)
            printf("[*] monitor ready\x1b[1;92m OK\x1b[0m\n");
        else
            printf("[!] monitor not ready in time - resuming anyway\n");
    }
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[!] ResumeThread failed: %lu\n", GetLastError());
    }
    printf("[*] target resumed - live feed:\n\n");

    /* --- wait for exit ------------------------------------------------ */
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    endTick = GetTickCount();

    /* let the monitor flush final events, then stop the reader */
    Sleep(700);
    pc.stop = 1;
    if (pipeOk) {
        CancelIoEx(hPipe, NULL);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        if (hPipeThread) {
            WaitForSingleObject(hPipeThread, 2000);
            CloseHandle(hPipeThread);
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    {
        double wall = (endTick - startTick) / 1000.0;
        verdict = rep_finalize(rep, o.sessionDir, o.target, pi.dwProcessId,
                               exitCode, wall);
    }
    rep_free(rep);
    return verdict;
}
