/*
 * Warden - src/common/log.c
 * Monitor-side logging: named pipe live feed + events.jsonl + warden.log
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "log.h"
#include "util.h"
#include "warden.h"

static HANDLE  g_pipe        = NULL;   /* write handle to launcher pipe */
static wchar_t g_dir[300]    = {0};
static wchar_t g_jsonlPath[340] = {0};
static wchar_t g_textPath[340]  = {0};
static DWORD   g_flags       = 0;
static DWORD   g_pid         = 0;
static CRITICAL_SECTION g_cs;
static BOOL    g_csInit      = FALSE;

BOOL wlog_init(const wchar_t *pipeName, const wchar_t *dir, DWORD flags)
{
    int tries;
    DWORD mode;

    g_pid = GetCurrentProcessId();
    g_flags = flags;
    if (dir && *dir) {
        wcsncpy_s(g_dir, 300, dir, _TRUNCATE);
        _snwprintf_s(g_jsonlPath, 340, _TRUNCATE, L"%s\\events.jsonl", g_dir);
        _snwprintf_s(g_textPath, 340, _TRUNCATE, L"%s\\warden.log", g_dir);
    }
    InitializeCriticalSection(&g_cs);
    g_csInit = TRUE;

    if (pipeName && *pipeName) {
        for (tries = 0; tries < 30; tries++) {  /* up to ~15 s */
            g_pipe = CreateFileW(pipeName, GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, 0, NULL);
            if (g_pipe != INVALID_HANDLE_VALUE) break;
            if (GetLastError() != ERROR_PIPE_BUSY) {
                g_pipe = NULL;
                break;
            }
            WaitNamedPipeW(pipeName, 500);
        }
        if (g_pipe) {
            mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(g_pipe, &mode, NULL, NULL);
        }
    }
    return (g_pipe != NULL) || (g_jsonlPath[0] != 0);
}

void wlog_close(void)
{
    if (g_csInit) {
        EnterCriticalSection(&g_cs);
        if (g_pipe) {
            FlushFileBuffers(g_pipe);
            CloseHandle(g_pipe);
            g_pipe = NULL;
        }
        LeaveCriticalSection(&g_cs);
        DeleteCriticalSection(&g_cs);
        g_csInit = FALSE;
    }
}

BOOL wlog_verbose(void) { return (g_flags & WF_VERBOSE) != 0; }
const wchar_t *wlog_dir(void) { return g_dir; }
DWORD wlog_flags(void) { return g_flags; }

static void wlog_write_pipe(const char *line, DWORD cb)
{
    DWORD written;
    if (g_pipe && g_pipe != INVALID_HANDLE_VALUE) {
        if (!WriteFile(g_pipe, line, cb, &written, NULL) || written != cb) {
            /* launcher died or pipe broken: drop pipe silently */
            CloseHandle(g_pipe);
            g_pipe = NULL;
        }
    }
}

void wlog_raw_json(const char *jsonLine)
{
    char tmp[4096];
    size_t len;
    char ts[24];

    if (!jsonLine || !g_csInit) return;
    len = strlen(jsonLine);
    if (len == 0) return;

    wu_time_str(ts, sizeof(ts));
    if (jsonLine[len - 1] == '\n') len--;

    EnterCriticalSection(&g_cs);
    /* JSONL: prepend ts/pid is not possible for raw lines; write as-is */
    wu_append_file(g_jsonlPath, jsonLine, (DWORD)len);
    wu_append_file(g_jsonlPath, "\n", 1);

    _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "[%s] %s\n", ts, jsonLine);
    wu_append_file(g_textPath, tmp, (DWORD)strlen(tmp));

    wlog_write_pipe(jsonLine, (DWORD)len);
    wlog_write_pipe("\n", 1);
    LeaveCriticalSection(&g_cs);
}

void wlog_event(const char *ev, long w, const char *sev, const char *dedup,
                const char *dataFmt, const char *msgFmt, ...)
{
    char ts[24];
    char msg[1600];
    char escMsg[3400];
    char dataBuf[900];
    char line[5200];
    va_list ap;
    int n;
    size_t lineLen;
    char escDedup[260];
    char dataPart[920] = {0};
    char dedupPart[280] = {0};

    if (!g_csInit) return;

    msg[0] = 0;
    va_start(ap, msgFmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, msgFmt, ap);
    va_end(ap);
    wu_json_escape(escMsg, sizeof(escMsg), msg);

    /* data is a caller-provided static JSON fragment, not a format string */
    dataBuf[0] = 0;
    if (dataFmt && *dataFmt)
        _snprintf_s(dataBuf, sizeof(dataBuf), _TRUNCATE, "%s", dataFmt);

    wu_time_str(ts, sizeof(ts));

    if (dedup && *dedup) {
        wu_json_escape(escDedup, sizeof(escDedup), dedup);
        _snprintf_s(dedupPart, sizeof(dedupPart), _TRUNCATE,
                    ",\"dedup\":\"%s\"", escDedup);
    }
    if (dataBuf[0])
        _snprintf_s(dataPart, sizeof(dataPart), _TRUNCATE,
                    ",\"data\":{%s}", dataBuf);

    n = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "{\"ts\":\"%s\",\"pid\":%lu,\"ev\":\"%s\",\"sev\":\"%s\",\"w\":%ld%s%s,"
        "\"msg\":\"%s\"}",
        ts, g_pid, ev, sev, w, dedupPart, dataPart, escMsg);
    if (n <= 0) return;
    lineLen = (size_t)n;

    EnterCriticalSection(&g_cs);
    wu_append_file(g_jsonlPath, line, (DWORD)lineLen);
    wu_append_file(g_jsonlPath, "\n", 1);

    {
        char human[4200];
        _snprintf_s(human, sizeof(human), _TRUNCATE, "[%s] [%-4s] %s\n",
                    ts, sev, msg);
        wu_append_file(g_textPath, human, (DWORD)strlen(human));
    }

    wlog_write_pipe(line, (DWORD)lineLen);
    wlog_write_pipe("\n", 1);
    LeaveCriticalSection(&g_cs);
}
