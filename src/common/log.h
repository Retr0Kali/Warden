/*
 * Warden - src/common/log.h
 * Event emission for the monitor DLL: named-pipe live feed + JSONL + text log.
 * One JSON object per line, e.g.
 *   {"ts":"10:02:03.004","pid":1234,"ev":"amsi_tamper","sev":"crit",
 *    "w":50,"dedup":"AmsiScanBuffer","data":{"func":"AmsiScanBuffer"},
 *    "msg":"amsi.dll!AmsiScanBuffer patched"}
 */
#ifndef WARDEN_LOG_H
#define WARDEN_LOG_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise logging. pipeName may be NULL (file-only mode).
 * dir is the session directory (must exist). Returns TRUE if either
 * the pipe or the files could be opened. */
BOOL wlog_init(const wchar_t *pipeName, const wchar_t *dir, DWORD flags);

/* Close handles (called from reaper thread, not DllMain). */
void wlog_close(void);

/*
 * Emit one event.
 *  ev     - short event kind, e.g. "exec_region"
 *  w      - score weight carried to the launcher aggregator
 *  sev    - "info" | "ok" | "warn" | "crit" | "debug"
 *  dedup  - key so the launcher scores a class of finding once (NULL = none)
 *  data   - pre-formatted JSON object fragment WITHOUT braces, e.g.
 *           "\"func\":\"AmsiScanBuffer\"" (may be NULL)
 *  msgFmt - printf-style human message (+ args)
 */
void wlog_event(const char *ev, long w, const char *sev, const char *dedup,
                const char *dataFmt, const char *msgFmt, ...);

/* Raw line write (already valid JSON), used by profiler layer. */
void wlog_raw_json(const char *jsonLine);

/* Verbose enabled? */
BOOL wlog_verbose(void);

/* Session directory (for dump paths) */
const wchar_t *wlog_dir(void);

/* Capability flags */
DWORD wlog_flags(void);

#ifdef __cplusplus
}
#endif
#endif /* WARDEN_LOG_H */
