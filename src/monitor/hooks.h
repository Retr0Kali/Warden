/*
 * Warden - src/monitor/hooks.h
 * Conservative x64 inline hook engine (trampoline detours) used for
 * best-effort API telemetry. Every hook degrades gracefully: if the
 * prologue cannot be safely relocated the hook is skipped and a debug
 * event is emitted - the scanner/integrity layers stay fully functional
 * without hooks.
 */
#ifndef WARDEN_HOOKS_H
#define WARDEN_HOOKS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Install all telemetry hooks (LdrLoadDll, LoadLibraryExW, VirtualAlloc,
 * VirtualProtect, CreateProcessW). Safe to call once at monitor start. */
void hooks_install_all(void);

#ifdef __cplusplus
}
#endif
#endif /* WARDEN_HOOKS_H */
