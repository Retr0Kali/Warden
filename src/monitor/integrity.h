/*
 * Warden - src/monitor/integrity.h
 * Live-vs-disk integrity engine for amsi.dll / ntdll.dll / clr.dll.
 */
#ifndef WARDEN_INTEGRITY_H
#define WARDEN_INTEGRITY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Blocking integrity loop (call from a dedicated thread). */
void integrity_run(DWORD intervalMs);

#ifdef __cplusplus
}
#endif
#endif /* WARDEN_INTEGRITY_H */
