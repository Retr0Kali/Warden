/*
 * Warden - src/monitor/scanner.h
 * Periodic memory scanner: private executable MZ images, shellcode
 * regions, shadow (PEB-hidden) images, CLR presence, PE dumping.
 */
#ifndef WARDEN_SCANNER_H
#define WARDEN_SCANNER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Blocking scanner loop (call from a dedicated thread). */
void scanner_run(DWORD intervalMs);

#ifdef __cplusplus
}
#endif
#endif /* WARDEN_SCANNER_H */
