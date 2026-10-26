/*
 * Warden - src/launcher/inject.h
 * DLL injection modes: classic (CreateRemoteThread + LoadLibraryW),
 * early APC (QueueUserAPC on the suspended main thread) and
 * manual map (reflective-style out-of-process PE mapping).
 */
#ifndef WARDEN_INJECT_H
#define WARDEN_INJECT_H

#include <windows.h>
#include "../common/warden.h"

typedef enum _INJECT_MODE {
    INJ_CLASSIC = 0,
    INJ_APC     = 1,
    INJ_MANUAL  = 2
} INJECT_MODE;

/*
 * Inject Warden.dll into hProc using the selected mode.
 * hThread    - suspended main thread (required for INJ_APC)
 * dllPath    - absolute path to the monitor DLL
 * ctx        - context block (copied into the target)
 * readyHMod  - [out] module handle of the DLL inside the target, if known
 * Returns TRUE when the DLL is loaded and InitWarden has been queued/run.
 */
BOOL inj_inject(INJECT_MODE mode, HANDLE hProc, HANDLE hThread,
                const wchar_t *dllPath, const WARDEN_CTX *ctx,
                DWORD64 *readyHMod);

#endif /* WARDEN_INJECT_H */
