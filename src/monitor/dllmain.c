/*
 * Warden - src/monitor/dllmain.c
 *
 * DLL entry + exported InitWarden. DllMain deliberately stays minimal
 * (no thread creation, no loader-lock risky work). The monitor boot
 * happens either:
 *   - on the launcher's remote thread   -> InitWarden(ctx)
 *   - on a queued APC (early-APC mode)  -> InitWarden(ctx)
 *   - on the CLR's profiler init path   -> mon_start(NULL) via DllGetClassObject
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "monitor.h"
#include "../common/warden.h"

static HMODULE g_hSelfModule = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)lpReserved;
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        g_hSelfModule = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        break;
    case DLL_PROCESS_DETACH:
        /* best effort only - logging keeps files open; no flush here to
         * stay loader-lock safe */
        break;
    }
    return TRUE;
}

/*
 * Monitor bootstrap exported by Warden.dll.
 * lpParam: pointer to a WARDEN_CTX written into this process by the
 *          launcher (NULL when called through the profiler path).
 */
void WINAPI InitWarden(LPVOID lpParam)
{
    const WARDEN_CTX *ctx = (const WARDEN_CTX *)lpParam;
    if (ctx && ctx->cbSize != sizeof(WARDEN_CTX))
        ctx = NULL;   /* version mismatch -> fall back to env config */
    mon_start(ctx);
}
