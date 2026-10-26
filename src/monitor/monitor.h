/*
 * Warden - src/monitor/monitor.h
 * Monitor core initialisation shared by DllMain / profiler / APC paths.
 */
#ifndef WARDEN_MONITOR_H
#define WARDEN_MONITOR_H

#include <windows.h>
#include "../common/warden.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the monitor exactly once (thread-safe). Safe to call from
 * InitWarden (remote thread / APC) or from the profiler Initialize
 * callback. ctx may be NULL when invoked via the profiler path, in which
 * case configuration is read from environment variables. */
void mon_start(const WARDEN_CTX *ctx);

/* Registration used by other monitor components */
void mon_register_patch_range(DWORD64 addr, DWORD cb);   /* hooks self-exclude */
BOOL mon_is_patch_range(DWORD64 addr, DWORD cb);
BOOL mon_is_self_region(DWORD64 addr, DWORD cb);
DWORD64 mon_self_base(void);
DWORD   mon_self_size(void);

/* Iterate hook patch ranges (used by the integrity engine's skip set) */
DWORD mon_patch_range_count(void);
BOOL  mon_patch_range_at(DWORD idx, DWORD64 *addr, DWORD *cb);

/* psapi helpers (avoid psapi.lib dependency) */
BOOL mon_module_info_from_addr(DWORD64 addr, DWORD64 *base, DWORD *size);

/* Emit clr_present style one-shot helper used by scanner */
BOOL mon_once(const char *key);

#ifdef __cplusplus
}
#endif
#endif /* WARDEN_MONITOR_H */
