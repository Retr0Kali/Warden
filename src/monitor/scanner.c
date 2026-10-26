/*
 * Warden - src/monitor/scanner.c
 *
 * The scanner thread walks the virtual address space every interval and
 * looks for:
 *   1. MEM_PRIVATE + PAGE_EXECUTE* regions containing a valid PE header
 *      -> manually mapped / reflective images                  -> dumped
 *   2. MEM_IMAGE regions whose base is NOT in the PEB module list
 *      -> shadow / unlinked images                             -> dumped
 *   3. executable private regions with high entropy and no MZ
 *      -> raw shellcode / packed stages                        -> dumped
 *   4. CLR module presence (clr.dll / coreclr.dll / clrjit.dll)
 *
 * Dumps land in  <session>\dumps\  with a .meta.json sidecar and a
 * .strings.txt for quick triage.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "scanner.h"
#include "monitor.h"
#include "../common/warden.h"
#include "../common/util.h"
#include "../common/log.h"

#define MAX_DUMP_BYTES   (32u * 1024u * 1024u)
#define MAX_DUMP_FILES   96
#define SCAN_BUDGET_MB   4096u   /* stop walking after 4 GB per pass */

static DWORD g_dumpCount = 0;

/* safe in-process read (region may vanish between query and read) */
static BOOL safe_read(DWORD64 addr, void *buf, size_t cb)
{
    __try {
        memcpy(buf, (const void *)(ULONG_PTR)addr, cb);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static void dump_write(const unsigned char *data, DWORD cb, DWORD64 addr,
                       const char *kind, double entropy)
{
    wchar_t dir[700];
    wchar_t path[900];
    wchar_t sidePath[900];
    unsigned char dg[32];
    char hex[65];
    char *pathA = NULL;
    char meta[1200];
    DWORD i, run = 0, lines = 0;
    FILE *mf, *sf;
    HANDLE h;
    DWORD written;
    const wchar_t *tag = L"raw";

    if (g_dumpCount >= MAX_DUMP_FILES || !cb || !data) return;
    g_dumpCount++;

    if      (!strcmp(kind, "pe"))     tag = L"pe";
    else if (!strcmp(kind, "hidden")) tag = L"hidden";

    wu_sha256(data, cb, dg);
    wu_hex(dg, 32, hex);

    _snwprintf_s(dir, 700, _TRUNCATE, L"%ls\\%ls", wlog_dir(),
                 WARDEN_DUMP_SUBDIR);
    _snwprintf_s(path, 900, _TRUNCATE, L"%ls\\dump_%02u_%llx_%ls.bin",
                 dir, g_dumpCount, (unsigned long long)addr, tag);

    h = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, data, cb, &written, NULL);
    CloseHandle(h);

    /* meta sidecar */
    wu_w2utf8(path, &pathA);
    _snprintf_s(meta, sizeof(meta), _TRUNCATE,
        "{\n  \"file\": \"%s\",\n  \"kind\": \"%s\",\n"
        "  \"baseAddress\": \"0x%llx\",\n  \"size\": %lu,\n"
        "  \"sha256\": \"%s\",\n  \"entropy\": %.3f\n}\n",
        pathA ? pathA : "", kind, (unsigned long long)addr, cb, hex, entropy);
    _snwprintf_s(sidePath, 900, _TRUNCATE, L"%ls.meta.json", path);
    mf = _wfopen(sidePath, L"wb");
    if (mf) { fwrite(meta, 1, strlen(meta), mf); fclose(mf); }

    /* quick strings extraction (ASCII >= 6, capped at 120 lines) */
    _snwprintf_s(sidePath, 900, _TRUNCATE, L"%ls.strings.txt", path);
    sf = _wfopen(sidePath, L"wb");
    if (sf) {
        char line[256];
        for (i = 0; i < cb && lines < 120; i++) {
            unsigned char c = data[i];
            if (c >= 0x20 && c < 0x7F) {
                if (run < 255) line[run++] = (char)c;
            } else {
                if (run >= 6) {
                    line[run] = 0;
                    fwrite(line, 1, run, sf);
                    fwrite("\n", 1, 1, sf);
                    lines++;
                }
                run = 0;
            }
        }
        fclose(sf);
    }

    {
        char data2[512];
        _snprintf_s(data2, sizeof(data2), _TRUNCATE,
                    "\"file\":\"%s\",\"sha256\":\"%s\",\"entropy\":%.3f,"
                    "\"size\":%lu",
                    pathA ? pathA : "", hex, entropy, cb);
        wlog_event("dump_saved", SC_INFO, "ok", hex, data2,
                   "dump saved: %ls (sha256 %s, entropy %.2f)",
                   path, hex, entropy);
    }
    warden_free(pathA);
}

/* does the region look like a valid PE image? returns size of image */
static DWORD pe_header_probe(DWORD64 addr, DWORD regionSize)
{
    unsigned char hdr[0x400];
    DWORD read = regionSize < sizeof(hdr) ? regionSize : sizeof(hdr);
    if (read < 0x100) return 0;
    if (!safe_read(addr, hdr, read)) return 0;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return 0;
    return wu_pe_validate(hdr, read);
}

/* CLR module presence check */
static void check_clr_presence(const WARDEN_MODLIST *mods)
{
    static const wchar_t *clrMods[] = {
        L"clr.dll", L"coreclr.dll", L"clrjit.dll", L"mscoree.dll", NULL
    };
    int i;
    for (i = 0; clrMods[i]; i++) {
        const WARDEN_MODULE *m = wu_modlist_find(mods, clrMods[i]);
        if (m) {
            char key[64];
            char data[600];
            char *pathA = NULL;
            _snprintf_s(key, sizeof(key), _TRUNCATE, "clr-%ls", clrMods[i]);
            if (!mon_once(key)) continue;
            wu_w2utf8(m->path, &pathA);
            _snprintf_s(data, sizeof(data), _TRUNCATE,
                        "\"module\":\"%ls\",\"path\":\"%s\"",
                        clrMods[i], pathA ? pathA : "");
            wlog_event("clr_present", SC_INFO, "info", NULL, data,
                       "CLR detected: %ls loaded from %ls",
                       clrMods[i], m->path);
            warden_free(pathA);
        }
    }
}

static BOOL is_exec_protect(DWORD protect)
{
    switch (protect & 0xFF) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    }
    return FALSE;
}

static void scan_pass(void)
{
    WARDEN_MODLIST mods;
    DWORD64 addr = 0;
    DWORD64 walked = 0;
    MEMORY_BASIC_INFORMATION mbi;

    if (!wu_module_snapshot(&mods)) return;

    check_clr_presence(&mods);

    while (VirtualQuery((LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi))) {
        DWORD64 base = (DWORD64)mbi.BaseAddress;
        DWORD size = (DWORD)mbi.RegionSize;

        walked += size;
        if (walked > (DWORD64)SCAN_BUDGET_MB * 1024 * 1024) break;

        if (mbi.State != MEM_COMMIT) {
            addr = base + size;
            continue;
        }

        if (mbi.Type == MEM_PRIVATE && is_exec_protect(mbi.Protect)) {
            if (!mon_is_self_region(base, size) &&
                !mon_is_patch_range(base, size)) {
                DWORD imgSize = pe_header_probe(base, size);
                if (imgSize) {
                    char key[40];
                    char data[300];
                    _snprintf_s(key, sizeof(key), _TRUNCATE, "mz-%llx",
                                (unsigned long long)base);
                    if (mon_once(key)) {
                        _snprintf_s(data, sizeof(data), _TRUNCATE,
                                    "\"baseAddress\":\"0x%llx\",\"size\":%lu,"
                                    "\"imageSize\":%lu,\"kind\":\"private-mz\"",
                                    (unsigned long long)base, size, imgSize);
                        wlog_event("exec_region", SC_EXEC_MZ, "crit", key,
                                   data,
                                   "private executable region at 0x%llx"
                                   " contains a PE image (manual map /"
                                   " reflective load)",
                                   (unsigned long long)base);
                        if (wlog_flags() & WF_DUMP) {
                            DWORD dumpSz = imgSize < size ? imgSize : size;
                            unsigned char *buf;
                            if (dumpSz > 0 && dumpSz <= MAX_DUMP_BYTES &&
                                (buf = (unsigned char *)HeapAlloc(
                                    GetProcessHeap(), 0, dumpSz)) != NULL) {
                                if (safe_read(base, buf, dumpSz))
                                    dump_write(buf, dumpSz, base, "pe",
                                        wu_entropy(buf, dumpSz));
                                HeapFree(GetProcessHeap(), 0, buf);
                            }
                        }
                    }
                } else if (size >= 0x1000) {
                    unsigned char buf[0x10000];
                    DWORD probe = size < sizeof(buf) ? size : sizeof(buf);
                    if (safe_read(base, buf, probe)) {
                        double e = wu_entropy(buf, probe);
                        if (e > 6.8) {
                            char key[40];
                            char data[300];
                            _snprintf_s(key, sizeof(key), _TRUNCATE,
                                        "sc-%llx", (unsigned long long)base);
                            if (mon_once(key)) {
                                _snprintf_s(data, sizeof(data), _TRUNCATE,
                                            "\"baseAddress\":\"0x%llx\","
                                            "\"size\":%lu,\"entropy\":%.2f",
                                            (unsigned long long)base, size, e);
                                wlog_event("shellcode_region", SC_SHELLCODE,
                                           "warn", key, data,
                                           "executable private region at"
                                           " 0x%llx (size %lu, entropy %.2f)"
                                           " - no PE header, likely raw"
                                           " shellcode or a packed stage",
                                           (unsigned long long)base, size, e);
                                if (wlog_flags() & WF_DUMP)
                                    dump_write(buf, probe, base, "raw", e);
                            }
                        }
                    }
                }
            }
        } else if (mbi.Type == MEM_IMAGE && is_exec_protect(mbi.Protect)) {
            if (!wu_modlist_by_addr(&mods, base) &&
                !mon_is_self_region(base, size)) {
                char key[40];
                char data[300];
                _snprintf_s(key, sizeof(key), _TRUNCATE, "hd-%llx",
                             (unsigned long long)base);
                if (mon_once(key)) {
                    _snprintf_s(data, sizeof(data), _TRUNCATE,
                                "\"baseAddress\":\"0x%llx\",\"size\":%lu",
                                (unsigned long long)base, size);
                    wlog_event("hidden_image", SC_HIDDEN_IMAGE, "crit", key,
                               data,
                               "image mapping at 0x%llx is NOT in the PEB"
                               " module list (unlinked / shadow DLL)",
                               (unsigned long long)base);
                    if (wlog_flags() & WF_DUMP) {
                        DWORD dumpSz = size < MAX_DUMP_BYTES ? size
                                                             : MAX_DUMP_BYTES;
                        unsigned char *buf;
                        if ((buf = (unsigned char *)HeapAlloc(
                                GetProcessHeap(), 0, dumpSz)) != NULL) {
                            if (safe_read(base, buf, dumpSz))
                                dump_write(buf, dumpSz, base, "hidden",
                                    wu_entropy(buf, dumpSz));
                            HeapFree(GetProcessHeap(), 0, buf);
                        }
                    }
                }
            }
        }

        addr = base + size;
        if (!addr) break; /* wrapped */
    }

    wu_modlist_free(&mods);
}

void scanner_run(DWORD intervalMs)
{
    if (!intervalMs) intervalMs = 1500;
    for (;;) {
        scan_pass();
        Sleep(intervalMs);
    }
}
