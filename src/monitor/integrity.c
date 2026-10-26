/*
 * Warden - src/monitor/integrity.c
 *
 * Compares the live in-memory bytes of defence-relevant modules against
 * their clean on-disk copies:
 *
 *   amsi.dll  - AmsiScanBuffer / AmsiScanString prologues + full .text/.rdata
 *   ntdll.dll - EtwEventWrite / EtwEventWriteFull prologues + full .text
 *   clr.dll   - .rdata data section (catches CLR string patching used by
 *               in-memory loader stubs to break the AMSI integration)
 *
 * False-positive control:
 *   - ASLR relocations are parsed from the on-disk .reloc table and the
 *     relocated sites are excluded from the comparison.
 *   - Warden's own inline hooks (ntdll!LdrLoadDll etc.) are registered in
 *     the monitor's patch-range list and are excluded as well.
 *
 * Known bypass byte patterns are classified for the report:
 *   B8 57 00 07 80 ...   mov eax, 0x80070057 (E_INVALIDARG) - fail-open patch
 *   33 C0 C3             xor eax, eax ; ret                 - ETW blindfold
 *   C3                   ret (nullsub)
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "integrity.h"
#include "monitor.h"
#include "../common/warden.h"
#include "../common/util.h"
#include "../common/log.h"

typedef struct _RVA_RANGE { DWORD start; DWORD end; } RVA_RANGE;

#define MAX_SKIP 4096

typedef struct _SKIPSET {
    RVA_RANGE items[MAX_SKIP];
    DWORD     count;
} SKIPSET;

/* ------------------------------------------------------------------ */

static void skip_add(SKIPSET *s, DWORD start, DWORD end)
{
    DWORD i;
    if (s->count >= MAX_SKIP || end <= start) return;
    for (i = 0; i < s->count; i++) {
        if (start <= s->items[i].end && end >= s->items[i].start) {
            if (start < s->items[i].start) s->items[i].start = start;
            if (end > s->items[i].end)     s->items[i].end = end;
            return;
        }
    }
    s->items[s->count].start = start;
    s->items[s->count].end = end;
    s->count++;
}

static int skip_cmp(const void *a, const void *b)
{
    const RVA_RANGE *x = (const RVA_RANGE *)a, *y = (const RVA_RANGE *)b;
    return (int)x->start - (int)y->start;
}

/* Parse the disk image .reloc table; every relocation target may differ
 * in memory because of ASLR, so those bytes are excluded. */
static void skip_from_relocs(const unsigned char *file, DWORD cb, SKIPSET *s)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)file;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_DATA_DIRECTORY *rd;
    DWORD rva, size, off = 0;
    unsigned char *block;

    if (!wu_pe_validate(file, cb < 0x4000 ? cb : 0x4000)) return;
    nt = (IMAGE_NT_HEADERS64 *)(file + dos->e_lfanew);
    rd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    rva = rd->VirtualAddress;
    size = rd->Size;
    if (!rva || !size || rva >= cb) return;
    if (rva + size > cb) size = cb - rva;

    block = (unsigned char *)file + rva;
    while (off + sizeof(IMAGE_BASE_RELOCATION) <= size) {
        IMAGE_BASE_RELOCATION *bh = (IMAGE_BASE_RELOCATION *)(block + off);
        DWORD entries, i;
        WORD *entry;
        if (bh->SizeOfBlock == 0 ||
            off + bh->SizeOfBlock > size) break;
        entries = (bh->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        entry = (WORD *)((BYTE *)bh + sizeof(IMAGE_BASE_RELOCATION));
        for (i = 0; i < entries; i++) {
            WORD type = entry[i] >> 12;
            WORD pos  = entry[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            skip_add(s, bh->VirtualAddress + pos,
                     bh->VirtualAddress + pos + 8); /* cover up to 8 bytes */
        }
        off += bh->SizeOfBlock;
    }
}

/* Warden's own hook patches, translated to module-relative RVAs. */
static void skip_from_own_hooks(DWORD64 modBase, DWORD modSize, SKIPSET *s)
{
    DWORD n = mon_patch_range_count();
    DWORD i;
    for (i = 0; i < n; i++) {
        DWORD64 addr; DWORD cb;
        if (!mon_patch_range_at(i, &addr, &cb)) continue;
        if (addr >= modBase && addr + cb <= modBase + modSize)
            skip_add(s, (DWORD)(addr - modBase), (DWORD)(addr - modBase) + cb);
    }
}

static const char *classify_patch_bytes(const unsigned char *b, DWORD cb)
{
    if (cb >= 5 && !memcmp(b, "\xB8\x57\x00\x07\x80", 5))
        return "mov eax,0x80070057; ... (E_INVALIDARG fail-open patch)";
    if (cb >= 4 && !memcmp(b, "\x48\x31\xC0\xC3", 4))
        return "xor rax,rax; ret (telemetry blindfold)";
    if (cb >= 3 && !memcmp(b, "\x33\xC0\xC3", 3))
        return "xor eax,eax; ret (ETW blindfold)";
    if (cb >= 3 && !memcmp(b, "\x31\xC0\xC3", 3))
        return "xor eax,eax; ret (telemetry blindfold)";
    if (cb >= 1 && b[0] == 0xC3)
        return "ret (nullsub patch)";
    return NULL;
}

/* ------------------------------------------------------------------ */

typedef struct _TARGET_MOD {
    const wchar_t *name;
    const wchar_t *textSec;    /* full compare section */
    const wchar_t *dataSec;    /* secondary compare (may be NULL) */
    BOOL  compareText;
    const char *const *watchExports;   /* NULL terminated */
} TARGET_MOD;

static const char *g_amsiExports[]  = { "AmsiScanBuffer", "AmsiScanString", NULL };
static const char *g_ntdllExports[] = { "EtwEventWrite", "EtwEventWriteFull", NULL };

static const TARGET_MOD g_targets[] = {
    { L"amsi.dll",  L".text",  L".rdata", TRUE,  g_amsiExports  },
    { L"ntdll.dll", L".text",  NULL,      TRUE,  g_ntdllExports },
    { L"clr.dll",   NULL,      L".rdata", FALSE, NULL },
    { NULL, NULL, NULL, FALSE, NULL }
};

typedef struct _MOD_STATE {
    BOOL            cached;
    unsigned char  *disk;      /* on-disk image */
    DWORD           cbDisk;
} MOD_STATE;

static MOD_STATE g_state[3];

static BOOL section_by_name(const unsigned char *file, const wchar_t *name,
                            DWORD *rva, DWORD *vsize)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)file;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    WORD i, n;
    char nameA[9];

    if (!wu_pe_validate(file, 0x4000)) return FALSE;
    nt = (IMAGE_NT_HEADERS64 *)(file + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);
    n = nt->FileHeader.NumberOfSections;
    WideCharToMultiByte(CP_UTF8, 0, name, -1, nameA, 9, NULL, NULL);
    for (i = 0; i < n; i++) {
        if (!strncmp((const char *)sec[i].Name, nameA, 8)) {
            *rva = sec[i].VirtualAddress;
            *vsize = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                             : sec[i].SizeOfRawData;
            return TRUE;
        }
    }
    return FALSE;
}

/* compare one RVA range: memory@base+rva vs file@off(rva), honour skips */
static BOOL ranges_equal(DWORD64 memBase, const unsigned char *file,
                         DWORD fileCb, DWORD rvaStart, DWORD rvaEnd,
                         SKIPSET *skips, DWORD *firstDiffRva,
                         unsigned char *orig16, unsigned char *now16)
{
    DWORD pos = rvaStart;
    DWORD i;
    qsort(skips->items, skips->count, sizeof(RVA_RANGE), skip_cmp);

    for (i = 0; i <= skips->count; i++) {
        DWORD segEnd;
        if (i < skips->count && skips->items[i].end <= pos) continue;
        segEnd = (i < skips->count && skips->items[i].start < rvaEnd)
                 ? skips->items[i].start : rvaEnd;
        if (segEnd > rvaEnd) segEnd = rvaEnd;
        if (segEnd > pos) {
            /* compare [pos, segEnd) */
            DWORD off = wu_pe_rva_to_offset(file, pos);
            if (!off || off + (segEnd - pos) > fileCb) return TRUE; /* unreadable: pass */
            {
                DWORD len = segEnd - pos;
                const unsigned char *a = (const unsigned char *)
                                            (ULONG_PTR)(memBase + pos);
                const unsigned char *b = file + off;
                __try {
                    if (memcmp(a, b, len) != 0) {
                        DWORD k;
                        for (k = 0; k < len; k++) {
                            if (a[k] != b[k]) {
                                *firstDiffRva = pos + k;
                                memcpy(orig16, b + k, 16 < len - k ? 16 : len - k);
                                memcpy(now16, a + k, 16 < len - k ? 16 : len - k);
                                return FALSE;
                            }
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return TRUE; /* memory vanished - do not flag */
                }
            }
        }
        if (i < skips->count) {
            if (skips->items[i].start > rvaEnd) break;
            pos = skips->items[i].end > pos ? skips->items[i].end : pos;
        }
    }
    return TRUE;
}

static void check_target(DWORD idx, const WARDEN_MODLIST *mods,
                         const TARGET_MOD *t)
{
    const WARDEN_MODULE *m;
    MOD_STATE *st = &g_state[idx];
    SKIPSET skips;
    DWORD64 memBase;
    DWORD memSize;
    DWORD e;

    memset(&skips, 0, sizeof(skips));
    m = wu_modlist_find(mods, t->name);
    if (!m) return;

    memBase = (DWORD64)m->base;
    memSize = m->sizeOfImage;
    if (!memBase || !memSize) return;

    /* cache the on-disk copy */
    if (!st->cached) {
        if (!wu_read_file(m->path, &st->disk, &st->cbDisk)) {
            st->cached = TRUE;   /* don't retry forever */
            return;
        }
        st->cached = TRUE;
        skip_from_relocs(st->disk, st->cbDisk, &skips);
        skip_from_own_hooks(memBase, memSize, &skips);
    }

    /* 1) watched exports (function prologues) */
    for (e = 0; t->watchExports && t->watchExports[e]; e++) {
        const char *fn = t->watchExports[e];
        DWORD rvaDisk = 0;
        DWORD offDisk;
        unsigned char *memFn;
        unsigned char orig[16] = {0}, now[16] = {0};
        DWORD firstDiff = 0;
        DWORD64 addr;
        char key[80];
        char data[700];
        char hexOrig[40], hexNow[40];
        const char *sig;
        SKIPSET fnSkips;

        if (!wu_pe_find_export(st->disk, fn, &rvaDisk)) continue;
        offDisk = wu_pe_rva_to_offset(st->disk, rvaDisk);
        if (!offDisk || offDisk + 16 > st->cbDisk) continue;
        addr = memBase + rvaDisk;
        memFn = (unsigned char *)(ULONG_PTR)addr;

        memset(&fnSkips, 0, sizeof(fnSkips));
        skip_from_relocs(st->disk, st->cbDisk, &fnSkips);
        skip_from_own_hooks(memBase, memSize, &fnSkips);

        {
            BOOL equal;
            __try {
                equal = ranges_equal(memBase, st->disk, st->cbDisk,
                                     rvaDisk, rvaDisk + 16, &fnSkips,
                                     &firstDiff, orig, now);
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (equal) continue;

            wu_hex(orig, 16, hexOrig);
            wu_hex(now, 16, hexNow);
            sig = classify_patch_bytes(now, 16);

            _snprintf_s(key, sizeof(key), _TRUNCATE, "%ls!%s", t->name, fn);
            _snprintf_s(data, sizeof(data), _TRUNCATE,
                        "\"module\":\"%ls\",\"func\":\"%s\",\"rva\":\"0x%x\","
                        "\"origBytes\":\"%s\",\"nowBytes\":\"%s\","
                        "\"signature\":\"%s\"",
                        t->name, fn, rvaDisk, hexOrig, hexNow,
                        sig ? sig : "");
            wlog_event(wcsstr(t->name, L"ntdll") ? "etw_tamper"
                                                 : "amsi_tamper",
                       wcsstr(t->name, L"ntdll") ? SC_ETW_TAMPER
                                                 : SC_AMSI_TAMPER,
                       "crit", key, data,
                       "%ls!%s patched in memory (orig %s -> now %s)%s%s",
                       t->name, fn, hexOrig, hexNow,
                       sig ? " - signature: " : "", sig ? sig : "");

            if (sig) {
                char sigKey[96];
                _snprintf_s(sigKey, sizeof(sigKey), _TRUNCATE, "sig-%s", sig);
                if (mon_once(sigKey))
                    wlog_event("bypass_sig", SC_BYPASS_BONUS, "warn", sigKey,
                               data, "known defence-bypass signature: %s", sig);
            }
        }
    }

    /* 2) full section compares */
    if (t->compareText && t->textSec) {
        DWORD rva = 0, vsz = 0;
        if (section_by_name(st->disk, t->textSec, &rva, &vsz) && rva && vsz) {
            if (vsz > memSize - rva) vsz = memSize - rva;
            if (vsz && vsz < 0x02000000) {
                DWORD firstDiff = 0;
                unsigned char orig[16] = {0}, now[16] = {0};
                char key[80];
                char data[700];
                char hexOrig[40], hexNow[40];
                BOOL equal = ranges_equal(memBase, st->disk, st->cbDisk,
                                          rva, rva + vsz, &skips,
                                          &firstDiff, orig, now);
                _snprintf_s(key, sizeof(key), _TRUNCATE, "%ls!%ls", t->name,
                            t->textSec);
                if (!equal) {
                    wu_hex(orig, 16, hexOrig);
                    wu_hex(now, 16, hexNow);
                    _snprintf_s(data, sizeof(data), _TRUNCATE,
                                "\"module\":\"%ls\",\"section\":\"%ls\","
                                "\"rva\":\"0x%x\",\"origBytes\":\"%s\","
                                "\"nowBytes\":\"%s\"",
                                t->name, t->textSec, firstDiff,
                                hexOrig, hexNow);
                    wlog_event(wcsstr(t->name, L"ntdll") ? "etw_tamper"
                                                         : "amsi_tamper",
                               wcsstr(t->name, L"ntdll") ? SC_ETW_TAMPER
                                                         : SC_AMSI_TAMPER,
                               "crit", key, data,
                               "%ls %ls section differs from disk at RVA"
                               " 0x%x (orig %s -> now %s)",
                               t->name, t->textSec, firstDiff,
                               hexOrig, hexNow);
                }
            }
        }
    }
    if (t->dataSec) {
        DWORD rva = 0, vsz = 0;
        if (section_by_name(st->disk, t->dataSec, &rva, &vsz) && rva && vsz) {
            if (vsz > memSize - rva) vsz = memSize - rva;
            if (vsz && vsz < 0x02000000) {
                DWORD firstDiff = 0;
                unsigned char orig[16] = {0}, now[16] = {0};
                char key[80];
                char data[700];
                char hexOrig[40], hexNow[40];
                BOOL equal = ranges_equal(memBase, st->disk, st->cbDisk,
                                          rva, rva + vsz, &skips,
                                          &firstDiff, orig, now);
                _snprintf_s(key, sizeof(key), _TRUNCATE, "%ls!%ls", t->name,
                            t->dataSec);
                if (!equal) {
                    wu_hex(orig, 16, hexOrig);
                    wu_hex(now, 16, hexNow);
                    _snprintf_s(data, sizeof(data), _TRUNCATE,
                                "\"module\":\"%ls\",\"section\":\"%ls\","
                                "\"rva\":\"0x%x\",\"origBytes\":\"%s\","
                                "\"nowBytes\":\"%s\"",
                                t->name, t->dataSec, firstDiff,
                                hexOrig, hexNow);
                    wlog_event("clr_tamper",
                               SC_CLR_TAMPER, "crit", key, data,
                               "%ls %ls section differs from disk at RVA"
                               " 0x%x (patched strings?) orig %s -> now %s",
                               t->name, t->dataSec, firstDiff,
                               hexOrig, hexNow);
                }
            }
        }
    }
}

static void integrity_pass(void)
{
    WARDEN_MODLIST mods;
    DWORD i;

    if (!wu_module_snapshot(&mods)) return;
    for (i = 0; g_targets[i].name; i++)
        check_target(i, &mods, &g_targets[i]);

    /* one-shot clean confirmation per module (first clean pass) */
    for (i = 0; g_targets[i].name; i++) {
        const WARDEN_MODULE *m = wu_modlist_find(&mods, g_targets[i].name);
        char key[64];
        if (!m) continue;
        _snprintf_s(key, sizeof(key), _TRUNCATE, "ok-%ls", g_targets[i].name);
        if (mon_once(key) && g_state[i].cached)
            wlog_event("integrity_ok", SC_INFO, "ok", NULL, NULL,
                       "%ls matches its on-disk copy (no tamper found)",
                       g_targets[i].name);
    }
    wu_modlist_free(&mods);
}

void integrity_run(DWORD intervalMs)
{
    if (!intervalMs) intervalMs = 3000;
    for (;;) {
        integrity_pass();
        Sleep(intervalMs);
    }
}
