/*
 * Warden - src/common/util.c
 * Shared utilities implementation (x64 only).
 */
#include "util.h"
#include <stdio.h>
#include <math.h>
#include <intrin.h>

/* ================================================================== */
/* Memory helpers                                                      */
/* ================================================================== */

void warden_free(void *p)
{
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

static void *warden_alloc(size_t cb)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
}

/* ================================================================== */
/* String helpers                                                      */
/* ================================================================== */

DWORD wu_w2utf8(const wchar_t *ws, char **out)
{
    int need;
    char *buf;

    *out = NULL;
    if (!ws) return 0;
    need = WideCharToMultiByte(CP_UTF8, 0, ws, -1, NULL, 0, NULL, NULL);
    if (need <= 0) return 0;
    buf = (char *)warden_alloc((size_t)need);
    if (!buf) return 0;
    if (WideCharToMultiByte(CP_UTF8, 0, ws, -1, buf, need, NULL, NULL) <= 0) {
        warden_free(buf);
        return 0;
    }
    *out = buf;
    return (DWORD)need;
}

static int wu_lowerw(wchar_t c)
{
    if (c >= L'A' && c <= L'Z') return c + 32;
    return c;
}

int wu_wieq(const wchar_t *a, const wchar_t *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        if (wu_lowerw(*a) != wu_lowerw(*b)) return 0;
        a++; b++;
    }
    return (*a == 0 && *b == 0);
}

char *wu_json_escape(char *dst, size_t dstCap, const char *src)
{
    size_t o = 0;
    for (; src && *src; src++) {
        unsigned char c = (unsigned char)*src;
        if (o + 8 >= dstCap) break;
        switch (c) {
        case '"':  dst[o++] = '\\'; dst[o++] = '"'; break;
        case '\\': dst[o++] = '\\'; dst[o++] = '\\'; break;
        case '\n': dst[o++] = '\\'; dst[o++] = 'n'; break;
        case '\r': dst[o++] = '\\'; dst[o++] = 'r'; break;
        case '\t': dst[o++] = '\\'; dst[o++] = 't'; break;
        default:
            if (c < 0x20) {
                o += (size_t)_snprintf(dst + o, 7, "\\u%04x", c);
            } else {
                dst[o++] = (char)c;
            }
        }
    }
    dst[o] = 0;
    return dst;
}

void wu_time_str(char *buf, size_t cap)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snprintf(buf, cap - 1, "%02u:%02u:%02u.%03u",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    buf[cap - 1] = 0;
}

void wu_hex(const unsigned char *data, size_t cb, char *dst)
{
    static const char *hx = "0123456789abcdef";
    size_t i;
    for (i = 0; i < cb; i++) {
        dst[i * 2]     = hx[(data[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hx[data[i] & 0xF];
    }
    dst[cb * 2] = 0;
}

/* ================================================================== */
/* File IO                                                             */
/* ================================================================== */

BOOL wu_append_file(const wchar_t *path, const void *data, DWORD cb)
{
    HANDLE h;
    DWORD written;
    BOOL ok;

    if (!path || !data || !cb) return FALSE;
    h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(h, data, cb, &written, NULL) && written == cb;
    CloseHandle(h);
    return ok;
}

BOOL wu_read_file(const wchar_t *path, unsigned char **out, DWORD *cbOut)
{
    HANDLE h;
    LARGE_INTEGER sz;
    unsigned char *buf;
    DWORD cbRead = 0;

    *out = NULL;
    *cbOut = 0;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 ||
        sz.QuadPart > 0x20000000 /* 512 MB cap */) {
        CloseHandle(h);
        return FALSE;
    }
    buf = (unsigned char *)warden_alloc((size_t)sz.QuadPart);
    if (!buf) { CloseHandle(h); return FALSE; }
    if (!ReadFile(h, buf, (DWORD)sz.QuadPart, &cbRead, NULL) || cbRead == 0) {
        CloseHandle(h);
        warden_free(buf);
        return FALSE;
    }
    CloseHandle(h);
    *out = buf;
    *cbOut = cbRead;
    return TRUE;
}

BOOL wu_mkdirs(const wchar_t *path)
{
    wchar_t tmp[1024];
    wchar_t *p;
    size_t len;

    if (!path) return FALSE;
    len = wcslen(path);
    if (len == 0 || len >= 1020) return FALSE;
    wcscpy_s(tmp, 1024, path);

    for (p = tmp + 1; *p; p++) {
        if (*p == L'\\') {
            *p = 0;
            CreateDirectoryW(tmp, NULL); /* ignore already-exists errors */
            *p = L'\\';
        }
    }
    CreateDirectoryW(tmp, NULL);
    return TRUE;
}

/* ================================================================== */
/* Entropy                                                             */
/* ================================================================== */

double wu_entropy(const unsigned char *data, size_t len)
{
    unsigned int hist[256];
    double e = 0.0;
    size_t i;

    if (!data || len == 0) return 0.0;
    memset(hist, 0, sizeof(hist));
    for (i = 0; i < len; i++) hist[data[i]]++;
    for (i = 0; i < 256; i++) {
        if (hist[i]) {
            double p = (double)hist[i] / (double)len;
            e -= p * (p > 0.0 ? log(p) : 0.0);
        }
    }
    return e / log(2.0);   /* bits per byte, 0..8 */
}

/* ================================================================== */
/* Module snapshot via PEB (x64)                                       */
/* ================================================================== */

/* Minimal x64 loader structures (offsets stable across Win8.1..Win11).
 * UNICODE_STRING is re-declared locally to avoid winternl.h dependencies. */
typedef struct _MIN_UNI_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MIN_UNI_STR;

typedef struct _MIN_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;            /* +0x00 */
    LIST_ENTRY InMemoryOrderLinks;          /* +0x10 */
    LIST_ENTRY InInitializationOrderLinks;  /* +0x20 */
    PVOID DllBase;                          /* +0x30 */
    PVOID EntryPoint;                       /* +0x38 */
    ULONG SizeOfImage;                      /* +0x40 */
    ULONG _pad;
    MIN_UNI_STR FullDllName;                /* +0x48 */
    MIN_UNI_STR BaseDllName;                /* +0x58 */
} MIN_LDR_ENTRY;

BOOL wu_module_snapshot(WARDEN_MODLIST *list)
{
    DWORD64 peb = (DWORD64)__readgsqword(0x60);
    DWORD64 ldr = *(DWORD64 *)(peb + 0x18);          /* PEB->Ldr            */
    DWORD64 head = ldr + 0x10;                       /* InLoadOrderLinks    */
    DWORD64 cur = *(DWORD64 *)head;
    DWORD cap = 64;

    list->items = NULL;
    list->count = 0;
    list->items = (WARDEN_MODULE *)warden_alloc(cap * sizeof(WARDEN_MODULE));
    if (!list->items) return FALSE;

    while (cur && cur != head) {
        MIN_LDR_ENTRY *e = (MIN_LDR_ENTRY *)(cur - 0x00);
        DWORD64 base = (DWORD64)e->DllBase;

        __try {
            if (list->count >= cap) {
                WARDEN_MODULE *nb;
                cap *= 2;
                nb = (WARDEN_MODULE *)HeapReAlloc(GetProcessHeap(),
                        HEAP_ZERO_MEMORY, list->items, cap * sizeof(WARDEN_MODULE));
                if (!nb) break;
                list->items = nb;
            }
            list->items[list->count].base = (HMODULE)base;
            list->items[list->count].sizeOfImage = e->SizeOfImage;
            if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0 &&
                e->BaseDllName.Length < 60 * sizeof(wchar_t)) {
                memcpy(list->items[list->count].name, e->BaseDllName.Buffer,
                       e->BaseDllName.Length);
                list->items[list->count].name[e->BaseDllName.Length / sizeof(wchar_t)] = 0;
            }
            if (e->FullDllName.Buffer && e->FullDllName.Length > 0 &&
                e->FullDllName.Length < 500 * sizeof(wchar_t)) {
                memcpy(list->items[list->count].path, e->FullDllName.Buffer,
                       e->FullDllName.Length);
                list->items[list->count].path[e->FullDllName.Length / sizeof(wchar_t)] = 0;
            }
            list->count++;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        cur = *(DWORD64 *)cur; /* Flink of InLoadOrderLinks */
    }
    return list->count > 0;
}

void wu_modlist_free(WARDEN_MODLIST *list)
{
    if (list && list->items) {
        warden_free(list->items);
        list->items = NULL;
        list->count = 0;
    }
}

const WARDEN_MODULE *wu_modlist_find(const WARDEN_MODLIST *list,
                                     const wchar_t *name)
{
    DWORD i;
    if (!list || !name) return NULL;
    for (i = 0; i < list->count; i++)
        if (wu_wieq(list->items[i].name, name))
            return &list->items[i];
    return NULL;
}

const WARDEN_MODULE *wu_modlist_by_addr(const WARDEN_MODLIST *list, DWORD64 addr)
{
    DWORD i;
    if (!list) return NULL;
    for (i = 0; i < list->count; i++) {
        DWORD64 base = (DWORD64)list->items[i].base;
        if (addr >= base && addr < base + list->items[i].sizeOfImage)
            return &list->items[i];
    }
    return NULL;
}

/* ================================================================== */
/* PE helpers                                                          */
/* ================================================================== */

DWORD wu_pe_validate(const unsigned char *p, size_t avail)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;

    if (!p || avail < sizeof(IMAGE_NT_HEADERS64)) return 0;
    dos = (IMAGE_DOS_HEADER *)p;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000 ||
        (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > avail) return 0;
    nt = (IMAGE_NT_HEADERS64 *)(p + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return 0;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    if (nt->OptionalHeader.SizeOfImage == 0 ||
        nt->OptionalHeader.SizeOfImage > 0x10000000 /* 256 MB */) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

DWORD wu_pe_rva_to_offset(const unsigned char *p, DWORD rva)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    WORD i;

    if (!wu_pe_validate(p, 0x4000)) return 0;
    dos = (IMAGE_DOS_HEADER *)p;
    nt = (IMAGE_NT_HEADERS64 *)(p + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD va = sec[i].VirtualAddress;
        DWORD sz = sec[i].SizeOfRawData ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        if (rva >= va && rva < va + sz)
            return sec[i].PointerToRawData + (rva - va);
    }
    /* headers */
    if (rva < nt->OptionalHeader.SectionAlignment) return rva;
    return 0;
}

BOOL wu_pe_find_export(const unsigned char *p, const char *name, DWORD *rva)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    DWORD rvaExp, off;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD *names;
    DWORD i;

    if (!p || !name || !rva) return FALSE;
    *rva = 0;
    if (!wu_pe_validate(p, 0x4000)) return FALSE;
    dos = (IMAGE_DOS_HEADER *)p;
    nt = (IMAGE_NT_HEADERS64 *)(p + dos->e_lfanew);
    rvaExp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rvaExp) return FALSE;
    off = wu_pe_rva_to_offset(p, rvaExp);
    if (!off) return FALSE;
    exp = (IMAGE_EXPORT_DIRECTORY *)(p + off);

    off = wu_pe_rva_to_offset(p, exp->AddressOfNames);
    if (!off) return FALSE;
    names = (DWORD *)(p + off);

    for (i = 0; i < exp->NumberOfNames; i++) {
        DWORD no = wu_pe_rva_to_offset(p, names[i]);
        if (no && strcmp((const char *)(p + no), name) == 0) {
            DWORD fo = wu_pe_rva_to_offset(p, exp->AddressOfFunctions);
            DWORD *funcs;
            WORD o;
            if (!fo) return FALSE;
            funcs = (DWORD *)(p + fo);
            off = wu_pe_rva_to_offset(p, exp->AddressOfNameOrdinals);
            if (!off) return FALSE;
            o = *(WORD *)(p + off + i * sizeof(WORD));
            *rva = funcs[o];
            return TRUE;
        }
    }
    return FALSE;
}
