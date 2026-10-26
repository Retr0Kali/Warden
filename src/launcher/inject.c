/*
 * Warden - src/launcher/inject.c
 * Three injection modes for placing the monitor DLL into the suspended
 * target before its main thread runs.
 *
 *  classic : VirtualAllocEx + CreateRemoteThread(LoadLibraryW)
 *  apc     : QueueUserAPC(LoadLibraryW) + QueueUserAPC(InitWarden)
 *            on the still-suspended initial thread (fires before main)
 *  manual  : out-of-process PE mapper with relocation, import resolution
 *            via a remote PEB walk, then a thread started at DllMain
 */
#include "inject.h"
#include <stdio.h>
#include <string.h>
#include "../common/util.h"

/* --- dynamic ntdll bits -------------------------------------------- */
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_RtlCreateUserThread)(
    HANDLE, PVOID, BOOLEAN, BOOLEAN, ULONG_PTR, ULONG_PTR,
    PVOID, PVOID, HANDLE *, PVOID *);   /* not used; reserved */

typedef struct _MIN_PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;        /* NtCurrentPeb placeholder */
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} MIN_PROCESS_BASIC_INFORMATION;

/* x64 LDR_DATA_TABLE_ENTRY field offsets (PEB->Ldr->InLoadOrderLinks) */
#define OFF_LDR_IN_LOAD_ORDER   0x10
#define OFF_LDR_ENTRY_DLLBASE   0x30
#define OFF_LDR_ENTRY_SIZE      0x40
#define OFF_LDR_ENTRY_BASENAME  0x58   /* UNICODE_STRING */
#define LDR_LIST_DELTA          0x00   /* entry starts at InLoadOrderLinks */

typedef struct _MIN_UNICODE_STRING_U {
    USHORT Length;
    USHORT MaximumLength;
    PVOID  Buffer;   /* in remote process space */
} MIN_UNICODE_STRING_U;

/* ------------------------------------------------------------------ */
/* forward decls                                                       */
/* ------------------------------------------------------------------ */
static void    inj_set_dll_path(const wchar_t *path);
static void    inj_get_dll_path(wchar_t *out, DWORD cch);
static BOOL    inj_find_export_rva_file(const wchar_t *path,
                                        const char *name, DWORD *rva);
static DWORD64 inj_remote_image_base(void);
static BOOL    inj_load_library_remote(HANDLE hProc, const wchar_t *dllPath,
                                       DWORD64 *hModOut);

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void *inj_remote_write(HANDLE hProc, const void *data, SIZE_T cb,
                              DWORD protect)
{
    void *remote = VirtualAllocEx(hProc, NULL, cb,
                                  MEM_COMMIT | MEM_RESERVE, protect);
    SIZE_T written;
    if (!remote) return NULL;
    if (!WriteProcessMemory(hProc, remote, data, cb, &written) ||
        written != cb) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return NULL;
    }
    return remote;
}

static BOOL inj_remote_call(HANDLE hProc, void *fn, void *arg, DWORD *exitCode)
{
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                        (LPTHREAD_START_ROUTINE)fn, arg, 0, NULL);
    DWORD code = 0;
    if (!hThread) return FALSE;
    WaitForSingleObject(hThread, 15000);
    if (exitCode) {
        GetExitCodeThread(hThread, &code);
        *exitCode = code;
    }
    CloseHandle(hThread);
    return TRUE;
}

/* Read remote memory into heap buffer. */
static BOOL inj_remote_read(HANDLE hProc, DWORD64 addr, void *buf, SIZE_T cb)
{
    SIZE_T got = 0;
    return ReadProcessMemory(hProc, (LPCVOID)addr, buf, cb, &got) && got == cb;
}

/* Case-insensitive wide compare for remote strings */
static int inj_wieqn(const wchar_t *a, const wchar_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n && a[i] && b[i]; i++) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return (a[i] == 0 && b[i] == 0) || i == n;
}

/* ------------------------------------------------------------------ */
/* Remote module lookup via PEB walk                                   */
/* ------------------------------------------------------------------ */

static DWORD64 inj_remote_find_module(HANDLE hProc, DWORD64 pebAddr,
                                      const wchar_t *baseName)
{
    DWORD64 ldr, head, cur;
    DWORD64 modBase = 0;
    wchar_t nameBuf[96];

    if (!inj_remote_read(hProc, pebAddr + 0x18, &ldr, sizeof(ldr)))
        return 0;
    if (!ldr) return 0;
    head = ldr + OFF_LDR_IN_LOAD_ORDER;
    if (!inj_remote_read(hProc, head, &cur, sizeof(cur)))
        return 0;

    while (cur && cur != head) {
        DWORD64 entry = cur - LDR_LIST_DELTA;
        DWORD64 base;
        DWORD   size;
        MIN_UNICODE_STRING_U us;

        if (!inj_remote_read(hProc, entry + OFF_LDR_ENTRY_DLLBASE, &base, sizeof(base)))
            break;
        if (!inj_remote_read(hProc, entry + OFF_LDR_ENTRY_SIZE, &size, sizeof(size)))
            break;
        if (!inj_remote_read(hProc, entry + OFF_LDR_ENTRY_BASENAME, &us, sizeof(us)))
            break;
        if (us.Buffer && us.Length >= sizeof(wchar_t) &&
            us.Length <= sizeof(nameBuf) - 2) {
            memset(nameBuf, 0, sizeof(nameBuf));
            if (inj_remote_read(hProc, (DWORD64)us.Buffer, nameBuf, us.Length)) {
                if (inj_wieqn(nameBuf, baseName, 96)) {
                    modBase = base;
                    break;
                }
            }
        }
        if (!inj_remote_read(hProc, cur, &cur, sizeof(cur)))
            break;
    }
    return modBase;
}

/* Resolve a remote module export by name (reads the remote PE). */
static DWORD64 inj_remote_export(HANDLE hProc, DWORD64 modBase, const char *name)
{
    unsigned char hdr[0x1000];
    DWORD e_lfanew, rvaExp, rvaNames, rvaFuncs, rvaOrds;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_EXPORT_DIRECTORY exp;
    DWORD i, funcRva = 0;
    DWORD64 result = 0;
    char nameBuf[128];
    size_t nameLen = strlen(name);

    if (!inj_remote_read(hProc, modBase, hdr, sizeof(hdr)))
        return 0;
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hdr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        e_lfanew = (DWORD)dos->e_lfanew;
    }
    if (e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) return 0;
    nt = (IMAGE_NT_HEADERS64 *)(hdr + e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    rvaExp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rvaExp) return 0;

    /* export dir is usually in .rdata, within first pages; read via hdr if
     * inside headers, else read separately */
    if (rvaExp < sizeof(hdr) - sizeof(IMAGE_EXPORT_DIRECTORY)) {
        memcpy(&exp, hdr + rvaExp, sizeof(exp));
    } else {
        if (!inj_remote_read(hProc, modBase + rvaExp, &exp, sizeof(exp)))
            return 0;
    }

    rvaNames = exp.AddressOfNames;
    rvaFuncs = exp.AddressOfFunctions;
    rvaOrds  = exp.AddressOfNameOrdinals;

    for (i = 0; i < exp.NumberOfNames; i++) {
        DWORD nameRva, ord;
        if (!inj_remote_read(hProc, modBase + rvaNames + i * sizeof(DWORD),
                             &nameRva, sizeof(nameRva)))
            break;
        memset(nameBuf, 0, sizeof(nameBuf));
        if (nameLen < sizeof(nameBuf))
            inj_remote_read(hProc, modBase + nameRva, nameBuf, (SIZE_T)nameLen);
        if (strncmp(nameBuf, name, nameLen) == 0 && nameBuf[nameLen] == 0) {
            if (!inj_remote_read(hProc, modBase + rvaOrds + i * sizeof(WORD),
                                 &ord, sizeof(ord)))
                break;
            if (!inj_remote_read(hProc, modBase + rvaFuncs + (DWORD)ord * sizeof(DWORD),
                                 &funcRva, sizeof(funcRva)))
                break;
            result = modBase + funcRva;
            break;
        }
    }
    return result;
}

/* ------------------------------------------------------------------ */
/* classic + apc                                                       */
/* ------------------------------------------------------------------ */

static BOOL inj_load_library_remote(HANDLE hProc, const wchar_t *dllPath,
                                    DWORD64 *hModOut)
{
    void *remotePath;
    HMODULE hKernel;
    void *pLoadLibraryW;
    DWORD exitCode = 0;

    hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) return FALSE;
    pLoadLibraryW = (void *)GetProcAddress(hKernel, "LoadLibraryW");
    if (!pLoadLibraryW) return FALSE;

    remotePath = inj_remote_write(hProc, dllPath,
                    (wcslen(dllPath) + 1) * sizeof(wchar_t), PAGE_READWRITE);
    if (!remotePath) return FALSE;

    if (!inj_remote_call(hProc, pLoadLibraryW, remotePath, &exitCode)) {
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        return FALSE;
    }
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);

    if (exitCode == 0) return FALSE;   /* LoadLibraryW returned NULL */
    if (hModOut) *hModOut = (DWORD64)exitCode;
    return TRUE;
}

static BOOL inj_call_initwarden_remote(HANDLE hProc, DWORD64 dllBase,
                                       const WARDEN_CTX *ctx)
{
    void *remoteCtx;
    void *pInit;
    unsigned char hdr[0x1000];
    DWORD e_lfanew, rvaInit = 0;
    IMAGE_NT_HEADERS64 *nt;
    wchar_t dllOnDisk[MAX_PATH];

    /* Resolve the InitWarden export RVA by parsing the DLL file on disk. */
    inj_get_dll_path(dllOnDisk, MAX_PATH);
    if (!inj_find_export_rva_file(dllOnDisk, WARDEN_INIT_EXPORT, &rvaInit))
        return FALSE;

    if (!dllBase) return FALSE;
    /* sanity: read headers back from remote */
    if (!inj_remote_read(hProc, dllBase, hdr, sizeof(hdr))) return FALSE;
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hdr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
        e_lfanew = (DWORD)dos->e_lfanew;
        nt = (IMAGE_NT_HEADERS64 *)(hdr + e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    }

    remoteCtx = inj_remote_write(hProc, ctx, sizeof(*ctx), PAGE_READWRITE);
    if (!remoteCtx) return FALSE;

    pInit = (void *)(dllBase + rvaInit);
    {
        BOOL ok = inj_remote_call(hProc, pInit, remoteCtx, NULL);
        VirtualFreeEx(hProc, remoteCtx, 0, MEM_RELEASE);
        return ok;
    }
}

/* ------------------------------------------------------------------ */
/* manual map                                                          */
/* ------------------------------------------------------------------ */

typedef struct _RELOC_BLOCK {
    DWORD pageRva;
    DWORD blockSize;
} RELOC_BLOCK_HDR;

static BOOL inj_apply_relocs(unsigned char *img, SIZE_T imgSize,
                             DWORD64 oldBase, DWORD64 newBase)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_DATA_DIRECTORY *relocDir;
    DWORD rva, size, off = 0;
    unsigned char *block;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS64 *)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    rva = relocDir->VirtualAddress;
    size = relocDir->Size;
    if (!rva || !size) return TRUE; /* nothing to relocate */
    if (rva >= imgSize) return FALSE;

    block = img + rva;
    while (off + sizeof(RELOC_BLOCK_HDR) <= size) {
        RELOC_BLOCK_HDR *bh = (RELOC_BLOCK_HDR *)(block + off);
        DWORD entries, i;
        WORD *entry;
        if (bh->blockSize == 0) break;
        entries = (bh->blockSize - sizeof(RELOC_BLOCK_HDR)) / sizeof(WORD);
        entry = (WORD *)((BYTE *)bh + sizeof(RELOC_BLOCK_HDR));
        for (i = 0; i < entries; i++) {
            WORD type = entry[i] >> 12;
            WORD pos  = entry[i] & 0x0FFF;
            DWORD64 *patch;
            if (type == IMAGE_REL_BASED_DIR64) {
                DWORD tgt = bh->pageRva + pos;
                if (tgt + sizeof(DWORD64) <= imgSize) {
                    patch = (DWORD64 *)(img + tgt);
                    *patch = (*patch - oldBase) + newBase;
                }
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD tgt = bh->pageRva + pos;
                if (tgt + sizeof(DWORD) <= imgSize) {
                    DWORD *p32 = (DWORD *)(img + tgt);
                    *p32 = (DWORD)((*p32 - (DWORD)oldBase) + (DWORD)newBase);
                }
            } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                /* padding */
            }
        }
        off += bh->blockSize;
    }
    return TRUE;
}

/* Resolve imports for the local image copy against remote modules. */
static BOOL inj_resolve_imports(HANDLE hProc, unsigned char *img,
                                SIZE_T imgSize, DWORD64 pebAddr)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_DATA_DIRECTORY *impDir;
    DWORD rva;
    unsigned char *descCursor;
    DWORD descOff = 0;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS64 *)(img + dos->e_lfanew);
    impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    rva = impDir->VirtualAddress;
    if (!rva || !impDir->Size) return TRUE;  /* no imports */

    descCursor = img + rva;
    for (;;) {
        IMAGE_IMPORT_DESCRIPTOR *desc =
            (IMAGE_IMPORT_DESCRIPTOR *)(descCursor + descOff);
        DWORD64 modBase;
        wchar_t dllName[96];
        char *nameA;
        IMAGE_THUNK_DATA64 *oft, *ft;
        DWORD i;

        if ((BYTE *)desc + sizeof(*desc) > img + imgSize) break;
        if (!desc->Name) break;

        nameA = (char *)(img + wu_pe_rva_to_offset(img, desc->Name));
        {
            size_t n = strlen(nameA);
            size_t j;
            if (n >= 90) return FALSE;
            for (j = 0; j <= n; j++) dllName[j] = (wchar_t)nameA[j];
        }

        modBase = inj_remote_find_module(hProc, pebAddr, dllName);
        if (!modBase) {
            /* load it into the target first (classic helper) */
            if (!inj_load_library_remote(hProc, dllName, &modBase))
                return FALSE;
            modBase = inj_remote_find_module(hProc, pebAddr, dllName);
            if (!modBase) return FALSE;
        }

        oft = (IMAGE_THUNK_DATA64 *)(img +
              wu_pe_rva_to_offset(img, desc->OriginalFirstThunk));
        ft  = (IMAGE_THUNK_DATA64 *)(img +
              wu_pe_rva_to_offset(img, desc->FirstThunk));
        if (!oft || !ft) { descOff += sizeof(*desc); continue; }

        for (i = 0; ft[i].u1.Function != 0; i++) {
            DWORD64 fnAddr = 0;
            if (oft[i].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                /* import by ordinal */
                WORD ord = (WORD)(oft[i].u1.Ordinal & 0xFFFF);
                DWORD expRva;
                DWORD64 expAddr;
                IMAGE_EXPORT_DIRECTORY expR;
                unsigned char hdr[0x1000];
                if (!inj_remote_read(hProc, modBase, hdr, sizeof(hdr))) return FALSE;
                {
                    IMAGE_DOS_HEADER *d2 = (IMAGE_DOS_HEADER *)hdr;
                    IMAGE_NT_HEADERS64 *n2;
                    if (d2->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
                    n2 = (IMAGE_NT_HEADERS64 *)(hdr + (DWORD)d2->e_lfanew);
                    expRva = n2->OptionalHeader.
                        DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                }
                if (!expRva) return FALSE;
                expAddr = modBase + expRva;
                if (!inj_remote_read(hProc, expAddr, &expR, sizeof(expR)))
                    return FALSE;
                if (ord >= expR.NumberOfFunctions) return FALSE;
                {
                    DWORD fnRva = 0;
                    if (!inj_remote_read(hProc,
                            modBase + expR.AddressOfFunctions + ord * sizeof(DWORD),
                            &fnRva, sizeof(fnRva)))
                        return FALSE;
                    fnAddr = modBase + fnRva;
                }
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(img + wu_pe_rva_to_offset(
                        img, (DWORD)oft[i].u1.AddressOfData));
                fnAddr = inj_remote_export(hProc, modBase, ibn->Name);
            }
            if (!fnAddr) return FALSE;
            ft[i].u1.Function = fnAddr;
        }

        /* write resolved FirstThunk array back into the remote image */
        {
            DWORD64 remoteFt = inj_remote_image_base() + desc->FirstThunk;
            if (!remoteFt ||
                !WriteProcessMemory(hProc, (LPVOID)remoteFt, ft,
                    i * sizeof(IMAGE_THUNK_DATA64), NULL))
                return FALSE;
        }
        descOff += sizeof(*desc);
    }
    return TRUE;
}

static DWORD64 g_manualBase = 0;      /* remote base of the manual-mapped DLL */
DWORD64 inj_remote_image_base(void) { return g_manualBase; }

static BOOL inj_manual_map(HANDLE hProc, const wchar_t *dllPath,
                           const WARDEN_CTX *ctx)
{
    unsigned char *file = NULL;
    DWORD cb = 0, imgSize = 0;
    unsigned char *img = NULL;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    WORD i;
    DWORD64 pebAddr = 0, newBase = 0;
    MIN_PROCESS_BASIC_INFORMATION pbi;
    PFN_NtQueryInformationProcess pNtQIP;
    HMODULE hNtdll;
    DWORD entryRva;
    void *pEntry;
    unsigned char hdr[0x1000];

    if (!wu_read_file(dllPath, &file, &cb)) return FALSE;
    dos = (IMAGE_DOS_HEADER *)file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { warden_free(file); return FALSE; }
    nt = (IMAGE_NT_HEADERS64 *)(file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        warden_free(file);
        return FALSE;
    }
    imgSize = nt->OptionalHeader.SizeOfImage;

    /* local copy of the image */
    img = (unsigned char *)VirtualAlloc(NULL, imgSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!img) { warden_free(file); return FALSE; }
    memcpy(img, file, min(cb, nt->OptionalHeader.SizeOfHeaders));
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD raw = sec[i].PointerToRawData;
        DWORD rawSz = sec[i].SizeOfRawData;
        DWORD va = sec[i].VirtualAddress;
        if (raw && rawSz && (SIZE_T)(raw + rawSz) <= cb &&
            (SIZE_T)(va + rawSz) <= imgSize)
            memcpy(img + va, file + raw, rawSz);
    }
    warden_free(file);

    /* remote base */
    newBase = (DWORD64)VirtualAllocEx(hProc, NULL, imgSize,
               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) { VirtualFree(img, 0, MEM_RELEASE); return FALSE; }
    g_manualBase = newBase;

    /* relocations */
    if (!inj_apply_relocs(img, imgSize,
            nt->OptionalHeader.ImageBase, newBase)) {
        VirtualFree(img, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, (LPVOID)newBase, 0, MEM_RELEASE);
        return FALSE;
    }

    /* resolve imports against remote modules */
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) { VirtualFree(img, 0, MEM_RELEASE); return FALSE; }
    pNtQIP = (PFN_NtQueryInformationProcess)
            GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pNtQIP) { VirtualFree(img, 0, MEM_RELEASE); return FALSE; }
    memset(&pbi, 0, sizeof(pbi));
    if (pNtQIP(hProc, 0 /*ProcessBasicInformation*/, &pbi,
               sizeof(pbi), NULL) != 0 || !pbi.PebBaseAddress) {
        VirtualFree(img, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, (LPVOID)newBase, 0, MEM_RELEASE);
        return FALSE;
    }
    pebAddr = (DWORD64)pbi.PebBaseAddress;

    if (!inj_resolve_imports(hProc, img, imgSize, pebAddr)) {
        VirtualFree(img, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, (LPVOID)newBase, 0, MEM_RELEASE);
        return FALSE;
    }

    /* copy the finished image */
    if (!WriteProcessMemory(hProc, (LPVOID)newBase, img, imgSize, NULL)) {
        VirtualFree(img, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, (LPVOID)newBase, 0, MEM_RELEASE);
        return FALSE;
    }
    VirtualFree(img, 0, MEM_RELEASE);

    /* verify remote headers, locate entry */
    if (!inj_remote_read(hProc, newBase, hdr, sizeof(hdr))) return FALSE;
    {
        IMAGE_DOS_HEADER *rd = (IMAGE_DOS_HEADER *)hdr;
        if (rd->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
        nt = (IMAGE_NT_HEADERS64 *)(hdr + (DWORD)rd->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
        entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    }
    if (!entryRva) return FALSE;

    /* DllMain(hmod, DLL_PROCESS_ATTACH, NULL) via a remote thread */
    pEntry = (void *)(newBase + entryRva);
    if (!inj_remote_call(hProc, pEntry, (void *)(ULONG_PTR)1, NULL))
        return FALSE;

    /* call InitWarden(ctx) */
    return inj_call_initwarden_remote(hProc, newBase, ctx);
}

/* ------------------------------------------------------------------ */
/* export RVA lookup from a DLL file on disk (used for InitWarden)     */
/* ------------------------------------------------------------------ */

static wchar_t g_dllPath[MAX_PATH] = {0};

static void inj_set_dll_path(const wchar_t *path)
{
    wcsncpy_s(g_dllPath, MAX_PATH, path ? path : L"", _TRUNCATE);
}

static void inj_get_dll_path(wchar_t *out, DWORD cch)
{
    wchar_t self[MAX_PATH];
    if (g_dllPath[0]) {
        wcsncpy_s(out, cch, g_dllPath, _TRUNCATE);
        return;
    }
    /* fallback: the launcher binary directory + Warden.dll */
    GetModuleFileNameW(NULL, self, MAX_PATH);
    {
        wchar_t *slash = wcsrchr(self, L'\\');
        if (slash) *(slash + 1) = 0;
        _snwprintf_s(out, cch, _TRUNCATE, L"%sWarden.dll", self);
    }
}

static BOOL inj_find_export_rva_file(const wchar_t *path, const char *name, DWORD *rva)
{
    unsigned char *file = NULL;
    DWORD cb = 0;
    BOOL ok;

    if (!wu_read_file(path, &file, &cb)) return FALSE;
    ok = wu_pe_find_export(file, name, rva);
    warden_free(file);
    return ok;
}

/* ------------------------------------------------------------------ */
/* public entry                                                        */
/* ------------------------------------------------------------------ */

BOOL inj_inject(INJECT_MODE mode, HANDLE hProc, HANDLE hThread,
                const wchar_t *dllPath, const WARDEN_CTX *ctx,
                DWORD64 *readyHMod)
{
    DWORD64 hMod = 0;
    BOOL ok = FALSE;

    inj_set_dll_path(dllPath);

    switch (mode) {
    case INJ_APC: {
        HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
        void *pInit;
        DWORD rvaInit = 0;
        void *remoteCtx;
        PAPCFUNC apcInit;

        if (!hKernel || !hThread) return FALSE;

        /* The DLL is pre-loaded synchronously while the target main thread
         * is still suspended (CLR has not started, so this is safe), then
         * InitWarden is queued as a user APC so it executes on that thread
         * before the target's entry point. */
        if (!inj_find_export_rva_file(dllPath, WARDEN_INIT_EXPORT, &rvaInit))
            return FALSE;
        if (!inj_load_library_remote(hProc, dllPath, &hMod))
            return FALSE;
        pInit = (void *)(hMod + rvaInit);

        remoteCtx = inj_remote_write(hProc, ctx, sizeof(*ctx), PAGE_READWRITE);
        if (!remoteCtx) return FALSE;

        apcInit = (PAPCFUNC)pInit;
        if (!QueueUserAPC(apcInit, hThread, (ULONG_PTR)remoteCtx))
            return FALSE;
        ok = TRUE;
        break;
    }
    case INJ_MANUAL:
        ok = inj_manual_map(hProc, dllPath, ctx);
        break;

    case INJ_CLASSIC:
    default:
        if (!inj_load_library_remote(hProc, dllPath, &hMod))
            return FALSE;
        ok = inj_call_initwarden_remote(hProc, hMod, ctx);
        break;
    }

    if (readyHMod) *readyHMod = hMod;
    return ok;
}
