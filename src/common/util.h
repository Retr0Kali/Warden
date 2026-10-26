/*
 * Warden - src/common/util.h
 * Small shared utilities: UTF conversions, JSON escaping, entropy,
 * module snapshot, file IO, PE helpers.
 */
#ifndef WARDEN_UTIL_H
#define WARDEN_UTIL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- string helpers ------------------------------------------------ */

/* Convert UTF-16 -> UTF-8 into caller heap buffer (*out must be freed
 * with warden_free). Returns number of bytes written or 0 on failure. */
DWORD wu_w2utf8(const wchar_t *ws, char **out);

/* JSON-escape src into dst (dstCap includes NUL). Returns dst. */
char *wu_json_escape(char *dst, size_t dstCap, const char *src);

/* Case-insensitive wide compare (avoids CRT variance) */
int  wu_wieq(const wchar_t *a, const wchar_t *b);

/* Append-file write helper. Creates file on first use. */
BOOL wu_append_file(const wchar_t *path, const void *data, DWORD cb);

/* Read whole file into heap (*out, freed by warden_free). */
BOOL wu_read_file(const wchar_t *path, unsigned char **out, DWORD *cbOut);

/* Recursive directory create (wide). */
BOOL wu_mkdirs(const wchar_t *path);

void warden_free(void *p);

/* Timestamp "HH:MM:SS.mmm" into buf. */
void wu_time_str(char *buf, size_t cap);

/* Bytes -> lowercase hex. dst needs 2*cb+1. */
void wu_hex(const unsigned char *data, size_t cb, char *dst);

/* --- hashing / statistics ------------------------------------------ */

/* SHA-256 of data; digest written as 32 raw bytes. */
void wu_sha256(const unsigned char *data, size_t len, unsigned char digest[32]);

/* Shannon entropy per byte [0..8], rounded to 2 decimals. */
double wu_entropy(const unsigned char *data, size_t len);

/* --- module snapshot (own process, x64 PEB walk) -------------------- */

typedef struct _WARDEN_MODULE {
    HMODULE   base;
    DWORD     sizeOfImage;
    wchar_t   name[64];       /* base name, e.g. "amsi.dll"            */
    wchar_t   path[512];      /* full on-disk path                     */
} WARDEN_MODULE;

typedef struct _WARDEN_MODLIST {
    WARDEN_MODULE *items;
    DWORD          count;
} WARDEN_MODLIST;

/* Snapshot current process modules via the loader data table.
 * Returns TRUE with list populated (caller frees via wu_modlist_free). */
BOOL wu_module_snapshot(WARDEN_MODLIST *list);

void wu_modlist_free(WARDEN_MODLIST *list);

/* Find a module by base name (case-insensitive). */
const WARDEN_MODULE *wu_modlist_find(const WARDEN_MODLIST *list,
                                     const wchar_t *name);

/* Address belongs to one of the module ranges? */
const WARDEN_MODULE *wu_modlist_by_addr(const WARDEN_MODLIST *list, DWORD64 addr);

/* --- PE helpers (in-memory or file image) --------------------------- */

/* Validate MZ/PE at p. Returns size of image on success, 0 otherwise. */
DWORD wu_pe_validate(const unsigned char *p, size_t avail);

/* RVA -> file offset using section table. 0 if unmappable. */
DWORD wu_pe_rva_to_offset(const unsigned char *p, DWORD rva);

/* Find export RVA by name in a PE image buffer (file layout). */
BOOL wu_pe_find_export(const unsigned char *p, const char *name, DWORD *rva);

#ifdef __cplusplus
}
#endif
#endif /* WARDEN_UTIL_H */
