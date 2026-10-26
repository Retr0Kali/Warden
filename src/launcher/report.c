/*
 * Warden - src/launcher/report.c
 * Aggregates monitor events, computes the threat score / verdict and
 * writes machine + human reports into the session directory.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "report.h"
#include "../common/warden.h"
#include "../common/util.h"

#define MAX_RAW_EVENTS  4000
#define MAX_DEDUP_KEYS   512

typedef struct _FINDING {
    char  ev[48];
    long  w;
    int   count;
    char  firstMsg[220];
} FINDING;

struct _WARDEN_REPORT {
    long        score;
    int         verdict;
    DWORD       eventCount;
    char      **raw;                    /* raw JSON lines (capped) */
    DWORD       rawCount;
    char      **dedup;                  /* dedup keys already scored */
    DWORD       dedupCount;
    FINDING    *findings;
    DWORD       findingCount;
    DWORD       findingCap;
};

/* ------------------------------------------------------------------ */
/* tiny JSON field extractor (string or number value of a flat object) */
/* ------------------------------------------------------------------ */

static BOOL jfind_str(const char *json, const char *key,
                      char *out, size_t cap)
{
    char pat[40];
    const char *p;
    size_t o = 0;

    _snprintf_s(pat, sizeof(pat), _TRUNCATE, "\"%s\":\"", key);
    p = strstr(json, pat);
    if (!p) return FALSE;
    p += strlen(pat);
    while (*p && *p != '"' && o + 1 < cap) {
        if (*p == '\\' && p[1]) p++;
        out[o++] = *p++;
    }
    out[o] = 0;
    return TRUE;
}

static BOOL jfind_long(const char *json, const char *key, long *out)
{
    char pat[40];
    const char *p;
    char buf[24];
    size_t o = 0;

    _snprintf_s(pat, sizeof(pat), _TRUNCATE, "\"%s\":", key);
    p = strstr(json, pat);
    if (!p) return FALSE;
    p += strlen(pat);
    while (*p && (*p == '-' || (*p >= '0' && *p <= '9')) && o + 1 < sizeof(buf))
        buf[o++] = *p++;
    buf[o] = 0;
    if (!o) return FALSE;
    *out = atol(buf);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* console colour helpers (VT)                                         */
/* ------------------------------------------------------------------ */

static void con_enable_vt(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static const char *sev_color(const char *sev)
{
    if (!sev) return "\x1b[90m";
    if (!strcmp(sev, "crit"))  return "\x1b[1;91m";   /* bright red    */
    if (!strcmp(sev, "warn"))  return "\x1b[1;93m";   /* bright yellow */
    if (!strcmp(sev, "ok"))    return "\x1b[1;92m";   /* bright green  */
    if (!strcmp(sev, "debug")) return "\x1b[90m";     /* gray          */
    return "\x1b[96m";                                /* cyan (info)   */
}

/* ------------------------------------------------------------------ */
/* findings bookkeeping                                                */
/* ------------------------------------------------------------------ */

static FINDING *rep_finding(WARDEN_REPORT *rep, const char *ev)
{
    DWORD i;
    for (i = 0; i < rep->findingCount; i++)
        if (!strcmp(rep->findings[i].ev, ev))
            return &rep->findings[i];
    if (rep->findingCount >= rep->findingCap) {
        rep->findingCap = rep->findingCap ? rep->findingCap * 2 : 16;
        rep->findings = (FINDING *)HeapReAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY, rep->findings,
            rep->findingCap * sizeof(FINDING));
        if (!rep->findings) return NULL;
    }
    strncpy_s(rep->findings[rep->findingCount].ev, 48, ev, _TRUNCATE);
    return &rep->findings[rep->findingCount++];
}

static BOOL rep_dedup_seen(WARDEN_REPORT *rep, const char *key)
{
    DWORD i;
    if (!key || !*key) return FALSE;
    for (i = 0; i < rep->dedupCount; i++)
        if (!strcmp(rep->dedup[i], key))
            return TRUE;
    if (rep->dedupCount < MAX_DEDUP_KEYS) {
        rep->dedup[rep->dedupCount] = _strdup(key);
        if (rep->dedup[rep->dedupCount])
            rep->dedupCount++;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

WARDEN_REPORT *rep_create(void)
{
    WARDEN_REPORT *rep = (WARDEN_REPORT *)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(WARDEN_REPORT));
    if (!rep) return NULL;
    rep->raw = (char **)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                MAX_RAW_EVENTS * sizeof(char *));
    rep->dedup = (char **)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                 MAX_DEDUP_KEYS * sizeof(char *));
    if (!rep->raw || !rep->dedup) {
        rep_free(rep);
        return NULL;
    }
    con_enable_vt();
    return rep;
}

void rep_free(WARDEN_REPORT *rep)
{
    DWORD i;
    if (!rep) return;
    if (rep->raw)
        for (i = 0; i < rep->rawCount; i++) free(rep->raw[i]);
    if (rep->dedup)
        for (i = 0; i < rep->dedupCount; i++) free(rep->dedup[i]);
    if (rep->findings) HeapFree(GetProcessHeap(), 0, rep->findings);
    HeapFree(GetProcessHeap(), 0, rep->raw);
    HeapFree(GetProcessHeap(), 0, rep->dedup);
    HeapFree(GetProcessHeap(), 0, rep);
}

void rep_feed(WARDEN_REPORT *rep, const char *jsonLine)
{
    char ev[48] = {0}, sev[16] = {0}, dedup[200] = {0}, msg[400] = {0};
    char ts[24] = {0};
    long w = 0;
    FINDING *f;

    if (!rep || !jsonLine || !*jsonLine) return;
    rep->eventCount++;

    jfind_str(jsonLine, "ev", ev, sizeof(ev));
    jfind_str(jsonLine, "sev", sev, sizeof(sev));
    jfind_str(jsonLine, "dedup", dedup, sizeof(dedup));
    jfind_str(jsonLine, "msg", msg, sizeof(msg));
    jfind_str(jsonLine, "ts", ts, sizeof(ts));
    jfind_long(jsonLine, "w", &w);

    /* console echo */
    printf("\x1b[90m[%s]\x1b[0m %s%-9s\x1b[0m %s\x1b[0m\n",
           ts[0] ? ts : "--:--:--",
           sev_color(sev), ev, msg);

    /* store raw */
    if (rep->rawCount < MAX_RAW_EVENTS) {
        char *copy = _strdup(jsonLine);
        if (copy) rep->raw[rep->rawCount++] = copy;
    }

    /* scoring with per-class dedup */
    if (w > 0) {
        if (rep_dedup_seen(rep, dedup[0] ? dedup : ev))
            return; /* already scored for this class/key */
        rep->score += w;
        if (rep->score > 100) rep->score = 100;
    }

    f = rep_finding(rep, ev[0] ? ev : "unknown");
    if (f) {
        f->count++;
        f->w = w > f->w ? w : f->w;
        if (!f->firstMsg[0] && msg[0])
            strncpy_s(f->firstMsg, 220, msg, _TRUNCATE);
    }
}

static const char *verdict_str(int v)
{
    switch (v) {
    case VERDICT_MALICIOUS:  return "MALICIOUS";
    case VERDICT_SUSPICIOUS: return "SUSPICIOUS";
    default:                 return "CLEAN";
    }
}

static void write_report_files(WARDEN_REPORT *rep, const wchar_t *sessionDir,
                               const wchar_t *targetDesc, DWORD targetPid,
                               DWORD exitCode, double wallSeconds)
{
    char pathJson[760], pathTxt[760];
    wchar_t wJson[760], wTxt[760];
    FILE *fj = NULL, *ft = NULL;
    DWORD i;
    char *targetUtf8 = NULL;

    _snwprintf_s(wJson, 760, _TRUNCATE, L"%s\\report.json", sessionDir);
    _snwprintf_s(wTxt, 760, _TRUNCATE, L"%s\\report.txt", sessionDir);
    WideCharToMultiByte(CP_UTF8, 0, wJson, -1, pathJson, 760, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wTxt, -1, pathTxt, 760, NULL, NULL);
    wu_w2utf8(targetDesc, &targetUtf8);

    /* ---- report.json ---- */
    fopen_s(&fj, pathJson, "wb");
    if (fj) {
        fprintf(fj, "{\n  \"tool\": \"Warden\",\n  \"version\": \"%s\",\n",
                WARDEN_VERSION);
        fprintf(fj, "  \"target\": \"%s\",\n",
                targetUtf8 ? targetUtf8 : "unknown");
        fprintf(fj, "  \"pid\": %lu,\n  \"exitCode\": %lu,\n", targetPid, exitCode);
        fprintf(fj, "  \"wallSeconds\": %.2f,\n", wallSeconds);
        fprintf(fj, "  \"score\": %ld,\n  \"verdict\": \"%s\",\n",
                rep->score, verdict_str(rep->verdict));
        fprintf(fj, "  \"events\": %lu,\n  \"findings\": [\n", rep->eventCount);
        for (i = 0; i < rep->findingCount; i++) {
            FINDING *fd = &rep->findings[i];
            char esc[460];
            wu_json_escape(esc, sizeof(esc), fd->firstMsg);
            fprintf(fj, "    {\"ev\": \"%s\", \"count\": %d, \"maxWeight\": %ld,\n"
                        "     \"firstMsg\": \"%s\"}%s\n",
                    fd->ev, fd->count, fd->w, esc,
                    (i + 1 < rep->findingCount) ? "," : "");
        }
        fprintf(fj, "  ],\n  \"rawEvents\": [\n");
        for (i = 0; i < rep->rawCount; i++)
            fprintf(fj, "    %s%s\n", rep->raw[i],
                    (i + 1 < rep->rawCount) ? "," : "");
        fprintf(fj, "  ]\n}\n");
        fclose(fj);
    }

    /* ---- report.txt ---- */
    fopen_s(&ft, pathTxt, "wb");
    if (ft) {
        fprintf(ft, "==============================================\n");
        fprintf(ft, " WARDEN ANALYSIS REPORT v%s\n", WARDEN_VERSION);
        fprintf(ft, "==============================================\n");
        fprintf(ft, " Target    : %ls\n", targetDesc);
        fprintf(ft, " PID       : %lu\n", targetPid);
        fprintf(ft, " Exit code : %lu\n", exitCode);
        fprintf(ft, " Runtime   : %.2f s\n", wallSeconds);
        fprintf(ft, " Events    : %lu\n", rep->eventCount);
        fprintf(ft, " Score     : %ld / 100\n", rep->score);
        fprintf(ft, " Verdict   : %s\n", verdict_str(rep->verdict));
        fprintf(ft, "----------------------------------------------\n");
        fprintf(ft, " FINDINGS\n");
        if (rep->findingCount == 0)
            fprintf(ft, " (none)\n");
        for (i = 0; i < rep->findingCount; i++) {
            FINDING *fd = &rep->findings[i];
            fprintf(ft, "  %-22s x%-3d maxW=%-3ld %s\n",
                    fd->ev, fd->count, fd->w, fd->firstMsg);
        }
        fprintf(ft, "----------------------------------------------\n");
        fprintf(ft, " Artifacts : %ls\\dumps\n", sessionDir);
        fprintf(ft, " Events    : %ls\\events.jsonl\n", sessionDir);
        fprintf(ft, " Log       : %ls\\warden.log\n", sessionDir);
        fclose(ft);
    }
    warden_free(targetUtf8);
}

int rep_finalize(WARDEN_REPORT *rep, const wchar_t *sessionDir,
                 const wchar_t *targetDesc, DWORD targetPid,
                 DWORD exitCode, double wallSeconds)
{
    DWORD i;
    int v;

    if (!rep) return EXITCODE_ERROR;
    v = (rep->score >= VERDICT_THRESHOLD_MALICIOUS) ? VERDICT_MALICIOUS :
        (rep->score >= VERDICT_THRESHOLD_SUSPICIOUS) ? VERDICT_SUSPICIOUS :
        VERDICT_CLEAN;
    rep->verdict = v;

    write_report_files(rep, sessionDir, targetDesc, targetPid, exitCode,
                       wallSeconds);

    printf("\n\x1b[1;97m================ WARDEN SUMMARY ================\x1b[0m\n");
    printf(" Events seen : %lu\n", rep->eventCount);
    printf(" Findings    : %lu\n", rep->findingCount);
    for (i = 0; i < rep->findingCount; i++)
        printf("   \x1b[90m-\x1b[0m %-22s x%d (%s)\n",
               rep->findings[i].ev, rep->findings[i].count,
               rep->findings[i].firstMsg);
    printf(" Score       : %ld / 100\n", rep->score);
    if (v == VERDICT_MALICIOUS)
        printf(" Verdict     : \x1b[1;91mMALICIOUS\x1b[0m\n");
    else if (v == VERDICT_SUSPICIOUS)
        printf(" Verdict     : \x1b[1;93mSUSPICIOUS\x1b[0m\n");
    else
        printf(" Verdict     : \x1b[1;92mCLEAN\x1b[0m\n");
    printf(" Reports     : %ls\\report.json | report.txt\n", sessionDir);
    printf("\x1b[1;97m================================================\x1b[0m\n");

    return v;
}
