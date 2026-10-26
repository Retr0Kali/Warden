/*
 * Warden - src/launcher/report.h
 * Live event aggregation + final threat scoring / verdict reports.
 */
#ifndef WARDEN_REPORT_H
#define WARDEN_REPORT_H

#include <windows.h>
#include "../common/warden.h"

typedef struct _WARDEN_REPORT WARDEN_REPORT;

WARDEN_REPORT *rep_create(void);

/* Feed one raw JSON event line received from the monitor.
 * The launcher parses "ev", "sev", "w" and "dedup" fields, echoes a
 * coloured console line, accumulates the score and stores the raw line
 * for the final report. */
void rep_feed(WARDEN_REPORT *rep, const char *jsonLine);

/* Finalise: returns verdict (VERDICT_*), writes report.json + report.txt
 * into sessionDir and prints the summary banner. */
int rep_finalize(WARDEN_REPORT *rep, const wchar_t *sessionDir,
                 const wchar_t *targetDesc, DWORD targetPid,
                 DWORD exitCode, double wallSeconds);

void rep_free(WARDEN_REPORT *rep);

#endif /* WARDEN_REPORT_H */
