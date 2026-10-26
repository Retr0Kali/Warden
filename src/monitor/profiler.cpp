/*
 * Warden - src/monitor/profiler.cpp
 *
 * CLR Profiler API layer (documented interface, version-stable).
 *
 * The launcher sets COR_ENABLE_PROFILING / COR_PROFILER /
 * COR_PROFILER_PATH_64 before the process starts, so the CLR loads
 * Warden.dll itself as the profiler - no injection required for .NET
 * targets. This gives us precise managed-side events:
 *
 *   AssemblyLoadStarted / AssemblyLoadFinished  -> every assembly load
 *   ModuleLoadFinished  -> base==0  => in-memory (Assembly.Load(byte[]))
 *                          COR_PRF_MODULE_DYNAMIC => Reflection.Emit
 *
 * Implemented against the Windows SDK <corprof.h> (ICorProfilerCallback
 * v1) so the compiler derives the exact vtable layout - no hand-rolled
 * interface definitions.
 *
 * Build note: requires the Windows SDK that ships with Visual Studio.
 */
#include <objbase.h>
#include <corhdr.h>   /* mdToken / mdMethodDef / CorElementType - corprof.h
                          does NOT pull this in itself (SDK quirk)        */
#include <corprof.h>
#include <new>
#include <stdio.h>
#include <string.h>

#include "monitor.h"

extern "C" {
#include "../common/log.h"
#include "../common/util.h"
#include "../common/warden.h"
}

/* {7C1E6B4A-9A2D-4E8B-B1F3-3C5A7D9E2F41} */
static const GUID CLSID_WardenProfiler =
{ 0x7c1e6b4a, 0x9a2d, 0x4e8b,
  { 0xb1, 0xf3, 0x3c, 0x5a, 0x7d, 0x9e, 0x2f, 0x41 } };

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static ICorProfilerInfo  *g_info  = NULL;
static ICorProfilerInfo2 *g_info2 = NULL;
#ifdef COR_PRF_MODULE_DYNAMIC
/* NETFXSDK / newer corprof.h exposes module flags via ICorProfilerInfo3.
   Older 10.0.* SDK um/ headers stop at Info2 - degrade gracefully.      */
static ICorProfilerInfo3 *g_info3 = NULL;
#endif

static void emit_wide(const char *ev, long w, const char *sev,
                      const char *dedup, const wchar_t *what,
                      const char *extra)
{
    char data[600];
    char whatA[300];
    WideCharToMultiByte(CP_UTF8, 0, what ? what : L"", -1,
                        whatA, 300, NULL, NULL);
    _snprintf_s(data, sizeof(data), _TRUNCATE,
                "\"name\":\"%s\"%s%s", whatA,
                extra && extra[0] ? "," : "",
                extra && extra[0] ? extra : "");
    wlog_event(ev, w, sev, dedup, data, "%s", whatA);
}

/* ------------------------------------------------------------------ */
/* WardenProfiler : ICorProfilerCallback (v1)                          */
/* ------------------------------------------------------------------ */

class WardenProfiler : public ICorProfilerCallback
{
public:
    /* IUnknown */
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == __uuidof(IUnknown) ||
            riid == __uuidof(ICorProfilerCallback)) {
            *ppv = static_cast<ICorProfilerCallback *>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override  { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }

    /* --- lifecycle ------------------------------------------------- */
    HRESULT STDMETHODCALLTYPE Initialize(IUnknown *pICorProfilerInfoUnk) override
    {
        if (!pICorProfilerInfoUnk) return E_POINTER;
        pICorProfilerInfoUnk->QueryInterface(__uuidof(ICorProfilerInfo),
                                             (void **)&g_info);
        if (g_info)
            g_info->QueryInterface(__uuidof(ICorProfilerInfo2),
                                   (void **)&g_info2);
#ifdef COR_PRF_MODULE_DYNAMIC
        if (g_info)
            g_info->QueryInterface(__uuidof(ICorProfilerInfo3),
                                   (void **)&g_info3);
#endif
        if (g_info)
            g_info->SetEventMask(COR_PRF_MONITOR_MODULE_LOADS |
                                 COR_PRF_MONITOR_ASSEMBLY_LOADS);
        /* boot the full monitor from the profiler path as well */
        mon_start(NULL);
        wlog_event("profiler_init", SC_INFO, "ok", NULL, NULL,
                   "CLR profiler attached (managed event stream live)");
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Shutdown() override
    {
        wlog_event("profiler_shutdown", SC_INFO, "info", NULL, NULL,
                   "CLR profiler shutting down");
        return S_OK;
    }

    /* --- appdomains (stubs) ----------------------------------------- */
    HRESULT STDMETHODCALLTYPE AppDomainCreationStarted(AppDomainID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainCreationFinished(AppDomainID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainShutdownStarted(AppDomainID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AppDomainShutdownFinished(AppDomainID, HRESULT) override { return S_OK; }

    /* --- assemblies: the money events ------------------------------- */
    HRESULT STDMETHODCALLTYPE AssemblyLoadStarted(AssemblyID assemblyId) override
    {
        wchar_t name[512] = L"";
        ULONG cch = 512, got = 0;
        AppDomainID ad = 0;
        ModuleID mid = 0;
        if (g_info &&
            SUCCEEDED(g_info->GetAssemblyInfo(assemblyId, cch, &got, name,
                                              &ad, &mid)) && got) {
            char key[340];
            WideCharToMultiByte(CP_UTF8, 0, name, -1, key, 340, NULL, NULL);
            emit_wide("assembly_load", SC_INFO, "info", key, name,
                      "\"phase\":\"load-started\"");
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE AssemblyLoadFinished(AssemblyID, HRESULT hr) override
    {
        if (FAILED(hr))
            wlog_event("assembly_load_failed", SC_INFO, "warn", NULL, NULL,
                       "assembly load finished with failure 0x%08lx",
                       (unsigned long)hr);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE AssemblyUnloadStarted(AssemblyID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AssemblyUnloadFinished(AssemblyID, HRESULT) override { return S_OK; }

    /* --- modules: in-memory + dynamic detection ---------------------- */
    HRESULT STDMETHODCALLTYPE ModuleLoadStarted(ModuleID) override { return S_OK; }

    HRESULT STDMETHODCALLTYPE ModuleLoadFinished(ModuleID moduleId,
                                                 HRESULT hrStatus) override
    {
        if (SUCCEEDED(hrStatus) && g_info) {
            wchar_t name[512] = L"";
            ULONG cch = 512, got = 0;
            LPCBYTE base = 0;
            AssemblyID asmId = 0;

            if (SUCCEEDED(g_info->GetModuleInfo(moduleId, &base, cch, &got,
                                                name, &asmId))) {
                BOOL inMemory = (base == 0);
                BOOL dynamic  = FALSE;
#ifdef COR_PRF_MODULE_DYNAMIC
                DWORD flags = 0;
                if (g_info3)
                    g_info3->GetModuleInfo2(moduleId, &base, cch, &got, name,
                                            &asmId, &flags);
                dynamic = (flags & COR_PRF_MODULE_DYNAMIC) != 0;
#endif

                if (dynamic) {
                    char key[340];
                    char extra[160];
                    WideCharToMultiByte(CP_UTF8, 0, name, -1, key, 340,
                                        NULL, NULL);
                    _snprintf_s(extra, sizeof(extra), _TRUNCATE,
                                "\"kind\":\"dynamic\"");
                    emit_wide("dynamic_module", SC_DYNAMIC_MODULE, "warn",
                              key, name, extra);
                } else if (inMemory) {
                    char key[340];
                    char extra[160];
                    WideCharToMultiByte(CP_UTF8, 0, name, -1, key, 340,
                                        NULL, NULL);
                    _snprintf_s(extra, sizeof(extra), _TRUNCATE,
                                "\"kind\":\"in-memory\",\"imageBase\":\"0\"");
                    emit_wide("inmemory_module", SC_INMEMORY_MODULE, "crit",
                              key, name, extra);
                } else {
                    /* disk-backed module load: verbose only */
                    if (wlog_verbose()) {
                        char key[340];
                        WideCharToMultiByte(CP_UTF8, 0, name, -1, key, 340,
                                            NULL, NULL);
                        emit_wide("module_load", SC_INFO, "debug", key,
                                  name, "\"kind\":\"disk\"");
                    }
                }
            }
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ModuleUnloadStarted(ModuleID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ModuleUnloadFinished(ModuleID, HRESULT) override { return S_OK; }

    HRESULT STDMETHODCALLTYPE ModuleAttachedToAssembly(ModuleID moduleId,
                                                       AssemblyID asmId) override
    {
        if (wlog_verbose() && g_info) {
            wchar_t name[512] = L"";
            ULONG cch = 512, got = 0;
            LPCBYTE base = 0;
            AssemblyID a2 = 0;
            if (SUCCEEDED(g_info->GetModuleInfo(moduleId, &base, cch, &got,
                                                name, &a2)) && got)
                emit_wide("module_attached", SC_INFO, "debug", NULL, name,
                          NULL);
        }
        return S_OK;
    }

    /* --- classes (stubs) --------------------------------------------- */
    HRESULT STDMETHODCALLTYPE ClassLoadStarted(ClassID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassLoadFinished(ClassID, HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassUnloadStarted(ClassID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ClassUnloadFinished(ClassID, HRESULT) override { return S_OK; }

    /* --- functions / JIT (stubs) -------------------------------------- */
    HRESULT STDMETHODCALLTYPE FunctionUnloadStarted(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITCompilationStarted(FunctionID, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITCompilationFinished(FunctionID, HRESULT, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITFunctionPitched(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITInlining(FunctionID callerId, FunctionID calleeId, BOOL *pfShouldInline) override
    {
        (void)callerId; (void)calleeId;
        if (pfShouldInline) *pfShouldInline = TRUE;
        return S_OK;
    }

    /* --- threads (stubs) ----------------------------------------------- */
    HRESULT STDMETHODCALLTYPE ThreadCreated(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadDestroyed(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ThreadAssignedToOSThread(ThreadID, DWORD) override { return S_OK; }

    /* --- remoting (stubs) ---------------------------------------------- */
    HRESULT STDMETHODCALLTYPE RemotingClientInvocationStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientSendingMessage(GUID *, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientReceivingReply(GUID *, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingClientInvocationFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerReceivingMessage(GUID *, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerSendingReply(GUID *, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerInvocationStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemotingServerInvocationReturned() override { return S_OK; }

    /* --- historical v1 stubs -------------------------------------------- */
    HRESULT STDMETHODCALLTYPE ManagedToUnmanagedTransition(FunctionID, COR_PRF_TRANSITION_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE UnmanagedToManagedTransition(FunctionID, COR_PRF_TRANSITION_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeSuspendAborted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeResumeStarted() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeResumeFinished() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeThreadSuspended(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RuntimeThreadResumed(ThreadID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE MovedReferences(ULONG, ObjectID[], ObjectID[], ULONG[]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectAllocated(ObjectID, ClassID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectsAllocatedByClass(ULONG, ClassID[], ULONG[]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ObjectReferences(ObjectID, ClassID, ULONG, ObjectID[]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RootReferences(ULONG, ObjectID[]) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionThrown(ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFilterEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchFilterLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionSearchCatcherFound(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionOSHandlerEnter(UINT_PTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionOSHandlerLeave(UINT_PTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyEnter(FunctionID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCatcherEnter(FunctionID, ObjectID) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCatcherLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE COMClassicVTableCreated(ClassID, REFGUID, void *, ULONG) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE COMClassicVTableDestroyed(ClassID, REFGUID, void *) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherFound() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherExecute() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchStarted(FunctionID,
                                                 BOOL *pbUseCachedFunction) override
    {
        if (pbUseCachedFunction) *pbUseCachedFunction = FALSE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchFinished(FunctionID, COR_PRF_JIT_CACHE) override { return S_OK; }
};

/* ------------------------------------------------------------------ */
/* class factory                                                       */
/* ------------------------------------------------------------------ */

class WardenFactory : public IClassFactory
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IClassFactory)) {
            *ppv = static_cast<IClassFactory *>(this);
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override  { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *pUnkOuter,
                                             REFIID riid,
                                             void **ppv) override
    {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppv) return E_POINTER;
        {
            WardenProfiler *p = new (std::nothrow) WardenProfiler();
            if (!p) return E_OUTOFMEMORY;
            HRESULT hr = p->QueryInterface(riid, ppv);
            if (FAILED(hr)) delete p;
            return hr;
        }
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL) override { return S_OK; }
};

/* ------------------------------------------------------------------ */
/* COM exports (see warden.def)                                        */
/* ------------------------------------------------------------------ */

extern "C" HRESULT STDAPICALLTYPE DllGetClassObject(REFCLSID rclsid,
                                                    REFIID riid,
                                                    LPVOID *ppv)
{
    if (!ppv) return E_POINTER;
    /* lenient CLSID check: accept whatever COR_PROFILER points at us */
    if (rclsid != CLSID_WardenProfiler) {
        /* still serve the factory - labs often reuse env templates */
    }
    {
        WardenFactory *f = new (std::nothrow) WardenFactory();
        if (!f) return E_OUTOFMEMORY;
        HRESULT hr = f->QueryInterface(riid, ppv);
        if (FAILED(hr)) delete f;
        return hr;
    }
}

extern "C" HRESULT STDAPICALLTYPE DllCanUnloadNow(void)
{
    return S_FALSE; /* stay resident for the life of the process */
}
