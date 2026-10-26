# Warden — Architecture

How the three detection engines, the injection modes and the reporting
pipeline fit together.

## Component overview

```
                        Warden.exe (launcher)
   ┌────────────────────────────────────────────────────────────┐
   │ parse args → resolve .exe/.bat/.cmd/.ps1 → session dir     │
   │ set COR_* profiler env + WARDEN_* env                      │
   │ CreateProcessW(CREATE_SUSPENDED | CREATE_NEW_CONSOLE)      │
   │        │                                                   │
   │        ▼                                                   │
   │ inj_inject(mode) ── classic  : remote thread LoadLibraryW  │
   │                     apc      : pre-load + QueueUserAPC     │
   │                     manual   : map PE + relocs + imports   │
   │        │                                                   │
   │        ▼                                                   │
   │ named pipe server  ◀──── events (JSONL) ────┐              │
   │ wait READY → ResumeThread                   │              │
   │ aggregate score/verdict → report.json/txt   │              │
   └─────────────────────────────────────────────┼──────────────┘
                                                 │
                        Warden.dll (monitor, inside target)
   ┌─────────────────────────────────────────────┼──────────────┐
   │ InitWarden(ctx) or CLR profiler Initialize  │              │
   │        ├── log: pipe + events.jsonl + log   │              │
   │        ├── hooks (optional, LDE trampolines)│              │
   │        ├── scanner thread (VirtualQuery)    │              │
   │        ├── integrity thread (disk compare)  │              │
   │        └── reaper thread (flush on exit)    │              │
   │                                             │              │
   │ CLR Profiler API (COM): Assembly/Module events             │
   └────────────────────────────────────────────────────────────┘
```

## Entry paths into the monitor

Warden.dll is dual-purpose: it is both an injected monitor and a registered
CLR profiler (same binary, two triggers).

1. **Injection** — launcher calls `InitWarden(ctx)` via remote thread
   (classic/manual) or a user APC queued on the suspended main thread
   (apc). The context block (`WARDEN_CTX`) carries pipe name, session dir,
   flags and scan interval.
2. **CLR profiler** — the launcher sets `COR_ENABLE_PROFILING`,
   `COR_PROFILER={CLSID}`, `COR_PROFILER_PATH_64` *before* the process
   starts. When the target initializes its CLR, the runtime itself loads
   `Warden.dll` and calls `DllGetClassObject → IClassFactory::CreateInstance
   → ICorProfilerCallback::Initialize`, which calls `mon_start(NULL)`.
   Configuration then falls back to `WARDEN_*` environment variables.

`mon_start` is a one-shot (interlocked guard), so both paths may fire —
the second call is a no-op.

## Engine 1 — CLR Profiler API layer

* Implemented against the SDK `<corprof.h>`, `ICorProfilerCallback` (v1).
  The compiler derives the exact vtable layout — nothing hand-rolled.
* Event mask: `COR_PRF_MONITOR_MODULE_LOADS | COR_PRF_MONITOR_ASSEMBLY_LOADS`.
* Key detections from `ModuleLoadFinished`:
  * `GetModuleInfo` returns `base == 0` → the module has **no backing image**
    → in-memory load (`Assembly.Load(byte[])`, crypter stubs) → `w=25`.
  * `GetModuleInfo2` sets `COR_PRF_MODULE_DYNAMIC` → Reflection.Emit → `w=25`.
* Because this is a *documented* interface, it survives CLR servicing that
  shuffles internal symbols — a hard requirement for a tool that must keep
  working across Windows updates without re-engineering.

## Engine 2 — memory scanner

Periodic full `VirtualQuery` walk (4 GB budget per pass, default 1500 ms):

| Region | Meaning | Action |
|---|---|---|
| `MEM_PRIVATE` + `PAGE_EXECUTE*` + valid `MZ/PE` header | manually mapped / reflective image | `exec_region` (+30), dump `SizeOfImage` bytes |
| `MEM_PRIVATE` + exec, no MZ, entropy > 6.8 | raw shellcode / packed stage | `shellcode_region` (+15), dump first 64 KB |
| `MEM_IMAGE` + exec, base **not** in PEB list | unlinked / shadow DLL | `hidden_image` (+35), dump region |

Self-protection: Warden skips its own module range (crucial in manual-map
mode where the monitor itself is a "hidden" image) and its own trampoline
pages. Detections are deduplicated per base address for the score, while
dumps are numbered sequentially with a sha256 sidecar.

## Engine 3 — integrity engine

For `amsi.dll`, `ntdll.dll`, `clr.dll` present in the target:

1. Cache the clean **on-disk** copy.
2. Build a **skip set** of byte ranges that legitimately differ between
   memory and disk:
   * every `.reloc` target (ASLR relocated absolute addresses),
   * Warden's own hook patches (queried from the monitor's patch registry).
3. Compare, range by range (sorted skip set, segmented `memcmp`):
   * watched function prologues — `AmsiScanBuffer`, `AmsiScanString`,
     `EtwEventWrite`, `EtwEventWriteFull` (16 bytes each),
   * full `.text` of amsi/ntdll, `.rdata` of amsi/clr (string patching —
     in-memory loader stubs patch CLR strings to break the AMSI integration).
4. Classify the first 16 divergent bytes against known bypass patterns:
   * `B8 57 00 07 80 …` → `mov eax, 0x80070057` (E_INVALIDARG fail-open),
   * `33 C0 C3` / `31 C0 C3` / `48 31 C0 C3` → `xor eax,eax; ret` blindfold,
   * `C3` → nullsub.
   Classified matches add a `bypass_sig` bonus (+10) and label the tamper
   event's `signature` field.

Any unexplained difference becomes `amsi_tamper` (+50), `etw_tamper` (+50)
or `clr_tamper` (+30) with `origBytes` / `nowBytes` hex in the event data.

## Hook engine (telemetry)

Conservative x64 inline detours:

* **LDE** — a table-driven length disassembler covering compiler-generated
  prologues: `endbr64`, nops/hint-nops, `push/pop r64`, `push imm8/32`,
  `mov/test/xor/lea/movsx` with ModRM (including SIB and `[rsp+d8]`
  forms), `sub rsp, imm8/32`, `call rel32`, RIP-relative `lea/mov/call`.
* **Trampoline** — relocated prologue + 14-byte `ff 25` absolute jump back;
  RIP-relative disp32 values are rebased to the trampoline address.
* **Patch** — 14-byte absolute jump to the hook at the target prologue;
  `FlushInstructionCache` after both writes.
* **Graceful skip** — any unsupported encoding aborts *that* hook only and
  logs `hook_skip`; the rest of Warden keeps working.
* Hooks: `ntdll!LdrLoadDll`, `kernelbase!LoadLibraryExW`,
  `kernelbase!VirtualAlloc` (RWX commits), `kernelbase!VirtualProtect`
  (→ exec), `kernelbase!CreateProcessW` (child chain).
* Hook bodies log **after** calling the original, use SEH around pointer
  dereferences, and deduplicate per name/address so loader storms don't
  flood the feed.

## Reporting pipeline

* Monitor → launcher: JSON lines over a message-mode named pipe
  (`\\.\pipe\Warden\<launcherpid>-<tick>`); the same lines are appended to
  `events.jsonl` and `warden.log` locally (survives launcher death).
* Launcher aggregates: console echo with VT severity colors, dedup-keyed
  scoring, final `report.json` / `report.txt`, verdict mapped to the
  process exit code for lab automation.
* A reaper thread in the monitor waits on the current process and flushes
  `done` + closes handles cleanly (never inside `DllMain`).

## Threading model (monitor)

| Thread | Origin | Role |
|---|---|---|
| init thread | remote thread / APC / CLR Initialize | `mon_start`, hook install, pipe connect |
| scanner | `CreateThread` | `scanner_run(interval)` |
| integrity | `CreateThread` | `integrity_run(2×interval)` |
| reaper | `CreateThread` | wait process → flush → close |
| profiler callbacks | CLR threads | `wlog_event` (mutex-guarded) |

`DllMain` only stores the module handle and calls
`DisableThreadLibraryCalls` — no loader-lock work.

## Known limitations

* x64 only; WoW64 targets are rejected.
* Profiler layer is validated for .NET Framework 4.x; .NET Core/5+ gets
  best-effort vars plus full scanner/integrity/hook coverage.
* The LDE deliberately refuses exotic prologues (security = coverage).
* Manual-map mode imports resolved via remote PEB walk; DLLs not yet
  loaded in the target are pulled in with a classic remote `LoadLibraryW`
  (documented trade-off, keeps the mapper simple and reliable).
* Job-object child-chain injection and YARA integration are natural next
  steps (see README roadmap notes).
