# Warden — Analysis Workflow (Lab Playbook)

From zero to a repeatable triage loop for `.bat / .cmd / .ps1 / .exe`
loader chains.

## 0. Lab prerequisites

* Windows 10/11 **x64** VM, snapshotted, no sensitive data.
* Visual Studio 2022 (or grab the `warden-bin-x64` artifact from GitHub
  Actions) — you need `Warden.exe`, `Warden.dll`, and ideally
  `LoadSim.exe`.
* Copy `Warden.exe`, `Warden.dll` into the same folder (the launcher
  locates the DLL next to itself).
* Keep the VM offline unless the sample *requires* C2 to reach its
  payload stage; when online, use a fake-network appliance or
  monitoring you control.

> Warden is an analysis instrument — do not add it to the Defender
> exclusion list of any machine that isn't a disposable lab VM, and
> never ship the dumps (they contain live malware code).

## 1. Sanity check: the simulator

Before touching real samples, prove every layer fires:

```bat
bin\Warden.exe bin\LoadSim.exe
```

Expected transcript (abridged):

```
[*] Warden v1.0.0 session
    target  : C:\lab\bin\LoadSim.exe
    inject  : classic (CreateRemoteThread)
[*] target pid 8152 created suspended
[*] injecting monitor (classic mode)...
[*] monitor ready OK
[*] target resumed - live feed:

[14:25:31.001] ok       ready       Warden monitor active (x64) ...
[14:25:31.104] info     clr_present CLR detected: clr.dll loaded from ...
[14:25:31.190] info     assembly_load loadsim
[14:25:31.204] crit     inmemory_module loadsim
[14:25:31.372] warn     dynamic_module SimModule
[14:25:31.980] warn     valloc_exec  VirtualAlloc committed RWX memory at 0x1f4a0000 ...
[14:25:32.011] crit     exec_region  private executable region at 0x1f4a0000 contains a PE image ...
[14:25:32.030] ok       dump_saved   dump saved: ...dump_01_1f4a0000_pe.bin (sha256 ...)
[14:25:33.500] warn     vprotect_exec VirtualProtect raised protection to executable ...
[14:25:34.220] info     childproc    child process 9910 created: cmd.exe /c echo loadsim-child-ok
[14:25:36.000] ok       integrity_ok amsi.dll matches its on-disk copy (no tamper found)
[14:25:36.010] ok       integrity_ok ntdll.dll matches its on-disk copy (no tamper found)

================ WARDEN SUMMARY ================
 Score       : 85 / 100
 Verdict     : MALICIOUS
================================================
```

(The simulator is benign, but it deliberately performs the *suspicious
trinity* — in-memory assembly, RWX+MZ region, dynamic module — so a
MALICIOUS verdict here is **correct tool behaviour**, not a false alarm.
The key negative check: **no** `amsi_tamper` / `etw_tamper` lines.)

Now compare the dump: `dump_01_*_pe.bin` is your fake 8 KB image with the
`MZ` header — check the `.meta.json` sha256 and the `.strings.txt`.

## 2. First look at a suspicious sample

```bat
Warden.exe C:\lab\samples\suspicious.bat
```

Warden wraps it as `cmd.exe /c "..."`, so any `powershell` / `csc`
children the script spawns inherit the profiler env vars — their CLR
loads Warden as the profiler too, giving you managed events **across the
whole chain** even though only the root process was injected.

During the run, triage live:

1. **`clr_present` + `assembly_load` storms** — the chain reached a .NET
   stage. Watch for `inmemory_module`: that is the payload materializing
   from a byte array, exactly what static analysis can't see.
2. **`exec_region` + `dump_saved`** — a manually mapped image. The dump
   is your real sample: open it in your PE tool of choice, or push the
   sha256 to your VT/ATP workflow.
3. **`amsi_tamper` / `etw_tamper` with a `signature`** — the stub
   patched the defence stack *before* loading the payload (the classic
   patch-then-load order). `origBytes → nowBytes` tells you which patch.
4. **`clr_tamper`** — CLR strings patched to break the AMSI integration
   path rather than amsi.dll itself. The `.rdata` diff points at the RVA.
5. **`hidden_image`** — an unlinked module; common for hand-rolled
   loaders that map themselves and unlink from the PEB.

## 3. Post-run triage

```text
%TEMP%\Warden\<session>\
├── report.txt     <- verdict + finding summary (attach to your case)
├── report.json    <- feed to your SIEM / pipeline (rawEvents included)
├── events.jsonl   <- full timeline
├── dumps\         <- PE images + sha256 + strings
└── warden.log     <- narrative log
```

Triage loop:

1. **Verdict + score** from `report.txt`; note which finding classes hit.
2. **Hash every dump** (sha256 is in each `.meta.json` — no re-hashing).
3. **Read `dumps\*.strings.txt`** — config blocks, URLs, mutexes, base64
   blobs usually surface here within seconds.
4. **Correlate timeline**: `amsi_tamper` *before* `inmemory_module` =
   bypass-then-load; the reverse can mean an unprotected first stage.
5. Keep the whole session folder as evidence; zip it with the sample hash
   in the filename.

## 4. Technique comparison mode

Warden's injection modes double as a research instrument:

```bat
Warden.exe --inject classic payload.exe
Warden.exe --inject apc     payload.exe
Warden.exe --inject manual  payload.exe
Warden.exe --no-inject      payload.exe   :: profiler-only
```

* `classic` produces the noisiest baseline (a remote thread exists).
* `apc` runs the monitor before the entry point with no extra threads.
* `manual` never appears in the PEB — the scanner's `hidden_image`
  logic *would* flag the monitor itself, but self-registration keeps it
  quiet; everything else is detected identically, so you can measure how
  samples react to each vector (some stubs check for remote threads).
* `--no-inject` isolates the profiler-only view (managed events only).

## 5. Automation

Exit codes make Warden pipeline-friendly:

```bat
Warden.exe --dir C:\lab\sessions\%SAMPLE% payload.exe
if errorlevel 2 echo MALICIOUS >> triage.txt
if errorlevel 1 echo SUSPICIOUS >> triage.txt
if errorlevel 0 if not errorlevel 1 echo CLEAN >> triage.txt
```

Batch a folder:

```bat
for %%S in (C:\lab\samples\*) do (
    Warden.exe --dir C:\lab\sessions\%%~nS "%%S"
)
```

## 6. House rules that keep results honest

* Revert to snapshot between samples — a previous sample's tampering
  (patched amsi in *that* process is gone with the process, but host
  persistence isn't).
* Run the simulator after every Warden rebuild — it is your regression
  test.
* Treat `integrity_ok` lines as your "defence stack was healthy" proof
  when you write up a case.
* If a sample anti-analyzes Warden (e.g. kills on remote thread), use
  `--inject apc` or `--inject manual`; if it checks `COR_ENABLE_PROFILING`
  (DarkTortilla-style), keep `--no-profiler` runs as a cross-check and
  rely on scanner+hooks.
