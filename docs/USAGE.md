# Warden — Usage Reference

Complete CLI, environment, event and artifact reference.

## Command line

```
Warden.exe [options] <target.exe|.bat|.cmd|.ps1> [-- target args...]
```

Everything after the first positional argument is forwarded to the target;
the `--` separator makes that explicit (recommended for PowerShell-style
switches).

| Option | Default | Meaning |
|---|---|---|
| `--inject <classic\|apc\|manual>` | `classic` | Injection technique used to place `Warden.dll` into the suspended target. `classic` = `VirtualAllocEx` + `CreateRemoteThread(LoadLibraryW)`. `apc` = DLL pre-loaded while suspended, `InitWarden` queued as a user APC so it runs *before* the target entry point. `manual` = out-of-process PE mapping (relocations, remote-PEB import resolution) — the monitor never appears in the target PEB, which Warden's own scanner handles via self-registration. |
| `--no-inject` | off | Profiler-only mode: no injection; the monitor enters through CLR env vars. Use for pure .NET targets or when comparing injection techniques. |
| `--no-profiler` | off | Do not set `COR_*` / `CORECLR_*` variables (isolates hook+scanner layers). |
| `--no-hooks` | off | Monitor runs without inline API hooks (scanner + integrity only). |
| `--no-dump` | off | Findings are reported but PE images are not written to disk. |
| `--scan-ms <N>` | `1500` | Scanner interval in ms (integrity runs at 2×). Range 100–60000. |
| `--dir <PATH>` | `%TEMP%\Warden\<ts>_p<pid>` | Session directory override. |
| `--dll <PATH>` | `<exedir>\Warden.dll` | Monitor DLL path override. |
| `--quiet` | off | Reserved for future live-echo suppression. |
| `--verbose` | off | Extra telemetry (`module_load` per disk module, `module_attached`, hook events at info level). |
| `--help` | | Usage text. |

### Target resolution

| Input | Launch command |
|---|---|
| `.exe` | `<target> <args>` |
| `.bat` / `.cmd` | `cmd.exe /c "<target>" <args>` |
| `.ps1` | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<target>" <args>` |

The target always starts with `CREATE_SUSPENDED`, is injected, receives
`READY` confirmation from the monitor, and only then is resumed — so no
instruction of the sample runs unobserved.

## Exit codes

| Code | Verdict | Meaning |
|---|---|---|
| `0` | CLEAN | score `< 25` |
| `1` | SUSPICIOUS | score `25–59` |
| `2` | MALICIOUS | score `>= 60` |
| `3` | — | bad arguments / missing files / WoW64 target |

## Environment variables (launcher → monitor)

| Variable | Purpose |
|---|---|
| `WARDEN_PIPE` | named pipe for the live event feed |
| `WARDEN_DIR` | session directory |
| `WARDEN_FLAGS` | capability bitmask (`1` dump, `2` hooks, `4` integrity, `8` verbose) |
| `WARDEN_SCANMS` | scanner interval |
| `COR_ENABLE_PROFILING=1`, `COR_PROFILER={CLSID}`, `COR_PROFILER_PATH_64=<dll>` | registry-free CLR profiler activation (.NET Framework 4.x) |
| `CORECLR_ENABLE_PROFILING`, `CORECLR_PROFILER`, `CORECLR_PROFILER_PATH_64` | same, best-effort for .NET Core/5+ |

## Event stream

One JSON object per line (`events.jsonl`, and live through the pipe):

```json
{"ts":"14:25:31.204","pid":8152,"ev":"inmemory_module","sev":"crit",
 "w":25,"dedup":"loadsim","data":{"name":"loadsim","kind":"in-memory",
 "imageBase":"0"},"msg":"loadsim"}
```

| `ev` | `sev` | `w` | Trigger |
|---|---|---:|---|
| `ready` | ok | 0 | monitor initialized (pipe handshake) |
| `profiler_init` | ok | 0 | CLR loaded the profiler |
| `clr_present` | info | 0 | `clr.dll` / `coreclr.dll` / `clrjit.dll` seen |
| `assembly_load` | info | 0 | CLR `AssemblyLoadStarted` (name in `data.name`) |
| `inmemory_module` | crit | 25 | CLR module with `imageBase == 0` → `Assembly.Load(byte[])` |
| `dynamic_module` | warn | 25 | `COR_PRF_MODULE_DYNAMIC` → Reflection.Emit |
| `exec_region` | crit | 30 | `MEM_PRIVATE` + `PAGE_EXECUTE*` containing a valid PE header |
| `shellcode_region` | warn | 15 | executable private region, entropy > 6.8 bits/byte, no MZ |
| `hidden_image` | crit | 35 | `MEM_IMAGE` region absent from the PEB module list |
| `dump_saved` | ok | 0 | image written to `dumps\` (+ sha256 in `data`) |
| `amsi_tamper` | crit | 50 | `amsi.dll` bytes differ from disk (function or `.text`) |
| `etw_tamper` | crit | 50 | `ntdll!EtwEventWrite*` / ntdll `.text` differs from disk |
| `clr_tamper` | crit | 30 | `clr.dll` `.rdata` differs from disk (patched strings) |
| `bypass_sig` | warn | 10 | bytes match a known bypass pattern (`mov eax,0x80070057…`, `xor eax,eax; ret`, `ret`) |
| `valloc_exec` | warn | 5 | `VirtualAlloc` committed RWX memory |
| `vprotect_exec` | warn | 10 | `VirtualProtect` raised protection to executable |
| `ldr_load` / `loadlib` | debug | 0 | module load telemetry (first time per name) |
| `childproc` | info | 5 | `CreateProcessW` success observed in the target |
| `hook_installed` / `hook_skip` | info/debug | 0 | hook engine status per API |
| `integrity_ok` | ok | 0 | module matched disk on first pass |
| `done` | info | 0 | target exited, monitor flushed |

## Reports

* `report.json` — `score`, `verdict`, `findings[]` (per event kind: count,
  maxWeight, firstMsg), full `rawEvents[]` transcript.
* `report.txt` — analyst summary with the same numbers plus artifact paths.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `monitor not ready in time` | DLL injection failed or the pipe name collided; check `warden.log` in the session dir. Profiler-only mode allows 20 s. |
| No CLR events on a .NET sample | Another `COR_ENABLE_PROFILING=1` env template is active, or the target is .NET Core (see README limitations). Verify with `clr_present` in the feed. |
| `hook_skip` for every API | Prologues on your build use encodings the conservative LDE refuses (e.g. exotic hotpatch prefixes). Analysis continues via scanner+integrity+profiler. |
| Dumps missing but `exec_region` fired | `--no-dump` was passed, or region vanished between detection and copy, or the 96-dump cap was hit. |
| amsi/ntdll tamper in a *clean* VM | Another security tool (or your own EDR testing tool) patched those modules — Warden reports memory-vs-disk truthfully. Base your triage on the `origBytes`/`nowBytes` fields. |
| Target exits instantly | The sample may check for a parent/console; try `--inject apc` (no remote thread) or run under your VM's debugger conventions. |
