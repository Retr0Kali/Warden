<div align="center">



<p align="center">
  <img src="assets/warden-team.png" alt="Warden — .NET malware analysis war room" width="720"/>
</p>


# Warden


> **x64 .NET runtime sentinel for malware analysts** — catch reflective .NET
> payloads as they materialize in memory, dump them, and verify the integrity
> of the defence stack (AMSI / ETW / CLR) while the sample runs.

![platform](https://img.shields.io/badge/platform-Windows%20x64-blue)
![lang](https://img.shields.io/badge/lang-C%2FC%2B%2B-informational)
![license](https://img.shields.io/badge/license-MIT-green)
![ci](https://github.com/Retr0Kali/Warden/actions/workflows/build.yml/badge.svg)

</div>



---

## What it does

Warden watches a suspicious process from *before its first instruction* and
reports everything a staged loader chain (`.bat → powershell → csharp
stub → payload`) tries to hide:

| Layer | Technique | Findings |
|---|---|---|
| **CLR Profiler API** | registry-free `COR_PROFILER` (documented, version-stable) | `assembly_load`, `inmemory_module` (base==0 → `Assembly.Load(byte[])`), `dynamic_module` (Reflection.Emit) |
| **Memory scanner** | periodic `VirtualQuery` walk | `exec_region` (private MZ images → **dumped**), `shellcode_region` (high-entropy exec), `hidden_image` (MEM_IMAGE missing from PEB) |
| **Integrity engine** | live-vs-disk differential with ASLR-reloc + self-hook exclusion | `amsi_tamper`, `etw_tamper`, `clr_tamper` (patched strings), known bypass byte-signature classification |
| **API telemetry** | conservative inline hooks with graceful skip | `ldr_load`, `loadlib`, `valloc_exec` (RWX), `vprotect_exec`, `childproc` |
| **Threat scoring** | weighted finding aggregation | 0–100 score, CLEAN / SUSPICIOUS / MALICIOUS verdict, scriptable exit codes |

**Dumps** land in `%TEMP%\Warden\<session>\dumps\` as raw PE images with a
`sha256` sidecar (`.meta.json`) and quick-triage `strings.txt`.

## Why Warden

Most runtime analysis of reflective .NET payloads relies on undocumented CLR
internals or assembly-level detours that break on every Windows update.
Warden takes a deliberately conservative, version-stable approach and layers
independent engines on top of it:

| Design choice | How Warden does it |
|---|---|
| .NET event source | **documented CLR Profiler API** + memory scanner (no version-specific asm, survives CLR servicing) |
| In-memory load proof | `ModuleLoadFinished` with `base == 0` + PEB-hidden image detection |
| Tamper checks | amsi/ntdll/clr live-vs-disk diff **with ASLR-reloc-aware skip sets** + known bypass byte-signature classification |
| Injection | classic + **early-APC** + **manual-map** (remote PEB walk, import resolution, relocations) |
| Verdict | **0–100 threat score, CLEAN/SUSPICIOUS/MALICIOUS, exit codes for automation** |
| Output | console (VT colors) + `events.jsonl` + `warden.log` + `report.json` + `report.txt` |
| CI | GitHub Actions builds binaries on every push |

## Quick start

**Build** (Visual Studio 2022, "x64 Native Tools Command Prompt"):

```bat
git clone https://github.com/Retr0Kali/Warden.git
cd Warden
build.bat
```

or just push — **GitHub Actions** compiles `Warden.exe`, `Warden.dll` and
`LoadSim.exe` on every push and publishes them as artifacts.

**Verify the install** against the included benign simulator:

```bat
bin\Warden.exe bin\LoadSim.exe
```

**Expected findings:** `inmemory_module`, `dynamic_module`, `exec_region` +
`dump_saved`, `valloc_exec`, `vprotect_exec`, `childproc` — and **zero**
`amsi_tamper` / `etw_tamper` findings. With default weights the score lands in
the MALICIOUS band (the simulator deliberately mimics loader behaviour), so
the real PASS criteria are: all seven event kinds fired, the tamper checks
stayed silent, and `report.json` contains the full event transcript — proving
every detection layer works without false positives.

**Analyze a suspicious chain:**

```bat
Warden.exe suspicious.bat
Warden.exe --inject manual payload.exe
Warden.exe --scan-ms 500 report.ps1 -- -NoExit
```

## Output layout

```
%TEMP%\Warden\
└── 20261023_142530_p1234\
    ├── dumps\
    │   ├── dump_01_7ff6a3f10000_pe.bin         <- reflective payload image
    │   ├── dump_01_7ff6a3f10000_pe.meta.json   <- sha256, entropy, base
    │   └── dump_01_7ff6a3f10000_pe.strings.txt <- quick IOC triage
    ├── events.jsonl      <- machine-readable event stream
    ├── warden.log        <- human-readable log
    ├── report.json       <- final report (score, verdict, findings, raw events)
    └── report.txt        <- analyst summary
```

## Scoring

| Finding | Weight |
|---|---:|
| `amsi_tamper` / `etw_tamper` | +50 |
| `hidden_image` | +35 |
| `exec_region` (private MZ) | +30 |
| `clr_tamper` (patched CLR strings) | +30 |
| `inmemory_module` / `dynamic_module` | +25 |
| `shellcode_region` | +15 |
| `bypass_sig` (known patch bytes) | +10 |
| `vprotect_exec` | +10 |
| `childproc` | +5 |
| `valloc_exec` | +5 |

Verdict: `>= 60` → **MALICIOUS**, `>= 25` → **SUSPICIOUS**, else **CLEAN**.
Exit codes: `0` clean · `1` suspicious · `2` malicious · `3` error.

## Docs

* [`docs/USAGE.md`](docs/USAGE.md) — every flag, event schema, troubleshooting
* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — engine internals, hook/LDE design, integrity math
* [`docs/ANALYSIS-WORKFLOW.md`](docs/ANALYSIS-WORKFLOW.md) — lab playbook, triage flow, simulator walkthrough

## Limitations

* x64 targets only (WoW64 processes are rejected loudly).
* The CLR Profiler layer targets **.NET Framework 4.x** (the ecosystem most
  reflective loaders use); `.NET Core / 5+` processes are still covered by the scanner +
  integrity + hook layers, and CoreCLR profiler vars are set best-effort.
* Inline hooks are best-effort: unsupported prologues are skipped, never
  forced (see ARCHITECTURE.md).
* Warden's own `LdrLoadDll` hook is transparently excluded from integrity
  checks; other EDR/tooling hooks on the box *will* be reported as tamper —
  that is correct behaviour in a clean lab VM.

## License

* MIT — see [LICENSE](LICENSE). Use responsibly.
