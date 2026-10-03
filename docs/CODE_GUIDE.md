# Code guide

How `wsl.py` works, how the ISF tooling fits in, and the memory-layer background
you need to follow either. Usage and install are in [../README.md](../README.md).

---

## 1. `wsl.py`

One file, one plugin: `windows.wsl.linux_plugins`. Volatility names a plugin
`module.__name__ + "." + class.__name__` (with `volatility3.plugins.` stripped),
so the class `linux_plugins` in `windows/wsl.py` becomes `windows.wsl.linux_plugins`.
The Linux plugin to run is chosen with `--linux-plugin`, not by a separate class,
so `vol.py -h` shows a single entry for the whole family.

### 1.1 Module-level helpers

| Function | Purpose |
|---|---|
| `_linux_plugin_table()` | `{"pslist.PsList": cls, ...}` for every non-hidden `linux.*` plugin, from `framework.list_plugins()` (nested packages such as `linux.malware.*` included). Computed on demand, so it always reflects what is installed. |
| `_resolve_linux_plugin(name)` | Maps user text to a class. Accepts `linux.ip.Addr`, `ip.Addr`, or a bare module name (`lsmod`, `linux.lsmod`) when the module holds exactly one plugin. Ambiguous (`ip`) or unknown names raise an error that lists the candidates. Case-insensitive. |
| `_linux_plugin_name_from_argv()` | Reads `--linux-plugin X` / `--linux-plugin=X` from `sys.argv`. See §1.2. |

Constants: `WSL_PROCESS_NAMES` (`vmmemwsl`, `vmmem`), `_DUMP_CHUNK_SIZE` (10 MB),
and `_GUEST_MMIO_HOLE_START/_SIZE` (`0xF8000000`, 128 MiB; see §1.4).

### 1.2 `get_requirements()`

Every Volatility plugin declares its options here and the CLI turns each into an
argparse flag:

1. `kernel` — the Windows kernel module (used to walk the process list).
2. `linux_plugin` — the selector (`--linux-plugin`). Its help text lists every
   available Linux plugin, so `windows.wsl.linux_plugins -h` is where you
   discover them.
3. `wsl_process` — optional process-name override.
4. `dump_extra_regions` — optional flag to also write the non-RAM spans.
5. The chosen Linux plugin's own requirements (e.g. `--pid` for `bash`), except
   its `kernel` requirement, which the plugin satisfies itself from the dump.

Volatility builds all argparse options *before* parsing the command line, so the
class cannot yet know which Linux plugin was chosen. `_linux_plugin_name_from_argv()`
therefore peeks at `sys.argv`; if it finds a resolvable name, that plugin's options
are appended. Limitation: this works from the `vol.py` command line only. A caller
that builds the configuration programmatically must set the Linux plugin's options
itself.

### 1.3 `run()`

1. Resolve `--linux-plugin`. A missing, unknown or ambiguous name is logged with
   `vollog.error` and re-raised (Volatility prints only a generic "unexpected
   situation" for a bare `PluginRequirementException`).
2. `_find_wsl_candidates()` — every process named `vmmemWSL`/`vmmem`. A
   recently-exited instance can still sit in the process list with an empty VAD
   tree, so all matches are returned, not just the first.
3. For each candidate in turn, `_dump_guest_memory()`. A candidate with no usable
   memory is skipped with a warning; if none work, a descriptive error is raised.
4. `_run_linux_plugin(dump_path)` on the first candidate that dumped.

### 1.4 `_dump_guest_memory()` and `_dump_span()`

**One VAD is not the guest.** `vmmemWSL` has several VADs, and the low part of
guest RAM can sit in a *smaller* VAD than the biggest one. So the VADs are sorted
by start address, every run where one VAD's end + 1 equals the next VAD's start is
merged into a span, and the largest **span** is dumped:

```python
for vad in sorted(vads, key=lambda v: v.get_start()):
    if spans and spans[-1][1] + 1 == vad.get_start():
        spans[-1][1] = vad.get_end()          # extend the current span
    else:
        spans.append([vad.get_start(), vad.get_end(), [vad]])
```

Host-VA adjacency ties the VADs together as one physical range; an unrelated big
allocation elsewhere in the process won't sit exactly end to end with guest RAM.

**The MMIO hole.** Page tables contain *guest-physical* addresses and Volatility's
Intel layer reads the physical layer at that offset, so the dump must be laid out
by guest-physical address. The guest's map is RAM at `0 .. 0xF8000000`, a 128 MiB
device hole, then RAM again from `0x100000000`. The host maps only the RAM, back to
back, so above 4 GiB the span is 128 MiB "short". `_dump_span(insert_mmio_hole=True)`
writes 128 MiB of zeros at `0xF8000000`, restoring *file offset == guest-physical
address*. This was measured, not assumed: a guest page-directory page at
guest-physical `0x1012b7000` was found in the span at `0xF92B7000`
(= gpa − `0x8000000`) and contained valid direct-map entries. Without the hole,
every page-table walk above 4 GiB reads the wrong page (zeros) and every plugin
that translates virtual addresses returns nothing, while `psscan` — which never
translates — still works.

**Dump reuse.** `vmmemwsl.pid<PID>.dmp` is many GB. If a file with that name
already exists *and* its size equals what would be written now (span size plus the
hole), it is reused. Checking the size means a stale or partial file is never
silently reused.

**Streaming.** The write loop reads 10 MB at a time with
`proc_layer.read(offset, size, pad=True)`, so memory use is flat whatever the guest
size; `pad=True` zero-fills unmapped pages instead of aborting (the same convention
as `windows.vadinfo`/`windows.memmap --dump`). The plugin writes to a path it
chooses with a plain `open()` rather than Volatility's `self.open()`, because it
needs the real filesystem path a moment later to point a new context at the file.

### 1.5 `_run_linux_plugin()`

Creates a **second, independent** `contexts.Context()` whose physical layer is the
dump, then follows the same sequence the CLI performs for `-f <file> <plugin>`:

```python
linux_ctx.config["automagic.LayerStacker.single_location"] = \
    requirements.URIRequirement.location_from_file(dump_path)
chosen = automagic.choose_automagic(automagic.available(linux_ctx), target_cls)
linux_ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(target_cls)
plugin = plugins.construct_plugin(linux_ctx, chosen, target_cls, "plugins", ...)
```

Values the user gave for the Linux plugin's own options are copied into the new
context at the config path that plugin expects. Because this *is* the normal
automagic path, banner-to-ISF matching, KASLR and page-table (DTB) discovery behave
exactly as for any Linux image. An unsatisfied requirement (typically no matching
ISF) is logged with a hint to check `symbols/linux/`, then re-raised.

---

## 2. ISF tooling

An ISF (Intermediate Symbol File) tells Volatility a kernel's **struct layouts**
(types) and **symbol addresses**. Volatility picks the ISF whose `linux_banner`
bytes exactly match the image. Both parts must match the *deployed* binary, and a
locally rebuilt kernel does not guarantee that.

### 2.1 `tools/build_wsl2_vmlinux.sh`

Builds a debug-info `vmlinux` from Microsoft's `WSL2-Linux-Kernel` tree
(dwarf2json needs DWARF, which the shipped kernel lacks). It starts from
Microsoft's `config-wsl`, turns on `CONFIG_DEBUG_INFO`, disables `-Werror`, then
retries the build up to 15 times, healing two failure classes from the log:

- **`No rule to make target`** for an object — comment that object out of its Makefile.
- **A compile error in a legacy netfilter file** (`net/*/netfilter/{ipt,ip6t,xt}_*.c`)
  — find the guarding `CONFIG_` symbol in that directory's Makefile and disable it
  with `scripts/config` instead of patching source. Disabled symbols are recorded
  in `kconfig-disables.txt` and re-applied on every run (the script always restarts
  from the clean base config).

**Build on a native Linux filesystem.** The tree contains files that differ only by
case (`ipt_ECN.h` / `ipt_ecn.h`). On a case-insensitive mount (`/mnt/c`) git
silently collapses them, causing a real compile error and, if "fixed" by disabling
that option, a kernel that is no longer code-identical to the deployed one.

### 2.2 `tools/vmcoreinfo_vs_isf.py`

A running Linux kernel publishes a VMCOREINFO note in RAM (starts with
`OSRELEASE=`) listing real runtime symbol addresses and `KERNELOFFSET`. For a
correct ISF, `runtime address − KERNELOFFSET == ISF address`. The script finds the
note in a dump, compares every symbol it shares with the ISF, and exits non-zero on
any mismatch. Values outside the kernel-text range (e.g. `mem_section`, a heap
pointer) are skipped. This is the ground truth check for any new ISF.

### 2.3 `tools/patch_isf_addresses.py`

Why a rebuilt ISF can be wrong: for 6.18.33.2 the local rebuild (gcc 11.4 /
binutils 2.38) laid the kernel out differently from Microsoft's (gcc 13.2 /
binutils 2.41), so every symbol address was off — `fair_sched_class`, `init_task`
and the rest — and even `psscan` found nothing. (For 5.15.167.4 the layouts
happened to be identical.) The script keeps the rebuilt ISF's types and replaces
each symbol's `address` with the deployed kernel's, matched by name. Symbols whose
name occurs more than once in the deployed kernel are left alone, so a duplicated
static can never be pointed at the wrong copy. The deployed kernel's symbols come
from `vmlinux-to-elf` (recovers the embedded kallsyms) + `nm`.

Banner patching (README step 4) is separate: the banner embeds build host,
compiler and timestamp, which a rebuild can never reproduce. Patching it only
affects ISF *selection*; layout and addresses are governed by the steps above.

---

## 3. Memory-layer background

### 3.1 Layers

A Volatility layer implements `read(offset, length)`; what differs is what
"offset" means.

- A **physical layer** (`FileLayer`) treats a raw dump as stored: offset is the
  physical address.
- A **translation layer** (`Intel32e`, ...) sits on a physical layer and turns a
  *virtual* address into a physical one before reading — the same 4-level x86-64
  page walk (PML4 → PDPT → PD → PT) the CPU's MMU does, in software. It needs one
  input beyond the layer below it: the physical address of the top-level table,
  the **DTB** (what the CPU loads into `CR3`), called `page_map_offset`.

Any plugin that follows a pointer (walk `init_task`'s task list, read a module
list) ends up as "translate this virtual address, then read the physical layer".
So if a physical page the walk needs is at the wrong offset in the file, that
pointer fails. This is exactly what the missing MMIO hole caused (§1.4).

### 3.2 How Linux's DTB and KASLR shift are found

`LinuxIntelStacker` scans the physical layer for the bytes of `swapper`'s (PID 0)
`comm`, validates the hit as `init_task` (`pid == 0`, `state == 0`), then derives:

- **`aslr_shift`** — virtual-side KASLR: runtime `init_task->files` versus the ISF's
  `init_files` symbol address.
- **`kaslr_shift`** — physical-side KASLR: where `init_task` was actually found
  versus where the ISF address maps under the fixed (non-KASLR) formula
  `addr − 0xFFFFFFFF80000000`.

The DTB is `virtual_to_physical_address(init_top_pgt + kaslr_shift)`. This is why
ISF symbol *addresses* matter so much: a wrong `init_files` address makes the whole
chain compute a plausible but meaningless number.

### 3.3 Symbol addresses come back masked

`symbol_space.get_symbol(...).address` and `module.get_symbol()` return addresses
masked to 48 bits (`0xffff82e13940`), while the ISF file stores the sign-extended
form (`0xffffffff82e13940`). OR in `0xFFFF000000000000` when bit 47 is set before
comparing them by hand.

### 3.4 Two linear regions, two KASLR bases

x86-64 Linux has a **kernel-text mapping** (`0xffffffff8...`, where `init_task` and
other static symbols live) and a **direct map / physmap** (where slab-allocated
objects such as every `task_struct` live). Both are `virtual = physical + constant`,
but the physmap base is randomized separately (`CONFIG_RANDOMIZE_MEMORY`; e.g.
`0xffff8bb700000000` on one boot). A pointer such as `init_task.tasks.next` is a
physmap address, which is why the first pointer hop is where a wrong physical
layout shows up.

### 3.5 Why `psscan` is the canary

`linux.psscan` scans the *physical* layer for the address of scheduler-class
symbols (`fair_sched_class`, ...) and builds `task_struct` objects directly on the
physical layer. No pointer chasing means no translation. That makes it the fastest
sanity check of a new ISF: if psscan finds processes the ISF's addresses are right;
if `psscan` works but `pslist` is empty, suspect the dump layout (the MMIO hole)
or a page-table problem instead.

### 3.6 The Windows side

The outer context works the same way in miniature: `proc.add_process_layer()` builds
a translation layer over the Windows physical layer using that `EPROCESS`'s own DTB
(found by Windows' self-referential-PML4 automagic), and the VADs live inside that
address space. `_dump_guest_memory()` reads through it to pull guest RAM into a
flat file, which becomes the physical layer of the second, Linux-side context. Two
independent layer stacks are chained only by a file on disk.

Most of a large guest's span shows as never-mapped (zero PTE) in Windows — unused
guest RAM that was never touched or was returned to the host. That is normal and
does not affect in-use kernel structures.
