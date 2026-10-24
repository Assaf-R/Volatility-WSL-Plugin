# windows.wsl.linux_plugins — analyze a WSL2 guest from a Windows memory image

A Volatility 3 plugin that runs any built-in `linux.*` plugin against the memory
of a **WSL2 guest found inside a Windows memory dump** — no separate Linux
acquisition step.

```bash
python vol.py -f windows.dmp windows.wsl.linux_plugins --linux-plugin pslist
python vol.py -f windows.dmp windows.wsl.linux_plugins --linux-plugin bash --pid 879
python vol.py -f windows.dmp windows.wsl.linux_plugins --linux-plugin sockstat
```

WSL2 runs Linux in a lightweight Hyper-V VM whose entire RAM is owned by one
Windows host process (`vmmemWSL`, or `vmmem` on newer builds). The plugin finds
that process, extracts the guest's RAM to a file, and runs the Linux plugin you
name on it, exactly as if you had run `vol.py -f <guest.dmp> linux.<plugin>`.

`vol.py -h` shows just one extra line (`windows.wsl.linux_plugins`) for the
whole family; `vol.py windows.wsl.linux_plugins -h` lists every Linux plugin you
can pick.

---

## Install

You need Volatility 3 (developed and tested on 2.28.1), Python 3, and a Linux
ISF (symbol file) matching the WSL kernel in your capture.

1. Copy the plugin into your Volatility 3 checkout:
   ```bash
   cp wsl.py <volatility3>/volatility3/framework/plugins/windows/wsl.py
   ```
2. Copy the ISF for your kernel into the symbols directory (two are included,
   for WSL kernels `5.15.167.4` and `6.18.33.2`):
   ```bash
   cp symbols/linux/*.json.xz <volatility3>/volatility3/symbols/linux/
   ```
   For any other kernel, build one — see [Building an ISF](#building-an-isf).
3. Check it is registered:
   ```bash
   python vol.py -h | grep wsl          # -> windows.wsl.linux_plugins
   ```

No other Volatility file is modified.

## Usage

```bash
python vol.py -f mem.dmp windows.wsl.linux_plugins --linux-plugin <name> [options]
```

| Option | Meaning |
|---|---|
| `--linux-plugin NAME` | **Required.** Which Linux plugin to run: `lsmod`, `linux.lsmod`, `pslist`, `linux.ip.Addr`, ... (case-insensitive; a bare name that matches several plugins, like `ip`, lists the choices) |
| *(the chosen plugin's own options)* | e.g. `--pid 879` for `bash`; shown by `-h` once `--linux-plugin bash` is on the command line |
| `--wsl-process NAME` | Host process name to look for (default: `vmmemWSL` and `vmmem`) |
| `--mmio-hole START:SIZE` | Override the detected MMIO-hole layout (e.g. `0xF8000000:0x8000000`), or `none` for no hole. Normally not needed (see *How it works*) |
| `--dump-extra-regions` | Also write the process's other memory spans to separate files |

Every run writes (or reuses) `vmmemwsl.pid<PID>.dmp` in the current directory —
the guest's RAM (about the size of the VM's memory, several GB), plus a small
`vmmemwsl.pid<PID>.dmp.json` recording which Windows image, process and layout it came
from. An existing dump is reused (so chained commands are fast) only if that record
matches the current run exactly; a dump with no record, or made from a different image,
is re-written, so a stale dump can never be mistaken for the current capture. Run from a
directory with enough free disk space.

### Tested results

Against two real captures (WSL2 with kernels 5.15.167.4 and 6.18.33.2):

| Plugin | 5.15.167.4 | 6.18.33.2 |
|---|---|---|
| `pslist`, `psscan`, `pstree` | works | works (finds a live `ping` process) |
| `bash` | works | works |
| `lsof`, `sockstat`, `ip.Addr` | works | works |
| `lsmod` | empty (that kernel has no modules) | works |
| `kthreads`, `netfilter` | works | works |

Other guest sizes (kernel 6.18.33.2):

| Capture | Guest RAM | Layout detected | Result |
|---|---|---|---|
| WSL up ~8 minutes | 2 GiB | one RAM VAD, no hole (e820 confirmed) | `pslist`, `psscan`, `lsmod`, `bash`, `lsof`, `sockstat`, `ip.Addr`, `kthreads`, `netfilter`, `pstree` all return data |
| WSL up ~9 hours, idle | 6 GiB | two RAM VADs, hole at `0xF8000000` (e820 confirmed) | layout correct, but list-walking plugins are truncated because Windows had paged part of the guest out (see Limitations) |
| WSL up a few minutes, `memory=4GB` | ~3.9 GiB + 128 MiB | low and high RAM VADs, the high one *below* the low one in host memory (not adjacent); hole at `0xF8000000` (e820 confirmed) | all seven plugins tried return data (`pslist` 277, `psscan` 587, `bash` 656, `lsof` 2,286, `sockstat` 550, `lsmod` 23, `ip.Addr` 6) |
| WSL up a few minutes, VMware Workstation also running | 6 GiB | two RAM VADs, hole at `0xF8000000` (e820 confirmed); one `vmmem`-type candidate (VMware's VM is `vmware-vmx.exe`, not `vmmem`) | `pslist` 133 tasks (kernel threads only), `lsmod` 29, `lsof` 16, `psscan` 582; `bash`, `sockstat`, `ip.Addr` empty: same paged-out-pages limitation |

Other `linux.*` plugins are exposed too but were not individually tested.

## How it works

1. **Find the host process.** Walk the Windows process list for `vmmemWSL`/`vmmem`.
   A recently exited instance can linger with no memory; such candidates are
   skipped with a warning and the next one is tried. `vmmemWSL` is tried before plain
   `vmmem` (which other lightweight VMs also use), and a process whose memory turns out
   not to be an analysable Linux guest (no matching ISF, or not Linux at all) is skipped
   in favour of the next.
2. **Extract guest RAM.** The guest's RAM is a few of that process's VADs: a low
   block, and above 4 GiB a high block. They are chosen by what they are (committed
   pages, the 3-4 GiB low block first), *not* by being next to each other in host
   memory, and streamed to disk in guest-physical order. The guest's
   physical address map has an MMIO (device) hole below 4 GiB that the host
   doesn't map, so the plugin re-inserts it as zeros. That makes *file offset ==
   guest-physical address*, which is what the Linux page-table code expects.
   (Without it, everything above 4 GiB is read from the wrong place and every
   plugin except `psscan` returns nothing.) The hole is **detected, not
   assumed**: Hyper-V's worker allocates the low-RAM block and the high-RAM block
   as two separate VADs, so the low VAD's size is where the hole starts and the
   high block resumes at 4 GiB (on the tested guests: hole `0xF8000000–0x100000000`,
   128 MiB). The result is then cross-checked against the guest kernel's own
   `BIOS-e820` boot-log lines found in the dump, and the plugin warns if they
   disagree. Use `--mmio-hole` to override.
3. **Run the Linux plugin.** A second, independent Volatility context is created
   on the dump and the chosen plugin is constructed through the normal
   automagic path, so kernel/ISF matching, KASLR and page-table discovery behave
   as for any Linux image.

See [docs/CODE_GUIDE.md](docs/CODE_GUIDE.md) for the code walkthrough and the
memory-layer background.

## Building an ISF

Volatility needs an ISF whose **symbol addresses and struct layouts match the
exact kernel binary in the capture**. Microsoft's kernel ships without debug
info, so the recipe rebuilds the same source with debug info to get types, then
takes addresses from the real kernel.

1. Get the exact kernel banner from your capture (or `uname -a` inside WSL):
   ```bash
   grep -a -o "Linux version [^\"]\{1,120\}" vmmemwsl.pid<PID>.dmp | sort -u
   ```
2. Clone the matching source **onto WSL's own Linux filesystem, not `/mnt/c`**
   (the tree has files differing only by case, which a case-insensitive
   filesystem corrupts):
   ```bash
   git clone --depth 1 --branch linux-msft-wsl-<version> \
       https://github.com/microsoft/WSL2-Linux-Kernel.git ~/wsl2-kernel-build
   ```
3. Build a debug-info `vmlinux`:
   ```bash
   cp tools/build_wsl2_vmlinux.sh ~/wsl2-kernel-build/ && cd ~/wsl2-kernel-build
   bash build_wsl2_vmlinux.sh
   ```
4. Convert with [dwarf2json](https://github.com/volatilityfoundation/dwarf2json)
   and patch the banner (Volatility matches ISFs by the exact `linux_banner`
   bytes, which a local rebuild can't reproduce):
   ```bash
   dwarf2json linux --elf vmlinux > kernel.json
   python3 - <<'EOF'
   import json, base64
   banner = b"<exact banner from step 1>\n\x00"
   d = json.load(open("kernel.json"))
   d["symbols"]["linux_banner"]["constant_data"] = base64.b64encode(banner).decode()
   d["symbols"]["linux_banner"]["type"]["count"] = len(banner)
   json.dump(d, open("kernel.json", "w"))
   EOF
   xz -9 kernel.json
   ```
5. **Validate against the guest's own kernel data.** The running kernel lists its
   real symbol addresses in a VMCOREINFO note in RAM:
   ```bash
   python tools/vmcoreinfo_vs_isf.py --dump vmmemwsl.pid<PID>.dmp --isf kernel.json.xz
   ```
   All compared symbols should say `yes`. (The 5.15.167.4 ISF matched as built.)
6. **If any differ**, your compiler differs from Microsoft's and symbols moved.
   Take the addresses from the deployed kernel (`C:\Program Files\WSL\tools\kernel`
   on the host), keeping the rebuilt types:
   ```bash
   pip install vmlinux-to-elf
   vmlinux-to-elf /mnt/c/Program\ Files/WSL/tools/kernel deployed.elf
   nm deployed.elf > deployed_symbols.nm
   python tools/patch_isf_addresses.py --isf-in kernel.json.xz \
       --nm-file deployed_symbols.nm --isf-out kernel-patched.json.xz
   python tools/vmcoreinfo_vs_isf.py --dump vmmemwsl.pid<PID>.dmp --isf kernel-patched.json.xz
   ```
   (The 6.18.33.2 ISF needed this step; it went from 4 to 13 of 13 matching.)
7. Install the result as `<volatility3>/volatility3/symbols/linux/<name>.json.xz`.

## Limitations

- Needs a matching ISF per WSL kernel version; only 5.15.167.4 and 6.18.33.2 are supplied.
- The MMIO hole is detected from the Windows VAD layout (and checked against the
  guest's e820 map), assuming the high-RAM block resumes at 4 GiB. Tested on
  15.5, 6 and 4 GiB guests (two RAM VADs, hole; in the 4 GiB one the blocks were not
  adjacent in host memory) and a 2 GiB guest (one RAM VAD, no hole); other sizes use the same logic but are untested. If the layout can't be derived from the VADs the
  plugin falls back to the usual 128 MiB at `0xF8000000` and says so. The e820
  check is skipped when an existing dump is reused, and finds nothing if the
  guest's boot log has been overwritten.
- Only tested on x86-64 WSL2, kernels 5.15.167.4 and 6.18.33.2, with four
  captures from one machine (15.5 GiB on both kernels, 6 GiB, 2 GiB); other
  Windows builds or `.wslconfig` settings may behave differently.
- **Pages Windows has paged out are missing from the dump.** Two kinds of page
  read as zeros: *never-touched* guest RAM (harmless, and most of a large idle
  guest), and pages Windows *trimmed to the pagefile*, which are real guest data
  that is simply not in a RAM image. In freshly started guests the paged-out share
  was ~0%, but on a 6 GiB guest that had sat idle for 9 hours about 22% of the
  sampled pages were paged out. That cut `pslist` to 11 tasks, because the walk
  stops at the first unreadable page (PID 1's `task_struct` was one), while
  `psscan`, which scans physical memory and follows no pointers, still found 394.
  Long idleness is not the only cause: a 6 GiB guest started minutes earlier but
  captured while VMware Workstation was also running on the host (memory pressure)
  had ~5% of sampled pages paged out and ~2% in other non-resident states. That was
  enough to stop the task-list walk after the 134 kernel threads (a guest page-table
  page was unreadable), so no user process such as `bash` was reached, `bash` and
  `sockstat` returned nothing, and `ip.Addr` was empty, while `psscan` still found
  582 tasks including five `bash` processes.
  The plugin does not currently warn about this. Take the capture soon after the
  WSL activity you care about, and compare against `psscan` when `pslist` looks
  short. Volatility can read paged-out pages back from the paging file(s) via its
  `--single-swap-locations` option; this has **not** been tested with this plugin.
- The Linux plugin's own options are exposed by reading `sys.argv`, so they work
  from the `vol.py` command line, not when the plugin is driven from a script.

## Repository layout

```
wsl.py                         the plugin
tools/build_wsl2_vmlinux.sh    build a debug-info WSL2 kernel (self-healing)
tools/vmcoreinfo_vs_isf.py     validate an ISF against a guest's VMCOREINFO
tools/patch_isf_addresses.py   fix ISF symbol addresses from the deployed kernel
symbols/linux/*.json.xz        ISFs for WSL kernels 5.15.167.4 and 6.18.33.2
docs/CODE_GUIDE.md             how the code works + memory-layer background
```

License: Volatility Software License 1.0 (see the header of `wsl.py`).
