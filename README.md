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
| `--dump-extra-regions` | Also write the process's other memory spans to separate files |

Every run writes (or reuses) `vmmemwsl.pid<PID>.dmp` in the current directory —
the guest's RAM (about the size of the VM's memory, several GB). If a file for
the same PID and size already exists it is reused, so chained commands are fast.
Run from a directory with enough free disk space.

### Tested results

Against two real captures (WSL2 with kernels 5.15.167.4 and 6.18.33.2):

| Plugin | 5.15.167.4 | 6.18.33.2 |
|---|---|---|
| `pslist`, `psscan`, `pstree` | works | works (finds a live `ping` process) |
| `bash` | works | works |
| `lsof`, `sockstat`, `ip.Addr` | works | works |
| `lsmod` | empty (that kernel has no modules) | works |
| `kthreads`, `netfilter` | works | works |

Other `linux.*` plugins are exposed too but were not individually tested.

## How it works

1. **Find the host process.** Walk the Windows process list for `vmmemWSL`/`vmmem`.
   A recently exited instance can linger with no memory; such candidates are
   skipped with a warning and the next one is tried.
2. **Extract guest RAM.** The guest's RAM is a run of adjacent VADs in that
   process; they are merged and the largest run is streamed to disk. The guest
   physical address map has a 128 MiB device hole below 4 GiB
   (`0xF8000000–0x100000000`) that the host doesn't map, so the plugin re-inserts
   it as zeros. That makes *file offset == guest-physical address*, which is what
   the Linux page-table code expects. (Without it, everything above 4 GiB is read
   from the wrong place and every plugin except `psscan` returns nothing.)
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
- The 128 MiB hole position/size is a fixed constant, correct for the captures
  tested. Guests with less than ~3.9 GiB RAM have no memory above the hole and
  are left untouched.
- Only tested on x86-64 WSL2 with two captures; other Windows builds or
  `.wslconfig` memory settings may behave differently.
- Pages Windows never mapped in the host process appear as zeros in the dump;
  most of a large guest's unused RAM is like this and is harmless, but a
  structure that lives in such a page will be unreadable.
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
