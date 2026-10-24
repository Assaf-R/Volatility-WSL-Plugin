# This file is Copyright 2026 and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""windows.wsl.linux_plugins - run ANY linux.* plugin against the WSL2 guest inside a Windows image.

WSL2 runs its Linux guest as a lightweight Hyper-V VM whose entire physical RAM
lives inside one Windows host process ("vmmemWSL", or plain "vmmem" on newer
builds). This plugin finds that process in a Windows memory image, dumps the
guest's RAM to a flat file in the current directory (re-inserting the guest's
128 MiB MMIO hole so file offset == guest-physical address), and then runs the
Linux plugin you name against that dump - exactly as if you had run
`vol.py -f <dump> linux.<plugin>` yourself.

Pick the Linux plugin with --linux-plugin; that plugin's own options (e.g.
--pid for bash) are accepted too:

    py vol.py -f mem.dmp windows.wsl.linux_plugins --linux-plugin lsmod
    py vol.py -f mem.dmp windows.wsl.linux_plugins --linux-plugin bash --pid 879
    py vol.py -f mem.dmp windows.wsl.linux_plugins --linux-plugin linux.ip.Addr

A matching Linux ISF for the exact WSL kernel must already be installed under
volatility3/symbols/linux/ (see README.md / build_wsl2_vmlinux.sh).

This is one plugin, rather than one windows.wsl.<name> per Linux plugin, so that
`vol.py -h` shows a single line for the whole family instead of ~40.
"""


import sys
import logging
import json
import os
import re
import urllib.parse
import urllib.request
from typing import Dict, List, NamedTuple, Optional, Tuple, Type

from volatility3 import framework
from volatility3.framework import (
    automagic,
    contexts,
    exceptions,
    interfaces,
)
from volatility3.framework import plugins as vol_plugins
from volatility3.framework.automagic import stacker
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)

# Process names Hyper-V/WSL2 has used for the lightweight-VM worker process
# that owns the guest's memory, matched case-insensitively against
# ImageFileName. "vmmemWSL" is the classic name; newer Windows builds
# share a single generic "vmmem" process across all lightweight utility VMs.
WSL_PROCESS_NAMES = {"vmmemwsl", "vmmem"}

# Chunk size used when streaming the guest-memory VAD out to disk - keeps
# memory usage flat regardless of how many GB the guest was configured with.
_DUMP_CHUNK_SIZE = 10 * 1024 * 1024

# --- The guest's MMIO hole -------------------------------------------------
# The WSL2 (Hyper-V) guest's physical address map has an MMIO hole just below
# 4 GiB: RAM at guest-physical 0 .. 0xF8000000, then nothing (device space)
# until 0x100000000, where the rest of RAM resumes. The host maps only the
# RAM, back to back, so in vmmemWSL's VAD run the "high" RAM starts right after
# the low RAM, i.e. one hole-size earlier than its guest-physical address.
# Every physical address the guest writes into its page tables is a *guest*
# address, so to make "file offset == guest-physical address" (which is what
# Volatility's Intel layer assumes) we re-insert the missing hole as zeros.
# Measured, not assumed: guest PD pages at gpa 0x1012b7000 were found at span
# offset 0xF92B7000 (= gpa - 0x8000000) and hold valid direct-map entries.
#
# Where the layout comes from (in order of preference):
#   1. --mmio-hole START:SIZE (or "none"), if the user gave it.
#   2. The Windows VAD structure: Hyper-V's worker allocates the low-RAM block
#      and the high-RAM block as two separate, host-adjacent VADs, so the
#      size of the first VAD *is* where the hole starts, and the high block
#      resumes at 4 GiB. Seen identically in all three captures tested.
#   3. The built-in default below, with a warning, when the VADs don't show it.
# Afterwards the result is cross-checked against the guest kernel's own
# "BIOS-e820" boot-log lines found in the RAM we are dumping (_E820Scanner).
_DEFAULT_HOLE_START = 0xF8000000
_DEFAULT_HOLE_SIZE = 0x8000000
_FOUR_GIB = 1 << 32
# A believable low-RAM block is 3 GiB .. just under 4 GiB; anything outside
# that is not "RAM below an MMIO gap" and must not be turned into a hole.
_MIN_LOW_RAM_BLOCK = 3 * (1 << 30)


class _HoleLayout(NamedTuple):
    start: int  # guest-physical address (== span offset) where the hole begins
    size: int  # bytes of zeros to insert there; 0 means "no hole"
    source: str  # where this came from, for the log


def _parse_hole_override(text: str) -> _HoleLayout:
    """Parses --mmio-hole: "none", or "START:SIZE" (ints, 0x... allowed)."""
    t = text.strip().lower()
    if t == "none":
        return _HoleLayout(0, 0, "--mmio-hole none")
    try:
        start_s, size_s = t.split(":")
        start, size = int(start_s, 0), int(size_s, 0)
        if start <= 0 or size < 0:
            raise ValueError
    except ValueError:
        raise exceptions.PluginRequirementException(
            f"--mmio-hole must be 'none' or START:SIZE (e.g. 0xF8000000:0x8000000), got {text!r}"
        )
    return _HoleLayout(start, size, f"--mmio-hole {text}")


def _choose_hole_layout(
    vad_sizes: List[int], span_size: int, override: Optional[str]
) -> _HoleLayout:
    """Decides where (if anywhere) to re-insert the guest's MMIO hole.

    vad_sizes: sizes of the VADs forming the guest-RAM span, in address order.
    """
    if override:
        return _parse_hole_override(override)

    # The low-RAM VAD ends exactly where the hole starts, and the next block of
    # RAM resumes at 4 GiB (verified against the guest's e820 map, see below).
    if len(vad_sizes) >= 2 and _MIN_LOW_RAM_BLOCK <= vad_sizes[0] < _FOUR_GIB:
        low = vad_sizes[0]
        return _HoleLayout(
            low,
            _FOUR_GIB - low,
            "boundary between the first two RAM VADs (high RAM resumes at 4 GiB)",
        )

    if span_size > _DEFAULT_HOLE_START:
        vollog.warning(
            "The VAD layout does not show where the guest's MMIO hole is; "
            f"assuming the usual {_DEFAULT_HOLE_SIZE >> 20} MiB hole at "
            f"{_DEFAULT_HOLE_START:#x}. If pslist/bash come back empty while "
            "psscan works, override it with --mmio-hole START:SIZE."
        )
        return _HoleLayout(
            _DEFAULT_HOLE_START, _DEFAULT_HOLE_SIZE, "built-in default (VADs gave no hint)"
        )

    return _HoleLayout(0, 0, "guest RAM fits below the MMIO gap, so no hole")


# Every vmmem process also holds a small fixed private VAD of exactly 32 MiB
# (0x2000000 bytes in all eight captures examined). It is not guest RAM (the
# guest's e820 map has no RAM for it), so a VAD this small is never taken as RAM.
_MARKER_VAD_SIZE = 0x2000000


def _select_ram_ranges(vad_ranges: List[Tuple[int, int]]) -> Tuple[List[Tuple[int, int]], str]:
    """Chooses which VADs hold the guest's RAM, in guest-physical order.

    vad_ranges: (host virtual start, size) of each VAD that has committed pages.

    Hyper-V's worker allocates the guest's RAM as separate VADs: a low block
    (0 .. below the MMIO hole, 0xF8000000 bytes on a guest of 3.875 GiB or more)
    and a high block (from 4 GiB up). They are NOT reliably adjacent in host
    memory - in a 4 GiB guest the 128 MiB high block sat *below* the low block,
    which merging "adjacent VADs" missed - so VADs are chosen by what they are:
    the one 3-4 GiB block is the low RAM and goes first, any other sizeable VAD
    is higher RAM and follows in address order. A guest smaller than 3.875 GiB
    has only the low block, which is then simply the biggest VAD.
    """
    big = [r for r in vad_ranges if r[1] > _MARKER_VAD_SIZE] or list(vad_ranges)
    low = [r for r in big if _MIN_LOW_RAM_BLOCK <= r[1] < _FOUR_GIB]
    if low and len(big) >= 2:
        first = max(low, key=lambda r: r[1])
        rest = sorted((r for r in big if r != first), key=lambda r: r[0])
        return [first] + rest, "the 3-4 GiB low-RAM VAD first, then the other RAM VADs by address"
    return sorted(big, key=lambda r: r[0]), "committed VADs in address order"


class _E820Scanner:
    """Collects the guest kernel's own record of its physical memory map.

    Early in boot Linux prints lines such as
        BIOS-e820: [mem 0x0000000100000000-0x00000003ef5fffff] usable
    into its log buffer, which sits in plain text in the RAM we are dumping.
    Fed every chunk as it is written out, this finds them for free (no address
    translation needed) so the layout we chose can be checked against what the
    guest itself says. Stale copies from earlier boots also turn up in free
    memory, so lines are grouped by proximity and *any* matching group is enough.
    """

    _LINE = re.compile(
        rb"BIOS-e820: \[mem 0x([0-9a-f]{16})-0x([0-9a-f]{16})\] usable"
    )
    _TAIL = 96  # longer than one line, so a line split across chunks is still seen

    def __init__(self) -> None:
        self.hits: Dict[int, Tuple[int, int]] = {}  # span offset -> (start, end)
        self.bytes_fed = 0
        self._tail = b""

    def feed(self, data: bytes, offset: int) -> None:
        # A line can straddle two chunks, so also scan the previous chunk's tail
        # joined to this chunk's head. Doing that on small slices (not a copy of
        # the whole chunk) keeps the scan cheap; hits are keyed by absolute
        # offset, so a line seen twice is stored once.
        if self._tail:
            join = self._tail + data[: self._TAIL]
            self._add(join, offset - len(self._tail))
        if b"BIOS-e820" in data:
            self._add(data, offset)
        # (a chunk shorter than the tail must not push older tail bytes out)
        self._tail = (
            data[-self._TAIL :]
            if len(data) >= self._TAIL
            else (self._tail + data)[-self._TAIL :]
        )
        self.bytes_fed += len(data)

    def _add(self, buf: bytes, base: int) -> None:
        for m in self._LINE.finditer(buf):
            self.hits[base + m.start()] = (int(m.group(1), 16), int(m.group(2), 16))

    def _groups(self) -> List[List[Tuple[int, int]]]:
        groups: List[List[Tuple[int, int]]] = []
        last = None
        for off in sorted(self.hits):
            if last is None or off - last > 4096:
                groups.append([])
            groups[-1].append(self.hits[off])
            last = off
        return groups

    def verify(self, layout: _HoleLayout, total_ram: int) -> Tuple[str, str]:
        """Returns (status, message); status is confirmed / contradicted / not_found.

        The guest's RAM must end exactly where our layout says it does: a group
        that also lists RAM *above* our top (e.g. a high block we failed to
        include) does not match.
        """
        groups = self._groups()
        if not groups:
            return "not_found", "no e820 boot-log lines found in the dump"
        top = total_ram + layout.size  # last guest-physical address + 1
        for g in groups:
            ends = {e + 1 for _, e in g}
            starts = {s for s, _ in g}
            if max(ends) != top:
                continue
            if layout.size == 0 or (
                layout.start in ends and layout.start + layout.size in starts
            ):
                return "confirmed", (
                    "the guest's own e820 memory map matches "
                    f"(RAM up to {top:#x}"
                    + (f", hole {layout.start:#x}-{layout.start + layout.size:#x}" if layout.size else "")
                    + ")"
                )
        # The same boot log is often present many times (copies in free memory,
        # page cache, ...), so show each *distinct* memory map once.
        distinct = list(dict.fromkeys(tuple(g) for g in groups))
        shown = "; ".join(
            "[" + ", ".join(f"{s:#x}-{e:#x}" for s, e in g) + "]" for g in distinct[:3]
        )
        return "contradicted", (
            f"none of the {len(groups)} e820 record group(s) found matches the chosen "
            f"layout (RAM top {top:#x}, hole {layout.start:#x}+{layout.size:#x}): {shown}. "
            "They may be stale copies from earlier boots; if pslist/bash come back "
            "empty while psscan works, a RAM block may be missing or the layout wrong - "
            "override with --mmio-hole START:SIZE."
        )



def _linux_plugin_table() -> Dict[str, Type[interfaces.plugins.PluginInterface]]:
    """{"pslist.PsList": cls, "malware.netfilter.Netfilter": cls, ...} for every
    non-hidden linux.* plugin Volatility has discovered (nested packages included)."""
    return {
        full[len("linux."):]: cls
        for full, cls in framework.list_plugins().items()
        if full.startswith("linux.")
    }


def _resolve_linux_plugin(name: str) -> Type[interfaces.plugins.PluginInterface]:
    """Maps user input to a Linux plugin class. Accepted spellings (case-insensitive):
    full name "linux.ip.Addr", without prefix "ip.Addr", or just the module
    "lsmod" / "linux.lsmod" when that module holds exactly one plugin."""
    key = name.strip().lower()
    if key.startswith("linux."):
        key = key[len("linux."):]
    table = _linux_plugin_table()
    for full, cls in table.items():
        if full.lower() == key:
            return cls
    by_module = [(f, c) for f, c in table.items() if f.lower().rsplit(".", 1)[0] == key]
    if len(by_module) == 1:
        return by_module[0][1]
    if by_module:
        raise exceptions.PluginRequirementException(
            f"'{name}' is ambiguous, it matches: "
            + ", ".join(f"linux.{f}" for f, _ in sorted(by_module))
        )
    raise exceptions.PluginRequirementException(
        f"'{name}' is not a known Linux plugin. Available: "
        + ", ".join(sorted(f"linux.{f}" for f in table))
    )


def _linux_plugin_name_from_argv() -> Optional[str]:
    """The CLI builds every plugin's argparse options *before* parsing, so to know
    which Linux plugin's options (--pid, ...) to expose we peek at sys.argv."""
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg == "--linux-plugin" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--linux-plugin="):
            return arg.split("=", 1)[1]
    return None


# --- Dump provenance -------------------------------------------------------
# A guest-RAM dump is many GB, so an existing one is reused instead of re-written.
# The filename (vmmemwsl.pid<PID>.dmp) and size are NOT enough to prove it came
# from the image being analysed: Windows reuses PIDs, and two captures of the
# same-sized guest give same-named, same-sized files with different contents.
# So each dump gets a sidecar "<dump>.json" recording where it came from (image
# path + size + mtime, process, create time, span and layout), written only after
# the dump completes, and reuse requires the sidecar to match exactly. A dump with
# no sidecar (older versions, an interrupted run) is never trusted.
def _sidecar_path(dump_path: str) -> str:
    return dump_path + ".json"


def _image_fingerprint(location: Optional[str]) -> Dict[str, object]:
    """Identifies the Windows image being analysed (path, size, mtime).

    If the image isn't a local file we can stat (a URL, a multi-file image, ...)
    the fingerprint is flagged `unverifiable` and a dump made from it is never
    reused, because nothing could prove a later image is the same one.
    """
    info: Dict[str, object] = {"image": location}
    try:
        parsed = urllib.parse.urlparse(location or "")
        if parsed.scheme != "file":
            raise ValueError("not a local file")
        st = os.stat(urllib.request.url2pathname(parsed.path))
        info["image_size"] = st.st_size
        info["image_mtime_ns"] = st.st_mtime_ns
    except (ValueError, OSError):
        info["unverifiable"] = True
    return info


def _proc_name(proc) -> str:
    """Lower-cased ImageFileName of a Windows process object."""
    try:
        return utility.array_to_string(proc.ImageFileName).lower()
    except Exception:
        return str(getattr(proc, "ImageFileName", "")).lower()


class linux_plugins(interfaces.plugins.PluginInterface):
    """Finds the WSL2 guest's memory in a Windows image and runs any linux.* plugin on it (choose with --linux-plugin NAME, e.g. lsmod, pslist, bash, sockstat; run this plugin with -h for the full list)."""

    _required_framework_version = (2, 0, 0)

    # Option names that belong to us (the Windows side); never forwarded to the
    # wrapped Linux plugin.
    _OWN_REQUIREMENT_NAMES = {
        "kernel",
        "wsl_process",
        "dump_extra_regions",
        "linux_plugin",
        "mmio_hole",
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        try:
            available = ", ".join(sorted(f"linux.{f}" for f in _linux_plugin_table()))
        except Exception:  # never let help generation crash the CLI
            available = "(unavailable)"
        reqs: List[interfaces.configuration.RequirementInterface] = [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel (used to find the WSL guest's process)",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="linux_plugin",
                description=(
                    "Linux plugin to run against the WSL guest, e.g. lsmod, "
                    "pslist, bash, linux.ip.Addr. Available: " + available
                ),
                optional=True,
            ),
            requirements.StringRequirement(
                name="wsl_process",
                description=(
                    "Exact process name backing the WSL guest's memory, if it "
                    f"isn't one of the defaults searched automatically ({', '.join(sorted(WSL_PROCESS_NAMES))})"
                ),
                optional=True,
            ),
            requirements.StringRequirement(
                name="mmio_hole",
                description=(
                    "Override the guest's MMIO-hole layout, as START:SIZE "
                    "(e.g. 0xF8000000:0x8000000), or 'none' for no hole. Normally "
                    "detected automatically from the Windows VAD layout and "
                    "cross-checked against the guest's e820 map."
                ),
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump_extra_regions",
                description=(
                    "Also dump every other host-VA-contiguous VAD span found in "
                    "the WSL process (not just the biggest one used as the main "
                    "guest memory), each to its own file, for your own "
                    "follow-up inspection. Off by default (can be multi-GB)."
                ),
                default=False,
                optional=True,
            ),
        ]
        # Splice in the chosen Linux plugin's own options (e.g. --pid for bash).
        # Its "kernel" requirement is excluded: we satisfy that ourselves from
        # the memory we dump.
        chosen = _linux_plugin_name_from_argv()
        if chosen:
            try:
                for req in _resolve_linux_plugin(chosen).get_requirements():
                    if req.name not in cls._OWN_REQUIREMENT_NAMES:
                        reqs.append(req)
            except exceptions.PluginRequirementException:
                pass  # reported properly at run() time
        return reqs

    def _find_wsl_candidates(self) -> List[interfaces.objects.ObjectInterface]:
        """Locates every vmmemWSL/vmmem process in the Windows memory image.

        Returns them all, in process-list order, rather than picking one
        here: a recently-exited process can still be sitting in the process
        list with an empty VAD tree (Windows doesn't unlink it immediately),
        so more than one hit is common and the *first* one isn't necessarily
        usable. The caller (`run`) tries each in turn until one actually has
        guest memory to dump.
        """
        wanted = (
            {self.config["wsl_process"].lower()}
            if self.config.get("wsl_process")
            else WSL_PROCESS_NAMES
        )

        def name_filter(proc: interfaces.objects.ObjectInterface) -> bool:
            # list_processes() yields whatever this returns False for.
            name = utility.array_to_string(proc.ImageFileName).lower()
            return name not in wanted

        candidates = list(
            pslist.PsList.list_processes(
                context=self.context,
                kernel_module_name=self.config["kernel"],
                filter_func=name_filter,
            )
        )

        if not candidates:
            raise exceptions.PluginRequirementException(
                f"No process named one of {sorted(wanted)} was found in this "
                "image - is a WSL2 instance running/resident here? You can "
                "override the name searched for with the wsl_process option."
            )
        if len(candidates) > 1:
            vollog.info(
                f"Found {len(candidates)} candidate WSL processes "
                f"(PIDs {[int(p.UniqueProcessId) for p in candidates]}); "
                "will try each in turn until one has usable guest memory."
            )
        return candidates

    def _dump_span(
        self,
        proc_layer: interfaces.layers.DataLayerInterface,
        pid: int,
        ranges: List[Tuple[int, int]],
        dest_path: str,
        progress_label: str,
        layout: Optional[_HoleLayout] = None,
        scanner: Optional[_E820Scanner] = None,
        identity: Optional[Dict[str, object]] = None,
    ) -> str:
        """Streams the given (host start, size) ranges, back to back in the
        order given, out to dest_path, reusing an existing file instead of re-writing it - but only if its
        provenance sidecar matches `identity` exactly (see "Dump provenance"
        above); without an identity nothing is ever reused.

        Shared by the main guest-memory span (always dumped) and, optionally,
        every other span found in the process (see `dump_extra_regions`).

        With a `layout` that has a hole, `layout.size` bytes of zeros are
        written at `layout.start` so that the file is laid out by guest-physical
        address (see the MMIO-hole comment at the top of this module). Only
        meaningful for the main RAM span. If a `scanner` is given, every chunk
        written is fed to it (it is not fed when an existing dump is reused).
        """
        span_size = sum(size for _, size in ranges)
        hole_start = layout.start if layout else 0
        hole = layout.size if layout else 0
        out_size = span_size + hole

        sidecar = _sidecar_path(dest_path)
        record = dict(identity, dump_size=out_size) if identity is not None else None
        if os.path.exists(dest_path):
            reusable = False
            reason = "it has no provenance record (older version or interrupted run)"
            if record is None or record.get("unverifiable"):
                reason = "the source image can't be verified"
            elif os.path.getsize(dest_path) != out_size:
                reason = "its size differs from this span"
            elif os.path.exists(sidecar):
                try:
                    with open(sidecar, "r", encoding="utf-8") as fh:
                        reusable = json.load(fh) == record
                except (OSError, ValueError):
                    pass
                reason = "it was made from a different image, process or layout"
            if reusable:
                vollog.info(
                    f"Reusing existing dump {dest_path} for PID {pid} "
                    f"({out_size:,} bytes, provenance matches) - skipping re-dump"
                )
                return dest_path
            vollog.info(f"Not reusing existing {dest_path}: {reason}; re-dumping")

        # Until the dump completes there must be no record claiming it is whole.
        if os.path.exists(sidecar):
            os.remove(sidecar)

        vollog.info(f"Dumping {out_size:,} bytes to {dest_path}")

        written = 0  # bytes of RAM consumed so far (excludes the hole)
        ri, roff = 0, 0  # which host range we are in, and how far into it
        with open(dest_path, "wb") as fh:
            while written < span_size:
                if hole and written == hole_start:
                    # Reached the guest's MMIO gap: emit it as zeros, once
                    # (in slices, as the hole can be large with a custom layout).
                    left = hole
                    while left:
                        n = min(left, _DUMP_CHUNK_SIZE)
                        fh.write(bytes(n))
                        left -= n
                    hole = 0
                rstart, rsize = ranges[ri]
                # never let a chunk straddle the end of a host range ...
                to_read = min(_DUMP_CHUNK_SIZE, span_size - written, rsize - roff)
                if hole and written < hole_start:
                    # ... or the hole's insertion point
                    to_read = min(to_read, hole_start - written)
                # pad=True: fill any unmapped/unavailable pages with zeros
                # rather than aborting the dump, same as vadinfo/memmap do.
                data = proc_layer.read(rstart + roff, to_read, pad=True)
                fh.write(data)
                if scanner is not None:
                    scanner.feed(data, written)
                written += to_read
                roff += to_read
                if roff == rsize:
                    ri, roff = ri + 1, 0
                self._progress_callback(written * 100 // span_size, progress_label)

        # Written last, so its presence means the dump above finished.
        if record is not None and not record.get("unverifiable"):
            with open(sidecar, "w", encoding="utf-8") as fh:
                json.dump(record, fh, indent=1)

        return dest_path

    def _capture_identity(self, proc: interfaces.objects.ObjectInterface) -> Dict[str, object]:
        """Who/what a dump belongs to: the Windows image plus this process
        (PID and create time, since Windows reuses PIDs)."""
        location = None
        try:
            kernel_layer = self.context.layers[proc.vol.layer_name]
            phys = self.context.layers[kernel_layer.config["memory_layer"]]
            location = getattr(phys, "location", None)
        except (KeyError, AttributeError, exceptions.LayerException):
            pass
        info = _image_fingerprint(location)
        info["pid"] = int(proc.UniqueProcessId)
        try:
            info["create_time"] = str(proc.get_create_time())
        except Exception:  # unreadable/odd value: still better than nothing
            info["create_time"] = "unknown"
        return info

    def _dump_guest_memory(self, proc: interfaces.objects.ObjectInterface) -> str:
        """Dumps the VAD run backing the guest's physical RAM to a flat file
        in the current directory and returns its full path.

        We deliberately write straight to a path we pick ourselves (rather
        than through self.open()/FileHandlerInterface) because a plugin has
        no portable way to learn the real filesystem path behind a
        FileHandlerInterface - and we need that exact path a moment later to
        point a brand new layer/Context at it for the loop-back run.
        """
        pid = proc.UniqueProcessId
        proc_layer_name = proc.add_process_layer()
        proc_layer = self.context.layers[proc_layer_name]

        vads = list(vadinfo.VadInfo.list_vads(proc))
        if not vads:
            raise exceptions.PluginRequirementException(
                f"Process {pid} has no VADs - can't locate its guest memory region"
            )

        # Which VADs are the guest's RAM? Hyper-V's worker allocates the low-RAM
        # block and the high-RAM block (above 4 GiB) as separate VADs - see
        # _select_ram_ranges. Only VADs with committed pages are candidates:
        # every vmmem process also carries a ~4 GiB PAGE_NOACCESS *reservation*
        # (0x10000-0xffffffff, zero commit charge) that holds no data, and it
        # would out-size the RAM of a guest under ~4 GiB (seen with a 2 GiB
        # guest). If nothing is committed, fall back to all VADs.
        def _commit(vad) -> int:
            try:
                return int(vad.get_commit_charge())
            except AttributeError:
                return 1  # can't tell: don't exclude it

        candidates = [v for v in vads if _commit(v) > 0] or vads
        vad_ranges = [(v.get_start(), v.get_end() - v.get_start() + 1) for v in candidates]
        ranges, how = _select_ram_ranges(vad_ranges)
        vad_sizes = [size for _, size in ranges]
        span_size = sum(vad_sizes)
        vollog.info(
            f"PID {pid}: guest RAM = {len(ranges)} VAD(s) ({how}): "
            + ", ".join(f"{start:#x}+{size:#x}" for start, size in ranges)
        )

        layout = _choose_hole_layout(vad_sizes, span_size, self.config.get("mmio_hole"))
        vollog.info(
            f"PID {pid}: MMIO hole "
            + (f"{layout.start:#x}+{layout.size:#x}" if layout.size else "none")
            + f" ({layout.source})"
        )

        dest_path = os.path.join(os.getcwd(), f"vmmemwsl.pid{pid}.dmp")
        scanner = _E820Scanner()
        base_identity = self._capture_identity(proc)
        # This is the memory the wrapped Linux plugin will actually be run
        # against, so a failure dumping it is fatal - let it raise.
        self._dump_span(
            proc_layer,
            pid,
            ranges,
            dest_path,
            f"Dumping WSL guest memory (PID {pid})",
            layout=layout,
            scanner=scanner,
            identity=dict(
                base_identity,
                ranges=[list(r) for r in ranges],
                hole=[layout.start, layout.size],
            ),
        )

        # Cross-check the layout against the guest's own memory map. Never
        # fatal: a long-running guest may have overwritten its boot log, and a
        # reused dump isn't re-scanned.
        if scanner.bytes_fed != span_size:
            vollog.info("Reused an existing dump, so the e820 layout check was skipped")
        else:
            status, detail = scanner.verify(layout, span_size)
            if status == "confirmed":
                vollog.info(f"MMIO layout check: {detail}")
            elif status == "not_found":
                vollog.info(f"MMIO layout check skipped: {detail}")
            else:
                vollog.warning(f"MMIO layout check: {detail}")

        if self.config.get("dump_extra_regions"):
            extras = [r for r in vad_ranges if r not in ranges]
            for i, (extra_start, extra_size) in enumerate(extras, 1):
                extra_path = os.path.join(
                    os.getcwd(),
                    f"vmmemwsl.pid{pid}.extra{i}.{extra_start:#x}-{extra_start + extra_size - 1:#x}.dmp",
                )
                # Best-effort: these are bonus data for manual follow-up, not
                # needed for the actual plugin run, so one failing (disk
                # space, an unreadable VAD, whatever) shouldn't take down a
                # run that has already gotten the memory it actually needs.
                try:
                    self._dump_span(
                        proc_layer,
                        pid,
                        [(extra_start, extra_size)],
                        extra_path,
                        f"Dumping extra WSL region {i}/{len(extras)} (PID {pid})",
                        identity=dict(
                            base_identity,
                            ranges=[[extra_start, extra_size]],
                            hole=[0, 0],
                        ),
                    )
                except Exception as excp:
                    vollog.warning(
                        f"Couldn't dump extra region {extra_start:#x}+{extra_size:#x} "
                        f"for PID {pid}: {excp}"
                    )

        return dest_path

    def _run_linux_plugin(self, dump_path: str) -> interfaces.renderers.TreeGrid:
        """Bootstraps a fresh Context around `dump_path` and runs
        `self._wsl_target_plugin` against it - the same sequence
        volatility3's own CLI performs for `-f dump_path linux.<...>`,
        just done here programmatically instead of from the command line.
        """
        target_cls = self._wsl_target_plugin
        vollog.info(
            f"Handing {dump_path} to {target_cls.__module__}.{target_cls.__name__}"
        )

        linux_ctx = contexts.Context()
        linux_ctx.config["automagic.LayerStacker.single_location"] = (
            requirements.URIRequirement.location_from_file(dump_path)
        )

        available_automagics = automagic.available(linux_ctx)
        chosen_automagics = automagic.choose_automagic(available_automagics, target_cls)
        linux_ctx.config["automagic.LayerStacker.stackers"] = (
            stacker.choose_os_stackers(target_cls)
        )

        base_config_path = "plugins"
        plugin_config_path = interfaces.configuration.path_join(
            base_config_path, target_cls.__name__
        )

        # Forward any values the user supplied for the wrapped plugin's own
        # options (e.g. `windows.wsl.bash --pid 123`) into the nested
        # Context, at the config path the loop-back plugin instance expects.
        for req in target_cls.get_requirements():
            if req.name in self._OWN_REQUIREMENT_NAMES:
                continue
            if req.name in self.config:
                linux_ctx.config[
                    interfaces.configuration.path_join(plugin_config_path, req.name)
                ] = self.config[req.name]

        try:
            constructed = vol_plugins.construct_plugin(
                linux_ctx,
                chosen_automagics,
                target_cls,
                base_config_path,
                self._progress_callback,
                self._file_handler,
            )
        except exceptions.UnsatisfiedException as excp:
            # Not logged here: run() may still have another candidate to try,
            # and only reports the failure once it runs out of them.
            excp.args = (
                f"{target_cls.__module__}.{target_cls.__name__} couldn't be "
                f"satisfied against the dumped WSL memory: {list(excp.unsatisfied)}. "
                "Do you have a matching Linux ISF for this WSL kernel installed "
                "under volatility3/symbols/linux/?",
            )
            raise

        return constructed.run()

    def run(self):
        name = self.config.get("linux_plugin")
        # Vol3 shows only a generic "unexpected situation" for a bare
        # PluginRequirementException, so log the real message ourselves first.
        try:
            if not name:
                raise exceptions.PluginRequirementException(
                    "No Linux plugin chosen: pass --linux-plugin NAME. Available: "
                    + ", ".join(sorted(f"linux.{f}" for f in _linux_plugin_table()))
                )
            self._wsl_target_plugin = _resolve_linux_plugin(name)
        except exceptions.PluginRequirementException as excp:
            vollog.error(str(excp))
            raise

        candidates = self._find_wsl_candidates()

        # "vmmem" is also the name other lightweight VMs (Windows Sandbox, ...)
        # run under, so try the process literally named vmmemWSL first. The sort
        # is stable, so process-list order is kept within each group.
        candidates = sorted(candidates, key=lambda p: _proc_name(p) != "vmmemwsl")

        last_error: Optional[Exception] = None
        unanalysable: Optional[exceptions.UnsatisfiedException] = None
        for n, proc in enumerate(candidates):
            try:
                dump_path = self._dump_guest_memory(proc)
            except exceptions.PluginRequirementException as excp:
                # Most commonly: "has no VADs" - a stale/exited process
                # still sitting in the process list. Move on to the next
                # candidate rather than failing outright.
                vollog.warning(
                    f"PID {proc.UniqueProcessId} isn't usable ({excp}); "
                    "trying the next candidate WSL process, if any."
                )
                last_error = excp
                continue
            try:
                return self._run_linux_plugin(dump_path)
            except exceptions.UnsatisfiedException as excp:
                # This process's memory has no Linux guest we can analyse: no
                # matching ISF, or it isn't a Linux VM at all (another vmmem).
                # Remembered separately so a later stale candidate's "no VADs"
                # can't hide it: it's the more useful thing to tell the user.
                unanalysable = excp
                if n < len(candidates) - 1:
                    vollog.warning(
                        f"PID {proc.UniqueProcessId}: {excp} Trying the next "
                        "candidate WSL process."
                    )
                    continue
                vollog.error(str(excp))
                raise

        # Every candidate failed. If an earlier one dumped fine but wasn't
        # analysable, that - not "no usable memory" - is the real problem.
        if unanalysable is not None:
            vollog.error(str(unanalysable))
            raise unanalysable

        msg = (
            f"None of the {len(candidates)} candidate WSL process(es) found "
            f"had usable guest memory to dump. Last error: {last_error} "
            "If WSL2 was genuinely running at capture time, this usually "
            "means the snapshot only caught a stale/exited vmmemWSL and "
            "missed the live one (a timing/smearing artifact of the "
            "capture) - try acquiring a fresh image."
        )
        vollog.error(msg)
        raise exceptions.PluginRequirementException(msg)
