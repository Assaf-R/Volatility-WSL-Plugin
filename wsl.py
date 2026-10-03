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
import os
from typing import Dict, List, Optional, Type

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

# The WSL2 (Hyper-V) guest's physical address map has a 128 MiB MMIO hole just
# below 4 GiB: RAM is at guest-physical 0 .. 0xF8000000, then nothing (device
# space) until 0x100000000, where the rest of RAM resumes. The host maps only
# the RAM, back to back, so in vmmemWSL's VAD run the "high" RAM starts right
# after the low RAM, i.e. 128 MiB earlier than its guest-physical address.
# Every physical address the guest writes into its page tables is a *guest*
# address, so to make "file offset == guest-physical address" (which is what
# Volatility's Intel layer assumes) we re-insert the missing hole as zeros.
# Measured, not assumed: guest PD pages at gpa 0x1012b7000 were found at span
# offset 0xF92B7000 (= gpa - 0x8000000) and hold valid direct-map entries.
_GUEST_MMIO_HOLE_START = 0xF8000000
_GUEST_MMIO_HOLE_SIZE = 0x8000000



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


class linux_plugins(interfaces.plugins.PluginInterface):
    """Finds the WSL2 guest's memory in a Windows image and runs any linux.* plugin on it (choose with --linux-plugin NAME, e.g. lsmod, pslist, bash, sockstat; run this plugin with -h for the full list)."""

    _required_framework_version = (2, 0, 0)

    # Option names that belong to us (the Windows side); never forwarded to the
    # wrapped Linux plugin.
    _OWN_REQUIREMENT_NAMES = {"kernel", "wsl_process", "dump_extra_regions", "linux_plugin"}

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
        span_start: int,
        span_end: int,
        dest_path: str,
        progress_label: str,
        insert_mmio_hole: bool = False,
    ) -> str:
        """Streams one [span_start, span_end] host-VA range out to dest_path,
        reusing an existing file of the right size instead of re-writing it.

        Shared by the main guest-memory span (always dumped) and, optionally,
        every other span found in the process (see `dump_extra_regions`).

        With insert_mmio_hole, 128 MiB of zeros are written at guest-physical
        0xF8000000 (see _GUEST_MMIO_HOLE_START) so that the file is laid out by
        guest-physical address. Only meaningful for the main RAM span.
        """
        span_size = span_end - span_start + 1
        hole = (
            _GUEST_MMIO_HOLE_SIZE
            if insert_mmio_hole and span_size > _GUEST_MMIO_HOLE_START
            else 0
        )
        out_size = span_size + hole

        # See the reuse comment in the caller for why we key on size too, not
        # just the filename existing.
        if os.path.exists(dest_path) and os.path.getsize(dest_path) == out_size:
            vollog.info(
                f"Reusing existing dump {dest_path} for PID {pid} "
                f"({out_size:,} bytes matches this span) - skipping re-dump"
            )
            return dest_path

        vollog.info(f"Dumping {out_size:,} bytes to {dest_path}")

        written = 0  # bytes consumed from the host span (excludes the hole)
        with open(dest_path, "wb") as fh:
            while written < span_size:
                if hole and written == _GUEST_MMIO_HOLE_START:
                    # Reached the guest's MMIO gap: emit it as zeros, once.
                    fh.write(bytes(hole))
                    hole = 0
                to_read = min(_DUMP_CHUNK_SIZE, span_size - written)
                if hole and written < _GUEST_MMIO_HOLE_START:
                    # never let a chunk straddle the insertion point
                    to_read = min(to_read, _GUEST_MMIO_HOLE_START - written)
                # pad=True: fill any unmapped/unavailable pages with zeros
                # rather than aborting the dump, same as vadinfo/memmap do.
                data = proc_layer.read(span_start + written, to_read, pad=True)
                fh.write(data)
                written += to_read
                self._progress_callback(written * 100 // span_size, progress_label)

        return dest_path

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

        # Heuristic: Hyper-V exposes a lightweight VM's guest-physical RAM as
        # a *set* of VADs inside its host worker process, not always a single
        # one - on real hardware-like layouts, RAM below the ~4GiB PCI/MMIO
        # hole and RAM above it commonly end up as separate VAD allocations.
        # Critically, the "low memory" portion (where the kernel image, and
        # thus symbols like the boot banner, actually load) can land in the
        # *smaller* of these, not the biggest one - so picking only the
        # single largest VAD can silently miss it, even though the biggest
        # VAD alone is still multiple GB and "looks" like the whole guest.
        #
        # Whenever Hyper-V splits guest RAM this way, the pieces are laid out
        # host-VA-contiguously (one VAD's end+1 == the next VAD's start),
        # which is exactly what lets us tell "parts of one guest-physical
        # range" apart from "an unrelated allocation that happens to be
        # large" (a big stack/heap region elsewhere in the process): we merge
        # every run of host-VA-adjacent VADs into one span and use the
        # largest resulting span, rather than the largest single VAD.
        vads_by_start = sorted(vads, key=lambda v: v.get_start())
        spans = []  # list of [start, end, [vads...]]
        for vad in vads_by_start:
            start, end = vad.get_start(), vad.get_end()
            if spans and spans[-1][1] + 1 == start:
                spans[-1][1] = end
                spans[-1][2].append(vad)
            else:
                spans.append([start, end, [vad]])

        main_span = max(spans, key=lambda s: s[1] - s[0])
        span_start, span_end, span_vads = main_span
        vollog.info(
            f"PID {pid}: treating host-VA-contiguous span {span_start:#x}-"
            f"{span_end:#x} ({span_end - span_start + 1:,} bytes, merged from "
            f"{len(span_vads)} VAD(s)) as the WSL guest's physical memory"
        )

        dest_path = os.path.join(os.getcwd(), f"vmmemwsl.pid{pid}.dmp")
        # This is the span the wrapped Linux plugin will actually be run
        # against, so a failure dumping it is fatal - let it raise.
        self._dump_span(
            proc_layer,
            pid,
            span_start,
            span_end,
            dest_path,
            f"Dumping WSL guest memory (PID {pid})",
            insert_mmio_hole=True,
        )

        if self.config.get("dump_extra_regions"):
            extra_spans = [s for s in spans if s is not main_span]
            for i, (extra_start, extra_end, extra_vads) in enumerate(extra_spans, 1):
                extra_path = os.path.join(
                    os.getcwd(),
                    f"vmmemwsl.pid{pid}.extra{i}.{extra_start:#x}-{extra_end:#x}.dmp",
                )
                # Best-effort: these are bonus data for manual follow-up, not
                # needed for the actual plugin run, so one failing (disk
                # space, an unreadable VAD, whatever) shouldn't take down a
                # run that has already gotten the main span it actually needs.
                try:
                    self._dump_span(
                        proc_layer,
                        pid,
                        extra_start,
                        extra_end,
                        extra_path,
                        f"Dumping extra WSL region {i}/{len(extra_spans)} (PID {pid})",
                    )
                except Exception as excp:
                    vollog.warning(
                        f"Couldn't dump extra region {extra_start:#x}-{extra_end:#x} "
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
            vollog.error(
                f"{target_cls.__module__}.{target_cls.__name__} couldn't be "
                f"satisfied against the dumped WSL memory: {list(excp.unsatisfied)}. "
                "Do you have a matching Linux ISF for this WSL kernel installed "
                "under volatility3/symbols/linux/?"
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

        last_error: Optional[Exception] = None
        for proc in candidates:
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
            return self._run_linux_plugin(dump_path)

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
