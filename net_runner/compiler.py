import hashlib
import os
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from mininet.log import info, debug, error, warning
from p4utils.utils.compiler import P4C, NotCompiledError, P4InfoDisabled, CompilationError


class CompilerBase(ABC):
    """Base class for P4 source code compilers implementing some of the functionality required by p4-utils."""

    def __init__(self, p4_src: str, output_dir: str) -> None:
        if not os.path.isfile(p4_src):
            raise FileNotFoundError(f'P4 source file not found: {p4_src}')
        elif os.path.isfile(output_dir):
            raise FileExistsError(f'Output directory is a file: {output_dir}')
        self.p4_src: str = p4_src  # This attribute is directly accessed by p4-utils
        self._output_dir: str = output_dir
        self._json_out_path: Optional[str] = None
        self._p4rt_out_path: Optional[str] = None
        self.compiled: bool = False  # This attribute is directly accessed by p4-utils
        self._checksum_path: Path = Path(self._output_dir) / f'.{Path(p4_src).parent.name}-{Path(p4_src).name}.sha1'

    @abstractmethod
    def _compile_impl(self, only_set_output_paths: bool) -> None:
        """The logic behind the compilation. Must call `_set_compilation_outputs()`."""

    def _set_compilation_outputs(self, json_out: str, p4rt_out: Optional[str] = None) -> None:
        """Sets the compilation output file paths. Must be called when the sources are compiled."""
        self._json_out_path = json_out
        self._p4rt_out_path = p4rt_out

    def compile(self) -> None:
        """Compiles the source code (if the source has changed) and stores the path of the output files."""
        os.makedirs(self._output_dir, exist_ok=True)
        self._json_out_path = None
        self._p4rt_out_path = None

        source_checksum = self._calculate_source_checksum()
        if self.new_source(source_checksum):
            info(f'Compiling {self.p4_src}...\n')
            self._compile_impl(only_set_output_paths=False)
            self._checksum_path.write_bytes(source_checksum)
        else:
            info(f'Skipping compilation of {self.p4_src}: no changes detected\n')
            self._compile_impl(only_set_output_paths=True)

        if self._json_out_path is None:
            raise AssertionError('Compilation output path not set')
        self.compiled = True

    def get_json_out(self) -> str:
        """The path of the compilation output. The file doesn't actually have to be a JSON file."""
        if self.compiled:
            return self._json_out_path
        else:
            raise NotCompiledError

    def get_p4rt_out(self) -> str:
        """The path of the P4Runtime configuration file, if it was generated. Otherwise, raises an exception."""
        if self.compiled:
            if self._p4rt_out_path is not None:
                return self._p4rt_out_path
            else:
                raise P4InfoDisabled  # This exception is used for flow control
        else:
            raise NotCompiledError

    def new_source(self, source_checksum: Optional[bytes] = None) -> bool:
        """Determines whether the source file(s) have changed since the last compilation."""
        if source_checksum is None:
            source_checksum = self._calculate_source_checksum()
        compiled_source_checksum = self._read_checksum_file()
        # Return: source hasn't been compiled yet OR source has been modified
        return compiled_source_checksum is None or compiled_source_checksum != source_checksum

    def _calculate_source_checksum(self) -> bytes:
        """Calculates the checksum of all P4 files within the main P4 file's directory."""
        digest = hashlib.sha256()
        digest.update(self.p4_src.encode())
        for path in Path(self.p4_src).parent.glob("**/*.p4"):
            digest.update(path.read_bytes())
        return digest.digest()

    def _read_checksum_file(self) -> Optional[bytes]:
        """Reads the cached checksum of the source file(s) from the checksum file."""
        if self._checksum_path.exists():
            return self._checksum_path.read_bytes()


class PsaSimpleSwitchCompiler(CompilerBase):
    """
    Variant of the P4C compiler class for the PSA architecture with the following modifications:
    - Fix the following issue: 'p4c -o ...' expects a directory, but 'p4c-bm2-psa -o ...' expects a file.
    - The original check used to determine whether recompilation is necessary doesn't take included files into account,
      and it only works within a single run of the script. Our fix checks whether any file in the main source file's
      directory has been modified and works across multiple invocations.
    """

    def __init__(self, p4_src: str, output_dir: str) -> None:
        super().__init__(p4_src, output_dir)
        # noinspection PyTypeChecker
        self._p4c = P4C(p4_src, p4c_bin='p4c-bm2-psa', outdir=None, opts='--target bmv2 --arch psa --std p4-16')
        self._p4c.p4rt_out = self._p4c.p4rt_out.replace(self._p4c.outdir, output_dir)
        self._p4c.json_out = self._p4c.json_out.replace(self._p4c.outdir, output_dir)
        self._p4c.outdir = self._p4c.json_out  # outdir is only used once: it's passed to -o

    def _compile_impl(self, only_set_output_paths: bool) -> None:
        self._p4c.compile()
        self._set_compilation_outputs(self._p4c.json_out, self._p4c.p4rt_out if self._p4c.p4rt else None)


class CompilerProcessBase(CompilerBase, ABC):
    """Base class for compilers that call a subprocess to compile the source code."""

    @abstractmethod
    def _create_process_cmd(self, only_set_output_paths: bool) -> str:
        """Creates the compiler process command. Must call _set_compilation_outputs()."""

    def _compile_impl(self, only_set_output_paths: bool) -> None:
        cmd = self._create_process_cmd(only_set_output_paths)
        if only_set_output_paths:
            return

        debug(f'{cmd}\n')
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        stdout, stderr = [x.decode(errors='backslashreplace') for x in (proc.stdout, proc.stderr)]
        if proc.returncode != 0:
            error(f'Compilation failed with return code {proc.returncode}:\n')
            info(stdout)
            error(stderr)
            raise CompilationError
        elif len(stderr) == 0:
            info('Compilation succeeded.\n')
            info(stdout)
        else:
            info('Compilation finished with warnings:\n')
            info(stdout)
            warning(stderr)


class NikssCompiler(CompilerProcessBase):
    """PSA-eBPF compiler to be used for NIKSS switches."""

    def _create_process_cmd(self, only_set_output_paths: bool) -> str:
        out_c, out_bc, out_o = [os.path.basename(self.p4_src).replace('.p4', x) for x in ['.c', '.bc', '.o']]
        self._set_compilation_outputs(os.path.join(self._output_dir, out_o))

        p4c_dir = os.getenv('P4C_ROOT')
        if p4c_dir is None:
            raise EnvironmentError('P4C_ROOT environment variable not set')

        # Compilation must be done from the P4C root directory, otherwise the output is invalid
        clean = f"rm -f {out_c} {out_bc} {out_o}"  # Files can get left here when the compilation fails
        make_vars = f"BPFOBJ={out_o} P4FILE={os.path.abspath(self.p4_src)}"
        make_vars += " P4ARGS=--Wwarn"  # By default, (even harmless) warnings are treated as errors
        make = f"make -f backends/ebpf/runtime/kernel.mk {make_vars} psa"
        mv = f"mv {out_c} {out_bc} {out_o} {os.path.abspath(self._output_dir)}"
        return f'cd {p4c_dir} && {clean} && {make} && {mv}'

# Note: a compiler for Tofino already exists in p4-utils: BF_P4C
