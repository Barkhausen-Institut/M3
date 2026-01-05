import os
import subprocess
import sys

from pathlib import Path
from textwrap import dedent
from typing import Optional


class Context:
    """
    Holds values that are needed by many commands.
    All attributes are read‑only – they are computed once in the driver.
    """

    def __init__(self) -> None:
        DEFAULTS = {
            "M3_BUILD": "release",
            "M3_TARGET": "gem5",
            "M3_ISA": "riscv64",
            "M3_OUT": "run",
        }
        for var, val in DEFAULTS.items():
            os.environ.setdefault(var, val)

        self.build = str(os.getenv("M3_BUILD"))         # debug / release / bench
        self.target = str(os.getenv("M3_TARGET"))       # gem5 / hw / …
        self.isa = str(os.getenv("M3_ISA"))             # x86_64 / riscv64 / …

        # validate variables
        if self.target == "gem5":
            if self.isa not in {"x86_64", "riscv64", "riscv32"}:
                sys.exit(f"ISA {self.isa} not supported for target gem5.")
        elif self.target in {"hw", "hw23"}:
            self.isa = "riscv64"
        else:
            sys.exit(f"Target {self.target} not supported.")
        if self.build not in {"debug", "release", "bench"}:
            sys.exit(f"Build mode {self.build} not supported.")

        # various paths
        self.root = Path(__file__).resolve().parent.parent.parent
        self.build_dir = Path("build") / f"{self.target}-{self.isa}-{self.build}"
        self.bin_dir = self.build_dir / "bin"
        self.tool_dir = self.build_dir / "toolsbin"
        self.out_dir = Path(str(os.getenv("M3_OUT")))
        self.cross_dir = self.root / f"build/cross-{self.isa}"
        self.ninjapie = Path("tools/ninjapie/ninjapie")

        # rust‑specific variables
        self.rust_toolchain = self.root / "src/toolchain/rust"
        self.rust_build = self.root / self.build_dir / "rust"
        self.rust_generic = self.root / "build/rust"
        self.rust_target = f"{self.isa}-linux-m3-musl"
        self.rust_host_args = ["--target-dir", str(self.rust_build)]
        self.rust_target_args = [
            "--target", str(self.rust_toolchain / f"{self.rust_target}.json"),
            "--target-dir", str(self.rust_build),
            "-Z", "build-std=core,alloc,std,panic_abort"
        ]

        # export variables for rust tools
        os.environ["RUST_TARGET"] = self.rust_target
        os.environ["RUST_TARGET_PATH"] = str(self.rust_toolchain)

        # create directories, if required
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Allow exclusion of the build directory from backups.
        cache_dir_tag = Path("build/CACHEDIR.TAG")
        if not cache_dir_tag.is_file():
            cache_dir_tag.write_text(dedent(
                """
                Signature: 8a477f597d28d172789f06886806bc55
                # This file is a cache directory tag created by b.
                # For information about cache directory tags, see:
                #   http://www.brynosaurus.com/cachedir/
                """
            ).lstrip())

    def isa_for_binary(self, binary: Path) -> str:
        """Return the ISA required to analyze the given binary."""
        out = subprocess.check_output(["file", "-b", str(binary)], text=True)
        if "x86-64" in out:
            return "x86_64"
        if "32-bit RISC-V" in out:
            return "riscv32"
        if "64-bit RISC-V" in out:
            return "riscv64"
        return self.isa

    def cross_prefix(self, binary: Optional[Path] = None) -> str:
        """Return the cross-compiler prefix required to analyze the given binary."""
        isa = self.isa_for_binary(binary) if binary else self.isa
        return str(self.root / f"build/cross-{isa}/host/bin/{self.cross_name(binary)}")

    def cross_name(self, binary: Optional[Path] = None) -> str:
        """Return the cross-compiler name required to analyze the given binary."""
        isa = self.isa_for_binary(binary) if binary else self.isa
        return f"{isa}-buildroot-linux-musl-"
