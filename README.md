M³
==

This is the official repository of M³: **m**icrokernel-based syste**m** for heterogeneous **m**anycores [1, 2, 3, 4]. M³ is the operating system (OS) for a new system architecture tailored for heterogeneous and more secure systems. The system architecture is based on a tiled hardware architecture and proposes a new per-tile hardware component called *trusted communication unit* (TCU). The TCU is responsible for isolating tiles from each other and for selectively allowing cross-tile communication, which has two primary benefits: First, having a common interface for all tiles simplifies the management and usage of heterogeneous tiles (e.g., collaboration between general-purpose cores and accelerators). Second, due to this architecture and the design of the OS, most cores and accelerators are not part of the trusted computing base. For example, applications can run on potentially buggy general-purpose cores (e.g., having a Meltdown-like vulnerability) with full access to all OS features without requiring other parts of the system to trust the general-purpose core or the software on it.

These two benefits are achieved through a co-design of the TCU and the M³ OS. M³ is a microkernel-based OS that runs its kernel on a dedicated *kernel tile*, and applications and OS services on the remaining *user tiles*. In contrast to the kernel tile, user tiles are not part of the trusted computing base. Applications and OS services are represented as *activities*, comparable to processes. An activity on a general-purpose tile executes code, whereas an activity on an accelerator tile uses the accelerator's logic. Lets assume for simplicity that each activity runs on a dedicated tile and is therefore initially isolated from other tiles via the TCU. Like in other microkernel-based systems, activities can communicate with each other via message passing or shared memory. However, activities on M³ communicate with each other via TCU. To that end, the TCU provides *endpoints* that need to be configured before they can be used. Endpoint configuration can only be performed by the M³ kernel. After the configuration, activities communicate directly via TCU with each other without involving the kernel.

Based on this system architecture, we are exploring different aspects like heterogeneity, security, performance, real-time guarantees, and scalability. In the past, we started with the general approach [4], followed by its scalability to large numbers of tiles [3], the ability to integrate accelerators [2], and the multiplexing of tiles among multiple applications [1].

Supported Platforms:
--------------------

Currently, M³ runs on the following target platforms:

- gem5, by adding a TCU model to gem5.
- hw, hw22, or hw23, a FPGA-based hardware platform.

The hardware platform comes in three variants: hw, hw22, and hw23. hw is the current development version of the hardware platform, whereas hw22 and hw23 correspond to the silicon version from the year 2022 and 2023, respectively. The target platform is specified with the environment variable `M3_TARGET`. For example:

    $ export M3_TARGET=gem5

Getting Started:
----------------

### 1. Initial setup

The recommended way to install all required packages is to use [Nix](https://nixos.org/):

    $ nix develop

Nix will then install all required packages in a known-to-work version and drop you into a shell to work with M³.

Without Nix, you need to install the packages manually and hope that all versions are as expected. On Debian-based distributions, this should be something like:

    $ sudo apt install git build-essential scons zlib1g-dev clang gawk m4 ninja-build libxml2-utils

Note: If you have `pyenv` installed and therefore `/usr/bin/python` does not exist, you might need to install the package `python-dev-is-python3`.

Afterwards, pull in the submodules:

    $ git submodule update --init tools/ninjapie cross/buildroot src/apps/bsdutils src/libs/musl src/libs/flac src/libs/leveldb src/libs/crypto/kecacc-xkcp

### 2. Preparations for gem5

These preparations are required when gem5 should be used as the M³ target. To use gem5, pull in the submodule `platform/gem5` and build it:

    $ git submodule update --init --recursive platform/gem5
    $ cd platform/gem5
    $ scons build/RISCV/gem5.opt # change ISA as needed

The build directory (`build/RISCV` in the example above) will be created automatically. You can build gem5 for a different ISA by changing the path to `build/X86/gem5.opt`. Note that you can specify the number of threads to use for building in the last command via, for example, `-j8`.

### 3. Preparations for the hardware platform

These preparations are required when hw/hw22/hw23 should be used as the M³ target. To use the hardware platform, pull in the submodule `platform/hw`:

    $ git submodule update --init platform/hw

The current workflow assumes that the FPGA is connected to a machine `M_fpga` that is reachable via SSH from the machine `M_m3` that hosts M³. A couple of environment variables have to be set before starting with the FPGA:

    $ export M3_HW_FPGA_HOST=ssh-alias-for-M_fpga
    $ export M3_HW_FPGA_DIR=directory-on-M_fpga     # relative to the home directory
    $ export M3_HW_FPGA_NO=fpga-number              # e.g. 0 if your FPGA has IP 192.168.42.240
    $ export M3_HW_VIVADO=path-to-vivado-on-M_fpga  # can also be vivado_lab

Note that `M_fpga` and `M_m3` can also be the same, in which case `M3_HW_FPGA_HOST` has to be set to localhost and a local SSH server is required.

The bitfiles for the hardware platform can be found in `platform/hw/fpga_tools/bitfiles`. The bitfiles are built for the Xilinx VCU118 FPGA. The following command can be used to load a specific bitfile onto the FPGA. This requires an installation of Vivado or Vivado Lab. For M3_TARGET=hw23, use:

    $ ./b loadfpga=fpga_top_v4.6.0.bit

With `M3_TARGET=hw22`, the bitfile `fpga_top_v4.4.12` needs to be used. M3_TARGET=hw is currently
not supported.

Note that the source of the hardware platform is [openly available](https://github.com/Barkhausen-Institut/M3-hardware) as well.

### 4. Cross compiler

To build M³, you need to first build a cross compiler for the desired ISA. Note that only gem5 supports all three ISAs; the hardware platform only supports RISC-V. You can build the cross compiler as follows:

    $ cd cross
    $ ./build.sh (x86_64|riscv32|riscv64)

The cross compiler will be installed to ``<m3-root>/build/cross-<ISA>``.

### 5. Rust

M³ is primarily written in Rust and requires some nightly features of Rust. The nightly toolchain will be installed automatically, but you need to install `rustup` manually first. Visit [rustup.rs](https://rustup.rs/) for further information.

### 6. Building

Before you build M³, you should choose your target platform, the build mode, and the ISA by exporting the corresponding environment variables. For example:

    $ export M3_BUILD=release M3_TARGET=gem5 M3_ISA=riscv64

Now, M³ can be built by using the script `b`:

    $ ./b

### 7. Running

On all platforms, scenarios can be run by starting the desired boot script in the directory `boot`, e.g.:

    $ ./b run boot/hello.xml

Note that this command ensures that everything is up to date as well. For more information, run

    $ ./b -h

### 8. M³Linux

M³Linux allows to run Linux on an isolated tile within M³. Before it can be used, the submodule has to be pulled in:

    $ git submodule update --init --recursive src/m3lx

Additionally, the Rust target needs to be installed:

    $ rustup target add riscv64gc-unknown-linux-gnu

M³Linux consists of Linux itself, riscv-pk with the bbl bootloader, and applications. The applications can both interface with M³ and Linux and thereby bridge the gap between both systems.

Linux and bbl need to be built explicitly due to the long build times and different build systems. `b` offers two commands for this purpose:

1. `./b mklx`: build Linux including bbl
2. `./b mkbbl`: build bbl

As bbl contains Linux as the payload, bbl needs to be rebuilt whenever Linux changes. Note that the M³Linux applications are automatically built with every `b` run and initrd and DTS for Linux are generated before every start.

M³Linux can be used via the boot scripts in `boot/linux/`. Note however, that M³Linux currently only works on RISC-V (both gem5 and hw23).

References:
-----------

**Warning:** Some papers below use the name *data transfer unit (DTU)* instead of TCU and some use the name *controller* instead of kernel.

[1] Nils Asmussen, Sebastian Haas, Carsten Weinhold, Till Miemietz, and Michael Roitzsch. **Efficient and Scalable Core Multiplexing with M³v**. In Proceedings of the Twenty-seventh International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS'22), pages 452–466, February 2022.

[2] Nils Asmussen, Michael Roitzsch, and Hermann Härtig. **M³x: Autonomous Accelerators via Context-Enabled Fast-Path Communication**. USENIX Annual Technical Conference (ATC'19), July 2019

[3] Matthias Hille, Nils Asmussen, Pramod Bhatotia, and Hermann Härtig, **SemperOS: A Distributed Capability System**, USENIX Annual Technical Conference (ATC'19), July 2019

[4] Nils Asmussen, Marcus Völp, Benedikt Nöthen, Hermann Härtig, and Gerhard Fettweis. **M³: A Hardware/Operating-System Co-Design to Tame Heterogeneous Manycores**. In Proceedings of the Twenty-first International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS'16), pages 189-203, April 2016.
