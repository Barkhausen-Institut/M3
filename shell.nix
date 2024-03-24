{ nixpkgs ? <nixpkgs>, system ? builtins.currentSystem }:
with import nixpkgs { inherit system; };

let
    # general dependencies
    generalInputs = [ less git gawk openssh which rsync wget cpio ];

    # building gem5
    gem5Inputs = [
        scons gcc zlib.dev protobuf gnum4
        python311Full python311Packages.pydot pre-commit
    ];

    # building the C cross compiler
    crossInputs = [ gcc perl unzip bc flock ] ++
        lib.optional stdenv.isDarwin (runCommand "CoreFoundation" {} ''
            # I think the vanilla CoreFoundation package should add its frameworks search path
            # but it doesn’t, so we stitch together a new package here
            mkdir -p $out/nix-support
            echo NIX_LDFLAGS+=\" -F$out/Library/Frameworks\" > $out/nix-support/setup-hook
            ln -s ${darwin.apple_sdk.frameworks.CoreFoundation}/Library $out/Library
        '');

    # building the M3 system and applications
    # we want to have clang 15 for clang-format (the clang package is still at 11.1.0)
    m3Inputs = [ rustup ninja llvmPackages_15.clang-unwrapped libxml2 python311Packages.autopep8 ];

    # building M³Linux
    m3lxInputs = [ flex bison dtc ];

    # build system support on Darwin
    darwinInputs = lib.attrValues {
        nproc = writeScriptBin "nproc" ''#!/bin/sh
            exec sysctl -n hw.activecpu
        '';
    };

in mkShellNoCC {

    packages = generalInputs ++ gem5Inputs ++ crossInputs ++ m3Inputs ++ m3lxInputs ++
        lib.optionals stdenv.isDarwin darwinInputs;

    hardeningDisable = [ "format" ];  # breaks cross-gcc build

    shellHook = ''
        # having these set breaks some configure checks
        unset CC CXX AS LD AR RANLIB NM OBJCOPY OBJDUMP READELF SIZE STRINGS STRIP

        export RUSTUP_HOME=$PWD/.rustup
        export CARGO_HOME=$PWD/.cargo
        export M3_TARGET=''${M3_TARGET:-gem5}
        export M3_ISA=''${M3_ISA:-riscv64}
        export M3_BUILD=''${M3_BUILD:-release}

        # determine correct terminfo directory. that is needed for ncurses, which is for example
        # used by gdb --tui. without setting TERMINFO_DIRS, a path in the cross directory will be
        # used and gdb quits as it does not find the info file there.
        for dir in /etc/terminfo /lib/terminfo /usr/share/terminfo; do
            if [ -f "$dir/''${TERM:0:1}/$TERM" ]; then
                export TERMINFO_DIRS="$dir"
                break
            fi
        done

        test -r ~/.shellrc && . ~/.shellrc
    '';
}
