from ninjapie import Env, Generator, SourcePath, BuildPath, BuildEdge, Rule

import os
import sys
import subprocess

target = os.environ.get('M3_TARGET')
isa = os.environ.get('M3_ISA', 'x86_64')
if (target in ['hw', 'hw22', 'hw23']) and isa != 'riscv64':
    exit('Unsupport ISA "' + isa + '" for hw')

if isa == 'riscv32':
    rustisa = 'riscv32'
    rustabi = 'musl'
    cross = 'riscv32-buildroot-linux-musl-'
    crts0 = ['crt0.o', 'crtbegin.o']
    crtsn = ['crtend.o']
elif isa == 'riscv64':
    rustisa = 'riscv64'
    rustabi = 'musl'
    cross = 'riscv64-buildroot-linux-musl-'
    crts0 = ['crt0.o', 'crtbegin.o']
    crtsn = ['crtend.o']
else:
    rustisa = isa
    rustabi = 'musl'
    cross = 'x86_64-buildroot-linux-musl-'
    crts0 = ['crt0.o', 'crt1.o', 'crtbegin.o']
    crtsn = ['crtend.o', 'crtn.o']
if os.environ.get('M3_BUILD') == 'coverage':
    rustabi = 'muslcov'
crossdir = os.path.abspath('build/cross-' + isa + '/host')
crossver = '13.2.0'

# ensure that the cross compiler is installed and up to date
crossgcc = crossdir + '/bin/' + cross + 'g++'
if not os.path.isfile(crossgcc):
    sys.exit('Please install the ' + isa + ' cross compiler first '
             + '(cd cross && ./build.sh ' + isa + ').')
else:
    ver = subprocess.check_output([crossgcc, '-dumpversion']).decode().strip()
    if ver != crossver:
        sys.exit('Please update the ' + isa + ' cross compiler from '
                 + ver + ' to ' + crossver + ' (cd cross && ./build.sh ' + isa + ' clean all).')

bins = {
    'bin': [],
    'sbin': [],
}
rustapps = []
rustlibs = []
rustfeatures = []
if isa == 'riscv64' or isa == 'riscv32':
    link_addr = 0x11000000
else:
    link_addr = 0x1000000


class M3Env(Env):
    def clone(self):
        env = Env.clone(self)
        if hasattr(self, 'hostenv'):
            env.hostenv = self.hostenv
        return env

    def try_execute(self, cmd):
        return subprocess.getstatusoutput(cmd)[0] == 0

    def m3_hex(self, gen, out, input):
        out = BuildPath.new(self, out)
        gen.add_build(BuildEdge(
            'elf2hex',
            outs=[out],
            ins=[SourcePath.new(self, input)],
            deps=[BuildPath(self['TOOLDIR'] + '/elf2hex')],
        ))
        return out

    def soft_float(self):
        if self['ISA'] == 'x86_64':
            self['ASFLAGS'] += ['-msoft-float', '-mno-sse']
            self['CFLAGS'] += ['-msoft-float', '-mno-sse']
            self['CXXFLAGS'] += ['-msoft-float', '-mno-sse']
        elif self['ISA'] == 'riscv32':
            self['ASFLAGS'] += ['-mabi=ilp32']
            self['CFLAGS'] += ['-march=rv32imac', '-mabi=ilp32']
            self['CXXFLAGS'] += ['-march=rv32imac', '-mabi=ilp32']
            self['LINKFLAGS'] += ['-march=rv32imac', '-mabi=ilp32']
            # make sure that embedded C-code or similar (minicov with llvm-profile library)
            # for Rust is built with soft-float as well
            cflags = os.environ.get('TARGET_CFLAGS')
            if cflags:
                cflags = cflags.replace('-march=rv32imafdc', '-march=rv32imac')
                cflags = cflags.replace('-mabi=ilp32d', '-mabi=ilp32')
                self['CRGENV']['TARGET_CFLAGS'] = cflags
        elif self['ISA'] == 'riscv64':
            self['ASFLAGS'] += ['-mabi=lp64']
            self['CFLAGS'] += ['-march=rv64imac', '-mabi=lp64']
            self['CXXFLAGS'] += ['-march=rv64imac', '-mabi=lp64']
            # make sure that embedded C-code or similar (minicov with llvm-profile library)
            # for Rust is built with soft-float as well
            cflags = os.environ.get('TARGET_CFLAGS')
            if cflags:
                cflags = cflags.replace('-march=rv64imafdc', '-march=rv64imac')
                cflags = cflags.replace('-mabi=lp64d', '-mabi=lp64')
                self['CRGENV']['TARGET_CFLAGS'] = cflags
        # use the soft-float target spec for rust
        self['TRIPLE'] += 'sf'

    def m3_exe(self, gen, out, ins, libs=[], dir='bin', NoSup=False,
               ldscript='default', varAddr=True):
        env = self.clone()

        m3libs = ['base', 'm3', 'thread']

        if not NoSup:
            baselibs = ['gcc', 'c', 'gem5', 'm', 'gloss', 'stdc++', 'supc++']
            # add the C library again, because the linker isn't able to resolve m3::Dir::readdir
            # otherwise, even though we use "--start-group ... --end-group". I have no idea why
            # that occurs now and why only for this symbol.
            libs = baselibs + m3libs + libs + ['c']

        ldconf = env['LDDIR'] + '/ld-' + ldscript + '.conf'
        env['LINKFLAGS'] += ['-Wl,-T,' + ldconf]
        deps = [ldconf] + [env['LIBDIR'] + '/' + crt for crt in crts0 + crtsn]

        if varAddr:
            global link_addr
            env['LINKFLAGS'] += ['-Wl,--section-start=.text=' + ('0x%x' % link_addr)]
            link_addr += 0x30000

        # we provide our own start files, unless no start files are desired by the app
        if '-nostartfiles' not in env['LINKFLAGS']:
            env['LINKFLAGS'] += ['-nostartfiles']
            crt0_objs = [BuildPath(self['BINDIR'] + '/' + f) for f in crts0]
            crtn_objs = [BuildPath(self['BINDIR'] + '/' + f) for f in crtsn]
            ins = crt0_objs + ins + crtn_objs

        # TODO workaround to ensure that our memcpy, etc. is used instead of the one from Rust's
        # compiler-builtins crate (or musl), because those are poor implementations.
        fileext = 'sf.o' if env['TRIPLE'].endswith('sf') else 'o'
        for cc in ['memcmp', 'memcpy', 'memset', 'memmove', 'memzero']:
            src = SourcePath('src/libs/memory/' + cc + '.cc')
            ins.append(BuildPath.with_file_ext(env, src, fileext))

        bin = env.cxx_exe(gen, out, ins, libs, deps)
        if env['TGT'] in ['hw', 'hw22', 'hw23']:
            hex = env.m3_hex(gen, out + '.hex', bin)
            env.install(gen, env['MEMDIR'], hex)

        env.install(gen, env['BINDIR'], bin)
        stripped = env.strip(gen, out=BuildPath(env['BINDIRSTRIP'] + '/' + out), input=bin)
        if dir is not None:
            bins[dir].append(stripped)
        return bin

    def m3_rust_exe(self, gen, out, libs=[], dir='bin', startup=None,
                    ldscript='default', varAddr=True, std=False, features=[]):
        global rustapps, rustfeatures
        if out != 'tilemux':
            rustapps += [self.cur_dir]
        rustfeatures += features

        env = self.clone()
        env['LINKFLAGS'] += ['-Wl,-z,muldefs']
        env['LIBPATH'] += [env['RUSTLIBS']]
        ins = [] if startup is None else [startup]
        if std:
            libs = ['c', 'gem5', 'gcc', 'gcc_eh', out] + libs
        elif out == 'tilemux':
            libs = ['simplecsf', 'gem5sf', out] + libs
        else:
            libs = ['simplec', 'gem5', 'gcc', 'gcc_eh', out] + libs
        env['LINKFLAGS'] += ['-nodefaultlibs']

        return env.m3_exe(gen, out, ins, libs, dir, True, ldscript, varAddr)

    def rust_exe(self, gen, out, deps=[]):
        deps += env.glob(gen, '**/*.rs') + [SourcePath.new(self, 'Cargo.toml')]
        cfg = SourcePath.new(self, '.cargo/config.toml')
        if os.path.isfile(cfg):
            deps += [cfg]
        return Env.rust_exe(self, gen, out, deps=deps)

    def m3_rust_lib(self, gen, features=[]):
        global rustlibs, rustfeatures
        rustlibs += [self.cur_dir]
        rustfeatures += features

    def add_rust_features(self):
        if self['BUILD'] == 'bench':
            self['CRGFLAGS'] += ['--features', 'base/bench']
        if self['BUILD'] == 'coverage' and self['ISA'] == 'riscv64':
            self['CRGFLAGS'] += ['--features', 'base/coverage']
        self['CRGFLAGS'] += ['--features', 'base/' + self['TGT']]

    def rust_deps(self):
        global rustlibs
        deps = [SourcePath('src/Cargo.toml'), SourcePath('src/.cargo/config.toml')]
        deps += [SourcePath('rust-toolchain.toml')]
        if os.path.isfile('src/toolchain/rust/' + self['TRIPLE'] + '.json'):
            deps += [SourcePath('src/toolchain/rust/' + self['TRIPLE'] + '.json')]
        for cr in rustlibs:
            deps += [SourcePath(cr + '/Cargo.toml')]
            deps += env.glob(gen, SourcePath(cr + '/**/*.rs'))
        return deps

    def m3_cargo(self, gen, out):
        env = self.clone()
        # better specify the path to the json file, because Rust seems to be picky about the triple
        # name in some cases. For example, it doesn't like riscv32-linux-m3-muslsf for some reason.
        # if we specify a path, Rust doesn't seem to care.
        tgtspec = os.path.abspath('src/toolchain/rust/' + env['TRIPLE'] + '.json')
        env['CRGFLAGS'] += ['--target', tgtspec]
        env['CRGFLAGS'] += ['-Z build-std=core,alloc,std,panic_abort']
        env.add_rust_features()
        return env.rust_exe(gen, out, self.rust_deps())

    def m3_cargo_ws(self, gen):
        global rustapps, rustfeatures
        env = self.clone()

        outs = []
        deps = self.rust_deps()
        for cr in rustapps:
            deps += [SourcePath(cr + '/Cargo.toml')] + env.glob(gen, SourcePath(cr + '/**/*.rs'))
            crate_name = os.path.basename(cr)
            outs.append('lib' + crate_name + '.a')
            # specify crates explicitly, because some crates are only supported by some targets
            env['CRGFLAGS'] += ['-p', crate_name]

        tgtspec = os.path.abspath('src/toolchain/rust/' + env['TRIPLE'] + '.json')
        env['CRGFLAGS'] += ['--target', tgtspec]
        env['CRGFLAGS'] += ['-Z build-std=core,alloc,std,panic_abort']
        for f in rustfeatures:
            env['CRGFLAGS'] += ['--features', f]
        env.add_rust_features()

        outs = env.rust(gen, outs, deps)
        for o in outs:
            env.install(gen, outdir=env['RUSTLIBS'], input=o)
        return outs

    def lx_exe(self, gen, out, ins, libs=[], dir='bin'):
        env = self.clone()
        env['LIBPATH'] += [env['LXLIBDIR']]

        libs = ['base-lx', 'm3-lx', 'thread', 'gem5'] + libs
        bin = env.cxx_exe(gen, out, ins, libs, [])
        env.install(gen, env['RUSTBINS'], bin)
        return bin

    def lx_cargo_ws(self, gen, outs):
        env = self.clone()

        deps = env.rust_deps()
        deps += [SourcePath.new(env, 'Cargo.toml'), SourcePath.new(env, '.cargo/config.toml')]
        for o in outs:
            deps += [SourcePath.new(env, o + '/Cargo.toml')]
            deps += env.glob(gen, SourcePath.new(env, o + '/**/*.rs'))

        env['CRGFLAGS'] += ['--target', env['TRIPLE']]
        env.add_rust_features()

        outs = env.rust(gen, outs, deps)
        for o in outs:
            env.install(gen, outdir=env['RUSTBINS'], input=o)
        return outs

    def build_fs(self, gen, out, dir, blocks, inodes):
        deps = [BuildPath(self['TOOLDIR'] + '/mkm3fs')]

        global bins
        for dirname, dirbins in bins.items():
            for b in dirbins:
                dst = self.install(gen, outdir=BuildPath.new(self, dirname), input=b)
                deps += [dst]

        dir_env = self.clone()
        dir_env['INSTFLAGS'] += ['-d']
        file_env = self.clone()
        file_env['INSTFLAGS'] += ['-m 0644']

        for f in self.glob(gen, dir + '/**/*'):
            src = SourcePath(f)
            dst = BuildPath.new(self, src)
            if os.path.isfile(src):
                file_env.install_as(gen, dst, src)
            elif os.path.isdir(src):
                dir_env.install_as(gen, dst, src)
            deps += [dst]

        out = BuildPath(self['BUILDDIR'] + '/' + out)
        gen.add_build(BuildEdge(
            'mkm3fs',
            outs=[out],
            ins=[],
            deps=deps,
            vars={
                'dir': BuildPath.new(self, dir),
                'blocks': blocks,
                'inodes': inodes
            }
        ))
        return out


# build basic environment
env = M3Env()

env['CPPPATH'] += ['src/include']
env['ASFLAGS'] += ['-Wl,-W', '-Wall', '-Wextra']
env['CFLAGS'] += ['-std=c99', '-Wall', '-Wextra', '-Wsign-conversion', '-fdiagnostics-color=always']
env['CXXFLAGS'] += ['-Wall', '-Wextra', '-Wsign-conversion', '-fdiagnostics-color=always']
env['CPPFLAGS'] += ['-U_FORTIFY_SOURCE']
env['CRGFLAGS'] += ['--color=always']
if os.environ.get('M3_VERBOSE', '0') == '1':
    env['CRGFLAGS'] += ['-v']
else:
    env['CRGFLAGS'] += ['-q']
env['RUSTOUT'] = 'rust/'

# add build-dependent flags (debug/release)
btype = os.environ.get('M3_BUILD')
if btype == 'debug':
    env['CXXFLAGS'] += ['-O0', '-g']
    env['CFLAGS'] += ['-O0', '-g']
    env['ASFLAGS'] += ['-g']
else:
    env['CRGFLAGS'] += ['--release']
    env['CXXFLAGS'] += ['-O2', '-DNDEBUG', '-flto=auto']
    env['CFLAGS'] += ['-O2', '-DNDEBUG', '-flto=auto']
    env['LINKFLAGS'] += ['-O2', '-flto=auto']
if btype == 'bench':
    env['CPPFLAGS'] += ['-Dbench']

# add some important paths
builddir = 'build/' + target + '-' + isa + '-' + btype
env['TGT'] = target
env['ISA'] = isa
env['BUILD'] = btype
env['BUILDDIR'] = builddir
env['BINDIR'] = builddir + '/bin'
env['BINDIRSTRIP'] = builddir + '/bin/stripped'
env['LIBDIR'] = builddir + '/bin'
env['LXLIBDIR'] = builddir + '/lxlib'
env['MEMDIR'] = builddir + '/mem'
env['TOOLDIR'] = builddir + '/toolsbin'
env['RUSTLIBS'] = builddir + '/rust/libs'
env['LDDIR'] = builddir + '/ldscripts'

# for host compilation
hostenv = env.clone()
hostenv['CXXFLAGS'] += ['-std=c++11']
hostenv['CPPFLAGS'] += ['-D__tools__']
if btype != 'debug':
    hostenv.remove_flag('CXXFLAGS', '-flto=auto')
    hostenv.remove_flag('CFLAGS', '-flto=auto')
    hostenv.remove_flag('LINKFLAGS', '-flto=auto')

# for target compilation
env['CROSS'] = cross
env['CROSSDIR'] = crossdir
env['CROSSVER'] = crossver
env['CXX'] = cross + 'g++'
env['CPP'] = cross + 'cpp'
env['AS'] = cross + 'gcc'
env['CC'] = cross + 'gcc'
env['AR'] = cross + 'gcc-ar'
env['RANLIB'] = cross + 'gcc-ranlib'
env['STRIP'] = cross + 'strip'
env['SHLINK'] = cross + 'gcc'

# basic flags for target compilation
env['CPPFLAGS'] += ['-D__' + target + '__']
env['CFLAGS'] += ['-gdwarf-2', '-fno-stack-protector', '-ffunction-sections', '-fdata-sections']
env['CXXFLAGS'] += [
    '-std=c++20', '-fno-strict-aliasing', '-gdwarf-2', '-fno-omit-frame-pointer',
    '-fno-stack-protector', '-Wno-address-of-packed-member',
    '-ffunction-sections', '-fdata-sections'
]
env['LINKFLAGS'] += ['-Wl,--gc-section', '-Wno-lto-type-mismatch', '-fno-stack-protector']

# for linux compilation
lxenv = env.clone()
lxenv['CPPFLAGS'] += ['-D__m3lx__']
lxenv['TRIPLE'] = 'riscv64gc-unknown-linux-gnu'
lxenv['RUSTOUT'] = 'm3lx'
lxenv['RUSTBINS'] = builddir + '/lxbin'

env.hostenv = hostenv

# m3-specific settings
env['CXXFLAGS'] += ['-fno-builtin', '-fno-threadsafe-statics']
env['CPPFLAGS'] += ['-D_GNU_SOURCE']
env['TRIPLE'] = rustisa + '-linux-m3-' + rustabi
if isa == 'x86_64':
    # disable red-zone for all applications, because we used the application's stack in rctmux's
    # IRQ handlers since applications run in privileged mode. TODO can we enable that now?
    env['CFLAGS'] += ['-mno-red-zone']
    env['CXXFLAGS'] += ['-mno-red-zone']
    env['LINKFLAGS'] += ['-Wl,-z,noexecstack']
elif isa == 'riscv32':
    env['CFLAGS'] += ['-march=rv32imafdc', '-mabi=ilp32d']
    env['CXXFLAGS'] += ['-march=rv32imafdc', '-mabi=ilp32d']
    env['LINKFLAGS'] += ['-march=rv32imafdc', '-mabi=ilp32d']
    env['ASFLAGS'] += ['-march=rv32imafdc', '-mabi=ilp32d']
elif isa == 'riscv64':
    env['CFLAGS'] += ['-march=rv64imafdc', '-mabi=lp64d']
    env['CXXFLAGS'] += ['-march=rv64imafdc', '-mabi=lp64d']
    env['LINKFLAGS'] += ['-march=rv64imafdc', '-mabi=lp64d']
    env['ASFLAGS'] += ['-march=rv64imafdc', '-mabi=lp64d']
env['CPPPATH'] += [
    # cross directories only to make clangd happy
    crossdir + '/' + cross[:-1] + '/include/c++/' + crossver,
    crossdir + '/' + cross[:-1] + '/include/c++/' + crossver + '/' + cross[:-1],
    'src/libs/musl/arch/' + isa,
    'src/libs/musl/arch/generic',
    'src/libs/musl/m3/include/' + isa,
    'src/libs/musl/include',
]
# we install the crt* files to that directory
env['SYSGCCLIBPATH'] = crossdir + '/lib/gcc/' + cross[:-1] + '/' + crossver
# no build-id because it confuses gem5
env['LINKFLAGS'] += ['-static', '-Wl,--build-id=none']
# binaries get very large otherwise
env['LINKFLAGS'] += ['-Wl,-z,max-page-size=4096', '-Wl,-z,common-page-size=4096']
env['LIBPATH'] += [crossdir + '/lib', env['LIBDIR']]

# start the generation
gen = Generator()

gen.add_rule('mkm3fs', Rule(
    cmd=env['TOOLDIR'] + '/mkm3fs $out $dir $blocks $inodes 0',
    desc='MKFS $out',
))
gen.add_rule('elf2hex', Rule(
    cmd=env['TOOLDIR'] + '/elf2hex $in > $out',
    desc='ELF2HEX $out',
))

# generate build edges
env.sub_build(gen, 'src')
env.sub_build(gen, 'tools')
if isa == 'riscv64' and os.path.exists('src/m3lx/build.py'):
    lxenv.sub_build(gen, 'src/m3lx')

# finally, write it to file
gen.write_to_file(defaults={})
gen.write_compile_cmds(outdir='build')
