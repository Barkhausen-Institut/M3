#!/usr/bin/env -S python3 -B

import copy
import src.tools.ninjagen as ninjagen
import os, sys
from subprocess import check_output
from glob import glob

target = os.environ.get('M3_TARGET')
if target == 'gem5' or target == 'hw':
    isa = os.environ.get('M3_ISA', 'x86_64')
    if target == 'hw' and isa != 'riscv':
        exit('Unsupport ISA "' + isa + '" for hw')

    if isa == 'arm':
        rustabi = 'gnueabihf'
        cross   = 'arm-none-eabi-'
        crts    = ['crt0.o', 'crtbegin.o', 'crtend.o', 'crtfastmath.o', 'crti.o', 'crtn.o']
    elif isa == 'riscv':
        rustabi = 'gnu'
        cross   = 'riscv64-unknown-elf-'
        crts    = ['crt0.o', 'crtbegin.o', 'crtend.o', 'crti.o', 'crtn.o']
    else:
        rustabi = 'gnu'
        cross   = 'x86_64-elf-m3-'
        crts    = ['crt0.o', 'crt1.o', 'crtbegin.o', 'crtend.o', 'crtn.o']
    crossdir    = os.path.abspath('build/cross-' + isa)
    crossver    = '10.1.0'
    platform    = 'kachel'
else:
    # build for host by default
    isa = os.popen('uname -m').read().strip()
    if isa == 'armv7l':
        isa = 'arm'

    target      = 'host'
    if os.environ.get('M3_BUILD') == 'coverage':
        rustabi = 'cov'
    else:
        rustabi = 'gnu'
    cross       = ''
    crossdir    = ''
    crossver    = ''
    platform    = 'host'

# ensure that the cross compiler is installed and up to date
if cross != '':
    crossgcc = crossdir + '/bin/' + cross + 'g++'
    if not os.path.isfile(crossgcc):
        sys.exit('Please install the ' + isa + ' cross compiler first ' \
            + '(cd cross && ./build.sh ' + isa + ').')
    else:
        ver = check_output([crossgcc, '-dumpversion']).decode().strip()
        if ver != crossver:
            sys.exit('Please update the ' + isa + ' cross compiler from ' \
                + ver + ' to ' + crossver + ' (cd cross && ./build.sh ' + isa + ' --rebuild).')

bins = {
    'bin': [],
    'sbin': [],
}
ldscripts = {}
if isa == 'riscv':
    link_addr = 0x10400000
else:
    link_addr = 0x400000

class M3Env(ninjagen.Env):
    def __init__(self):
        super().__init__()
        self.rustcrates = []

    def clone(self):
        env = M3Env()
        env.cwd = self.cwd
        env.vars = copy.deepcopy(self.vars)
        if hasattr(self, 'hostenv'):
            env.hostenv = self.hostenv
        return env

    def m3_hex(self, gen, out, input):
        out = ninjagen.BuildPath.new(self, out)
        gen.add_build(ninjagen.BuildEdge(
            'elf2hex',
            outs = [out],
            ins = [ninjagen.SourcePath.new(self, input)],
            deps = [ninjagen.BuildPath(self['TOOLDIR'] + '/elf2hex')],
        ))
        return out

    def m3_exe(self, gen, out, ins, libs = [], dir = 'bin', NoSup = False,
               ldscript = 'default', varAddr = True):
        env = self.clone()

        m3libs = ['base', 'm3', 'thread']

        if env['PLATF'] == 'kachel':
            if not NoSup:
                baselibs = ['gcc', 'c', 'gem5', 'm', 'gloss', 'stdc++', 'supc++']
                # add the C library again, because the linker isn't able to resolve m3::Dir::readdir
                # otherwise, even though we use "--start-group ... --end-group". I have no idea why
                # that occurs now and why only for this symbol.
                libs = baselibs + m3libs + libs + ['c']

            global ldscripts
            env['LINKFLAGS'] += ['-Wl,-T,' + ldscripts[ldscript]]
            deps = [ldscripts[ldscript]] + [env['LIBDIR'] + '/' + crt for crt in crts]

            if varAddr:
                global link_addr
                env['LINKFLAGS'] += ['-Wl,--section-start=.text=' + ('0x%x' % link_addr)]
                link_addr += 0x30000

            # search for crt* in our library dir
            env['LINKFLAGS'] += ['-B' + os.path.abspath(env['LIBDIR'])]

            # TODO workaround to ensure that our memcpy, etc. is used instead of the one from Rust's
            # compiler-builtins crate (or musl), because those are poor implementations.
            for cc in ['memcmp', 'memcpy', 'memset', 'memmove', 'memzero']:
                src = ninjagen.SourcePath('src/libs/memory/' + cc + '.cc')
                ins.append(ninjagen.BuildPath.with_ending(env, src, '.o'))

            bin = env.cxx_exe(gen, out, ins, libs, deps)
            if env['TGT'] == 'hw':
                hex = env.m3_hex(gen, out + '.hex', bin)
                env.install(gen, env['MEMDIR'], hex)
        else:
            if not NoSup:
                libs = m3libs + ['pthread'] + libs
            bin = env.cxx_exe(gen, out, ins, libs)

        env.install(gen, env['BINDIR'], bin)
        if not dir is None:
            bins[dir].append(bin)
        return bin

    def m3_rust_lib(self, gen):
        self.rustcrates += [env.cwd.path]

    def m3_rust_exe(self, gen, out, libs = [], dir = 'bin', startup = None,
                    ldscript = 'default', varAddr = True):
        self.rustcrates += [self.cwd.path]

        env = self.clone()
        env['LINKFLAGS'] += ['-Wl,-z,muldefs']
        env['LIBPATH']   += [env['RUSTBINS']]

        if env['PLATF'] == 'kachel':
            ins     = [] if startup is None else [startup]
            libs    = ['simplec', 'gem5', 'gcc', out] + libs
            env['LINKFLAGS'] += ['-nodefaultlibs']
        else:
            ins     = []
            # leave the host lib in here as well to make it a dependency
            libs    = ['c', 'host', 'gcc', 'pthread', out] + libs
            # ensure that the host library gets linked in
            env['LINKFLAGS'] += ['-Wl,--whole-archive', '-lhost', '-Wl,--no-whole-archive']
            if env['BUILD'] == 'coverage':
                libs += ['gcov', 'llvmprofile']

        return env.m3_exe(gen, out, ins, libs, dir, True, ldscript, varAddr)

    def cargo_ws(self, gen):
        outs = []
        deps = []

        env = self.clone()
        for cr in self.rustcrates:
            crate_name = os.path.basename(cr)
            out = ninjagen.BuildPath(env['RUSTBINS'] + '/lib' + crate_name + '.a')
            outs.append(out)
            deps += [cr + '/Cargo.toml', '.cargo/config']
            deps += env.glob(cr + '/**/*.rs', recursive = True)
            deps += ['src/toolchain/rust/' + env['TRIPLE'] + '.json']
            # specify crates explicitly, because some crates are only supported by some targets
            env['CRGFLAGS'] += ['-p', crate_name]

        gen.add_build(ninjagen.BuildEdge(
            'cargo_ws',
            outs = outs,
            ins = [],
            deps = deps,
            vars = { 'cargoflags' : 'build -Z build-std=core,alloc --target ' + env['TRIPLE'] + ' ' + ' '.join(env['CRGFLAGS']), 'dir': '.' }
        ))

    def build_fs(self, gen, out, dir, blocks, inodes):
        deps = [ninjagen.BuildPath(env['TOOLDIR'] + '/mkm3fs')]

        global bins
        for dirname, dirbins in bins.items():
            for b in dirbins:
                dst = ninjagen.BuildPath.new(self, dirname + '/' + os.path.basename(b))
                self.strip(gen, out = dst, input = b)
                deps += [dst]
        for f in glob(ninjagen.SourcePath.new(self, dir + '/**/*'), recursive = True):
            src = ninjagen.SourcePath(f)
            dst = ninjagen.BuildPath.new(self, src)
            if os.path.isfile(src):
                self.install_as(gen, dst, src, flags = '-m 0644')
            elif os.path.isdir(src):
                self.install_as(gen, dst, src, flags = '-d')
            deps += [dst]

        out = ninjagen.BuildPath(env['BUILDDIR'] + '/' + out)
        gen.add_build(ninjagen.BuildEdge(
            'mkm3fs',
            outs = [out],
            ins = [],
            deps = deps,
            vars = {
                'dir' : ninjagen.BuildPath.new(self, dir),
                'blocks' : blocks,
                'inodes' : inodes
            }
        ))
        return out

# build basic environment
env = M3Env()

env['CPPFLAGS'] += ['-D__' + target + '__', '-D__' + platform + '__']
env['CPPPATH']  += ['src/include']
env['CFLAGS']   += ['-std=c99', '-Wall', '-Wextra', '-Wsign-conversion', '-fdiagnostics-color=always']
env['CXXFLAGS'] += ['-std=c++17', '-Wall', '-Wextra', '-Wsign-conversion', '-fdiagnostics-color=always']

# for host compilation
hostenv = env.clone()
hostenv['CPPFLAGS'] += [' -D__tools__']
hostenv['TRIPLE']   = 'x86_64-unknown-linux-gnu'    # TODO don't hardcode that

env.hostenv = hostenv

# for target compilation
env['CXX']          = cross + 'g++'
env['CPP']          = cross + 'cpp'
env['AS']           = cross + 'gcc'
env['CC']           = cross + 'gcc'
env['AR']           = cross + 'gcc-ar'
env['RANLIB']       = cross + 'gcc-ranlib'
env['STRIP']        = cross + 'strip'

env['CXXFLAGS']     += [
    '-ffreestanding', '-fno-strict-aliasing', '-gdwarf-2', '-fno-omit-frame-pointer',
    '-fno-threadsafe-statics', '-fno-stack-protector', '-Wno-address-of-packed-member'
]
env['CPPFLAGS']     += ['-U_FORTIFY_SOURCE', '-D_GNU_SOURCE']
env['CFLAGS']       += ['-gdwarf-2', '-fno-stack-protector']
env['ASFLAGS']      += ['-Wl,-W', '-Wall', '-Wextra']
env['LINKFLAGS']    += ['-Wl,--no-gc-sections', '-Wno-lto-type-mismatch', '-fno-stack-protector']
env['TRIPLE']       = isa + '-unknown-' + target + '-' + rustabi
if os.environ.get('M3_VERBOSE', 0) != 0:
    env['CRGFLAGS'] += ['-v']
else:
    env['CRGFLAGS'] += ['-q']

# add build-dependent flags (debug/release)
btype = os.environ.get('M3_BUILD')
if btype == 'debug' or btype == 'coverage':
    env['CXXFLAGS']         += ['-O0', '-g']
    env['CFLAGS']           += ['-O0', '-g']
    if target == 'host' and btype == 'coverage':
        env['CXXFLAGS']     += ['--coverage']
        env['CFLAGS']       += ['--coverage']
        env['LINKFLAGS']    += ['-lgcov']
    elif target == 'host':
        env['CXXFLAGS']     += ['-fsanitize=address', '-fsanitize=undefined']
        env['CFLAGS']       += ['-fsanitize=address', '-fsanitize=undefined']
        env['LINKFLAGS']    += ['-fsanitize=address', '-fsanitize=undefined', '-lasan', '-lubsan']
    env['ASFLAGS']          += ['-g']
    hostenv['CXXFLAGS']     += ['-O0', '-g']
    hostenv['CFLAGS']       += ['-O0', '-g']
else:
    env['CRGFLAGS']         += ['--release']
    hostenv['CRGFLAGS']     += ['--release']
    env['CXXFLAGS']         += ['-O2', '-DNDEBUG', '-flto']
    env['CFLAGS']           += ['-O2', '-DNDEBUG', '-flto']
    env['LINKFLAGS']        += ['-O2', '-flto']
builddir = 'build/' + target + '-' + isa + '-' + btype

# add some important paths
env['TGT']          = target
env['PLATF']        = platform
env['ISA']          = isa
env['BUILD']        = btype
env['BUILDDIR']     = builddir
env['BINDIR']       = builddir + '/bin'
env['LIBDIR']       = builddir + '/bin'
env['MEMDIR']       = builddir + '/mem'
env['TOOLDIR']      = builddir + '/tools'
env['CROSS']        = cross
env['CROSSDIR']     = crossdir
env['CROSSVER']     = crossver
rustbuild = btype if btype != 'coverage' else 'debug'
env['RUSTBINS']     = 'build/rust/' + env['TRIPLE'] + '/' + rustbuild
hostenv['TOOLDIR']  = env['TOOLDIR']
hostenv['BINDIR']   = env['BINDIR']
hostenv['BUILDDIR'] = env['BUILDDIR']
hostenv['RUSTBINS'] = 'build/rust/' + hostenv['TRIPLE'] + '/' + rustbuild

# add platform-dependent stuff to env
if platform == 'kachel':
    if isa == 'x86_64':
        # disable red-zone for all applications, because we used the application's stack in rctmux's
        # IRQ handlers since applications run in privileged mode. TODO can we enable that now?
        env['CFLAGS']       += ['-mno-red-zone']
        env['CXXFLAGS']     += ['-mno-red-zone']
    elif isa == 'arm':
        env['CFLAGS']       += ['-march=armv7-a']
        env['CXXFLAGS']     += ['-march=armv7-a']
        env['LINKFLAGS']    += ['-march=armv7-a']
        env['ASFLAGS']      += ['-march=armv7-a']
    elif isa == 'riscv':
        env['CFLAGS']       += ['-march=rv64imafdc', '-mabi=lp64']
        env['CXXFLAGS']     += ['-march=rv64imafdc', '-mabi=lp64']
        env['LINKFLAGS']    += ['-march=rv64imafdc', '-mabi=lp64']
        env['ASFLAGS']      += ['-march=rv64imafdc', '-mabi=lp64']
    musl_isa = 'riscv64' if isa == 'riscv' else isa
    env['CPPPATH']          += [
        'src/libs/musl/arch/' + musl_isa,
        'src/libs/musl/arch/generic',
        'src/libs/musl/m3/include/' + isa,
        'src/libs/musl/include',
        crossdir + '/include/c++/' + crossver,
        crossdir + '/include/c++/' + crossver + '/' + cross[:-1],
    ]
    # we install the crt* files to that directory
    env['SYSGCCLIBPATH']    = crossdir + '/lib/gcc/' + cross[:-1] + '/' + crossver
    # no build-id because it confuses gem5
    env['LINKFLAGS']        += ['-static', '-Wl,--build-id=none']
    # binaries get very large otherwise
    env['LINKFLAGS']        += ['-Wl,-z,max-page-size=4096', '-Wl,-z,common-page-size=4096']
    env['LIBPATH']          += [crossdir + '/lib', env['LIBDIR']]
else:
    env['LIBPATH']          += [env['LIBDIR']]

# start the generation
gen = ninjagen.Generator()

gen.add_rule('mkm3fs', ninjagen.Rule(
    cmd = env['TOOLDIR'] + '/mkm3fs $out $dir $blocks $inodes 0',
    desc = 'MKFS $out',
))
gen.add_rule('elf2hex', ninjagen.Rule(
    cmd = env['TOOLDIR'] + '/elf2hex $in > $out',
    desc = 'ELF2HEX $out',
))

gen.add_rule('cargo_ws', ninjagen.Rule(
    cmd = 'cd $dir && cargo $cargoflags --color=always',
    desc = 'CARGO Cargo.toml',
))

# by default, use the cross toolchain
gen.add_var('cc', env['CC'])
gen.add_var('cxx', env['CXX'])
gen.add_var('cpp', env['CPP'])
gen.add_var('link', env['CXX'])
gen.add_var('ar', env['AR'])
gen.add_var('ranlib', env['RANLIB'])
gen.add_var('strip', env['STRIP'])

# generate linker scripts
if env['PLATF'] == 'kachel':
    ldscript = 'src/toolchain/kachel/ld.conf'
    ldscripts['default'] = env.cpp(gen, out = 'ld-default.conf', ins = [ldscript])

    bare_env = env.clone()
    bare_env['CPPFLAGS'] += ['-D__baremetal__=1']
    ldscripts['baremetal'] = bare_env.cpp(gen, out = 'ld-baremetal.conf', ins = [ldscript])

    isr_env = env.clone()
    isr_env['CPPFLAGS'] += ['-D__baremetal__=1', '-D__isr__=1']
    ldscripts['isr'] = isr_env.cpp(gen, out = 'ld-isr.conf', ins = [ldscript])

    tilemux_env = env.clone()
    tilemux_env['CPPFLAGS'] += ['-D__isr__=1', '-D__tilemux__=1']
    ldscripts['tilemux'] = tilemux_env.cpp(gen, out = 'ld-tilemux.conf', ins = [ldscript])

# generate build edges first
env.sub_build(gen, 'src')

# now that we know the rust crates to build, generate build edge to build the workspace with cargo
env.cargo_ws(gen)

class LinuxEnv(ninjagen.Env):
    # TODO: this env only supports rust on riscv
    def __init__(self):
        assert isa == 'riscv'
        assert target == 'gem5' or target == 'hw'
        super().__init__()
        self.rustcrates = []

        self.triple = 'riscv64gc-unknown-linux-gnu'
        self.vars['CRGFLAGS'] = ['--target', self.triple]
        if btype != 'debug' and btype != 'coverage':
            self.vars['CRGFLAGS'] += ['--release']
        self.vars['RUSTBINS'] = 'build/rust/' + self.triple + '/' + rustbuild
    
    def clone(self):
        env = M3Env()
        env.cwd = self.cwd
        env.vars = copy.deepcopy(self.vars)
        return env

    def cargo_ws(self, gen):
        outs = []
        deps = []

        env = self.clone()
        for cr in self.rustcrates:
            crate_name = os.path.basename(cr)
            out = ninjagen.BuildPath(env['RUSTBINS'] + '/lib' + crate_name + '.a')
            outs.append(out)
            deps += [cr + '/Cargo.toml', '.cargo/config']
            deps += env.glob(crate_name + '/**/*.rs', recursive = True)
            # specify crates explicitly, because some crates are only supported by some targets
            env['CRGFLAGS'] += ['-p', crate_name]

        gen.add_build(ninjagen.BuildEdge(
            'cargo_ws',
            outs = outs,
            ins = [],
            deps = deps,
            vars = { 'cargoflags' : 'build ' + ' '.join(env['CRGFLAGS']), 'dir': 'linux-deps/src' }
        ))

linux_env = LinuxEnv()
if os.path.exists('linux-deps'):
    linux_env.sub_build(gen, 'linux-deps/src')

# finally, write it to file
gen.write_to_file(env['BUILDDIR'])
