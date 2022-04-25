from glob import glob
import importlib
import os
import subprocess

class SourcePath(str):
    def __init__(self, path):
        self.path = path

    def new(env, path):
        if isinstance(path, SourcePath):
            return SourcePath(path.path)
        elif isinstance(path, BuildPath):
            return SourcePath(path.path)
        else:
            return SourcePath(env.cwd.path + '/' + path)

    def __str__(self):
        return self.path
    def __repr__(self):
        return repr(self.path)

class BuildPath(str):
    def __init__(self, path):
        self.path = path

    def new(env, path):
        if isinstance(path, BuildPath):
            return BuildPath(path.path)
        elif isinstance(path, SourcePath):
            return BuildPath(env['BUILDDIR'] + '/' + path.path)
        else:
            return BuildPath(env['BUILDDIR'] + '/' + env.cwd.path + '/' + path)

    def with_ending(env, path, ending):
        (root, ext) = os.path.splitext(path)
        if isinstance(path, BuildPath):
            return BuildPath(root + ending)
        elif isinstance(path, SourcePath):
            return BuildPath.new(env, SourcePath(root + ending))
        else:
            return BuildPath.new(env, root + ending)

    def __str__(self):
        return self.path
    def __repr__(self):
        return repr(self.path)

class Location:
    def __init__(self, path):
        self.path = path

class Env:
    def __init__(self):
        self.cwd = Location('.')

        self.vars = {}

        # default tools
        self.vars['CXX']        = 'g++'
        self.vars['CPP']        = 'cpp'
        self.vars['AS']         = 'gcc'
        self.vars['CC']         = 'gcc'
        self.vars['AR']         = 'gcc-ar'
        self.vars['RANLIB']     = 'gcc-ranlib'
        self.vars['STRIP']      = 'strip'

        # default flags
        self.vars['ASFLAGS']    = []
        self.vars['CFLAGS']     = []
        self.vars['CPPFLAGS']   = []
        self.vars['CXXFLAGS']   = []
        self.vars['LINKFLAGS']  = []
        self.vars['CRGFLAGS']   = []

        # default paths
        self.vars['CPPPATH']    = []
        self.vars['LIBPATH']    = []
        self.vars['BUILDDIR']   = 'build'
        self.vars['RUSTBINS']   = 'build'

    def __getitem__(self, key):
        return self.vars[key]

    def __setitem__(self, key, value):
        self.vars[key] = value

    def remove_flag(self, flags, name):
        if name in self.vars[flags]:
            self.vars[flags].remove(name)

    def sub_build(self, gen, dir):
        old_cwd = self.cwd.path
        self.cwd.path += '/' + dir

        mod_path = self.cwd.path[2:].replace('/', '.')
        b = importlib.import_module(mod_path + '.build')
        b.build(gen, self)

        self.cwd.path = old_cwd

    def try_execute(self, cmd):
        return subprocess.getstatusoutput(cmd)[0] == 0

    def glob(self, pattern, recursive=False):
        files = glob(self.cwd.path + '/' + pattern, recursive=recursive)
        return [SourcePath(f) for f in files]

    def install(self, gen, outdir, input, flags = ''):
        return self.install_as(gen, outdir + '/' + os.path.basename(input), input, flags)

    def install_as(self, gen, out, input, flags = ''):
        edge = BuildEdge(
            'install',
            outs = [out],
            ins = [SourcePath.new(self, input)],
            vars = { 'instflags' : flags }
        )
        gen.add_build(edge)
        return out

    def strip(self, gen, out, input):
        edge = BuildEdge(
            'strip',
            outs = [out],
            ins = [SourcePath.new(self, input)],
        )
        gen.add_build(edge)
        return out

    def cc(self, gen, out, ins, flags = []):
        flags = ' '.join(self['CFLAGS'] + self['CPPFLAGS'] + flags)
        flags += ' ' + ' '.join(['-I' + i for i in self['CPPPATH']])

        obj = BuildPath.new(self, out)
        edge = BuildEdge(
            'cc',
            outs = [obj],
            ins = [SourcePath.new(self, i) for i in ins],
            vars = { 'cc' : self['CC'], 'ccflags' : flags }
        )
        gen.add_build(edge)
        return obj

    def asm(self, gen, out, ins):
        return self.cc(gen, out, ins, flags = self['ASFLAGS'])

    def cxx(self, gen, out, ins):
        flags = ' '.join(self['CXXFLAGS'] + self['CPPFLAGS'])
        flags += ' ' + ' '.join(['-I' + i for i in self['CPPPATH']])

        obj = BuildPath.new(self, out)
        edge = BuildEdge(
            'cxx',
            outs = [obj],
            ins = [SourcePath.new(self, i) for i in ins],
            vars = { 'cxx' : self['CXX'], 'cxxflags' : flags }
        )
        gen.add_build(edge)
        return obj

    def objs(self, gen, ins):
        objs = []
        for i in ins:
            if i.endswith('.S') or i.endswith('.s'):
                objs.append(self.asm(gen, BuildPath.with_ending(self, i, '.o'), [i]))
            elif i.endswith('.c'):
                objs.append(self.cc(gen, BuildPath.with_ending(self, i, '.o'), [i]))
            elif i.endswith('.cc') or i.endswith('.cpp'):
                objs.append(self.cxx(gen, BuildPath.with_ending(self, i, '.o'), [i]))
            elif i.endswith('.o'):
                objs.append(BuildPath.new(self, i))
        return objs

    def cxx_exe(self, gen, out, ins, libs = [], deps = []):
        flags = ' '.join(self['LINKFLAGS'])
        flags += ' ' + ' '.join(['-L' + d for d in self['LIBPATH']])
        flags += ' -Wl,--start-group'
        flags += ' ' + ' '.join(['-l' + l for l in libs])
        flags += ' -Wl,--end-group'

        bin = BuildPath.new(self, out)
        edge = BuildEdge(
            'link',
            outs = [bin],
            ins = self.objs(gen, ins),
            deps = deps,
            pre_deps = libs,
            lib_path = self['LIBPATH'],
            vars = { 'link' : self['CXX'], 'linkflags' : flags }
        )
        gen.add_build(edge)
        return bin

    def cpp(self, gen, out, ins):
        flags = ' '.join(self['CPPFLAGS'])
        flags += ' ' + ' '.join(['-I' + i for i in self['CPPPATH']])

        bin = BuildPath.new(self, out)
        edge = BuildEdge(
            'cpp',
            outs = [bin],
            ins = [SourcePath.new(self, i) for i in ins],
            vars = { 'cpp' : self['CPP'], 'cppflags' : flags }
        )
        gen.add_build(edge)
        return bin

    def static_lib(self, gen, out, ins):
        lib = BuildPath.new(self, out + '.a')
        edge = BuildEdge(
            'ar',
            outs = [lib],
            ins = self.objs(gen, ins),
            vars = { 'ar' : self['AR'], 'ranlib' : self['RANLIB'] }
        )
        gen.add_build(edge)
        return lib

    def cargo(self, gen, out, cmd = 'build', deps = []):
        bin = BuildPath(self['RUSTBINS'] + '/' + out)
        deps += glob(self.cwd.path + '/**/*.rs', recursive=True)
        deps += [SourcePath.new(self, 'Cargo.toml')]
        edge = BuildEdge(
            'cargo',
            outs = [bin],
            ins = [],
            deps = deps,
            vars = {
                'dir' : self.cwd.path,
                'cargoflags' : cmd + ' ' + ' '.join(self['CRGFLAGS']),
            }
        )
        gen.add_build(edge)
        return bin

class Rule:
    def __init__(self, cmd, desc, deps = '', depfile = '', generator = '', pool = ''):
        assert(cmd != '' and desc != '');
        self.cmd = cmd
        self.desc = desc
        self.deps = deps
        self.depfile = depfile
        self.generator = generator
        self.pool = pool

    def _write_to_file(self, name, file):
        file.write('rule %s\n' % name)
        file.write('  command = %s\n' % self.cmd)
        file.write('  description = %s\n' % self.desc)
        if self.deps != '':
            file.write('  deps = %s\n' % self.deps)
        if self.depfile != '':
            file.write('  depfile = %s\n' % self.depfile)
        if self.generator != '':
            file.write('  generator = %s\n' % self.generator)
        if self.pool != '':
            file.write('  pool = %s\n' % self.pool)

class BuildEdge:
    def __init__(self, rule, outs, ins, deps = [], vars = {}, pre_deps = [], lib_path = []):
        self.rule = rule
        self.outs = outs
        self.ins = ins
        # copy the dependencies, because we want to alter them for this specific BuildEdge later
        self.deps = deps.copy()
        self.pre_deps = pre_deps
        self.lib_path = lib_path
        self.vars = vars

    def _write_to_file(self, vars, file):
        file.write('build %s: %s %s' % (' '.join(self.outs), self.rule, ' '.join(self.ins)))
        if len(self.deps) > 0:
            file.write(' | %s' % (' '.join(self.deps)))
        file.write('\n')
        for k, v in self.vars.items():
            if not k in vars or vars[k] != v:
                file.write('  %s = %s\n' % (k, v))

class Generator:
    def __init__(self):
        self.vars = {}
        self.rules = {}
        self.build_edges = []

        # default rules
        self.add_rule('install', Rule(
            cmd = 'install $instflags $in $out',
            desc = 'INSTALL $out'
        ))
        self.add_rule('cpp', Rule(
            cmd = '$cpp -MD -MF $out.d -P $cppflags $in -o $out',
            deps = 'gcc',
            depfile = '$out.d',
            desc = 'CPP $out'
        ))
        self.add_rule('link', Rule(
            cmd = '$link -o $out $in $linkflags',
            desc = 'LINK $out'
        ))
        self.add_rule('cc', Rule(
            cmd = '$cc -MD -MF $out.d $ccflags -c $in -o $out',
            deps = 'gcc',
            depfile = '$out.d',
            desc = 'CC $out'
        ))
        self.add_rule('cxx', Rule(
            cmd = '$cxx -MD -MF $out.d $cxxflags -c $in -o $out',
            deps = 'gcc',
            depfile = '$out.d',
            desc = 'CXX $out'
        ))
        self.add_rule('ar', Rule(
            cmd = '$ar rc $out $in && $ranlib $out',
            desc = 'AR $out'
        ))
        self.add_rule('cargo', Rule(
            cmd = '( cd $dir && cargo $cargoflags -q --color=always ) && touch $out',
            desc = 'CARGO $out'
        ))
        self.add_rule('strip', Rule(
            cmd = '$strip -o $out $in',
            desc = 'STRIP $out'
        ))

    def add_var(self, name, value):
        assert(name not in self.vars)
        self.vars[name] = value

    def add_rule(self, name, rule):
        assert(name not in self.rules)
        self.rules[name] = rule

    def add_build(self, edge):
        self.build_edges.append(edge)

    def write_to_file(self, outdir):
        build_file = outdir + '/build.ninja'
        dep_file = outdir + '/.build.deps'

        # rules and build edge to automatically regenerate the build.ninja
        self.add_rule('generator', Rule(
            cmd = './configure.py',
            depfile = outdir + '/.build.deps',
            pool = 'build_pool',
            generator = '1',
            desc = 'Regenerating build.ninja',
        ))
        self.add_build(BuildEdge(
            'generator',
            outs = [build_file],
            ins = [],
            deps = ['src/tools/ninjagen.py'],
        ))

        self._finalize_deps()

        # generate build.ninja
        with open(build_file, 'w') as file:
            file.write('# This file has been generated by the M³ build system.\n')
            file.write('\n')

            for k, v in self.vars.items():
                file.write('%s = %s\n' % (k, v))
            file.write('\n')

            for n, r in self.rules.items():
                r._write_to_file(n, file)
            file.write('\n')

            # use a separate pool for the build.ninja regeneration to run that alone
            file.write('pool build_pool\n')
            file.write('  depth = 1\n')
            file.write('\n')

            for b in self.build_edges:
                b._write_to_file(self.vars, file)

        # generate deps of build.ninja
        build_files = ['configure.py'] + glob('src/**/build.py', recursive = True)
        with open(dep_file, 'w') as deps:
            deps.write(build_file + ': ' + ' '.join(build_files))

    def _finalize_deps(self):
        libs = self._collect_libs()
        for b in self.build_edges:
            for d in b.pre_deps:
                name = 'lib' + d + '.a'
                for p in b.lib_path:
                    if p in libs and name in libs[p]:
                        b.deps.append(libs[p][name])
                        break

    def _collect_libs(self):
        libs = {}
        for b in self.build_edges:
            for o in b.outs:
                if o.endswith('.a'):
                    dir = os.path.dirname(o)
                    if not dir in libs:
                        libs[dir] = {}
                    libs[dir][os.path.basename(o)] = o
        return libs
