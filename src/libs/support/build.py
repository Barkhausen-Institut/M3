from ninjapie import BuildPath, SourcePath
from pathlib import Path
import os


def is_our(ours, file):
    for o in ours:
        if os.path.basename(o) == os.path.basename(file):
            return True
    return False


def build(gen, env):
    ours = []
    for isa in env['ALL_ISAS']:
        for sf in [True, False]:
            env = env.new(isa, sf)

            dir = isa if not isa.startswith('riscv') else 'riscv'
            for f in env.glob(gen, dir + '/*.S'):
                out = BuildPath.with_file_ext(env, f, isa + '-' + str(sf) + '.o')
                obj = env.asm(gen, out=out, ins=[f])
                ours.append(env.install_as(gen, env['LIBDIR'] + '/' + Path(f).stem + '.o', obj))

            for f in env.glob(gen, SourcePath(env['SYSGCCLIBPATH'] + '/crt*')):
                if not is_our(ours, f):
                    env.install(gen, env['LIBDIR'], SourcePath(f))
