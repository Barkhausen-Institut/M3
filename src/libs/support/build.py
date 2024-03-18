from ninjapie import BuildPath, SourcePath
import os


def is_our(ours, file):
    for o in ours:
        if os.path.basename(o) == os.path.basename(file):
            return True
    return False


def build(gen, env):
    ours = []
    dir = env['ISA'] if not env['ISA'].startswith('riscv') else 'riscv'
    for f in env.glob(gen, dir + '/*.S'):
        obj = env.asm(gen, out=BuildPath.with_file_ext(env, f, 'o'), ins=[f])
        ours.append(env.install(gen, env['LIBDIR'], obj))

    for f in env.glob(gen, SourcePath(env['SYSGCCLIBPATH'] + '/crt*')):
        if not is_our(ours, f):
            env.install(gen, env['LIBDIR'], SourcePath(f))
