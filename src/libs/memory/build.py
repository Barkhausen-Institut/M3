from ninjapie import BuildPath
from pathlib import Path


def build(gen, env):
    files = env.glob(gen, '*.cc')

    # build files manually here to specify the exact file name of the object file. we reference
    # them later in the configure.py to ensure that we use our own memcpy etc. implementation.
    for isa in env['ALL_ISAS']:
        for sf in [True, False]:
            tenv = env.new(isa, sf)
            tenv.remove_flag('CXXFLAGS', '-flto=auto')
            for f in files:
                out = BuildPath.with_file_ext(tenv, f, isa + '-' + str(sf) + '.o')
                obj = tenv.cxx(gen, out=out, ins=[f])
                tenv.install_as(gen, tenv['LIBDIR'] + '/' + Path(f).stem + '.o', obj)
