from ninjapie import BuildPath


def build(gen, env):
    env = env.clone()
    env.remove_flag('CXXFLAGS', '-flto=auto')

    files = env.glob(gen, '*.cc')

    # build files manually here to specify the exact file name of the object file. we reference
    # them later in the configure.py to ensure that we use our own memcpy etc. implementation.
    for f in files:
        env.cxx(gen, BuildPath.with_file_ext(env, f, 'o'), [f])

    # same for the soft-float version
    sfenv = env.clone()
    sfenv.soft_float()
    for f in files:
        sfenv.cxx(gen, BuildPath.with_file_ext(sfenv, f, 'sf.o'), [f])
