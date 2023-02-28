def build(gen, env):
    lib = env.static_lib(gen, out = 'libuart', ins = env.glob('*.cc'))
    env.install(gen, env['LIBDIR'], lib)
