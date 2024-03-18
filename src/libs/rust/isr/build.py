def build(gen, env):
    dir = env['ISA'] if not env['ISA'].startswith('riscv') else 'riscv'
    files = ['src/' + dir + '/Entry.S']

    lib = env.static_lib(gen, out='isr', ins=files)
    env.install(gen, env['LIBDIR'], lib)

    sf_env = env.clone()
    sf_env.soft_float()
    lib = sf_env.static_lib(gen, out='isrsf', ins=files)
    sf_env.install(gen, sf_env['LIBDIR'], lib)

    env.m3_rust_lib(gen)
