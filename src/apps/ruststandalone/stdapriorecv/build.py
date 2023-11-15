def build(gen, env):
    env = env.clone()

    if env['ISA'] == 'arm':
        env['LINKFLAGS'] += ['-Wl,--whole-archive', '-lisr', '-Wl,--no-whole-archive']

    env.m3_rust_exe(
        gen,
        out='stdapriorecv',
        libs=['isr'],
        dir=None,
        ldscript='tilemux',
        varAddr=False
    )
