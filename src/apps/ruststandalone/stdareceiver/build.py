def build(gen, env):
    env.m3_rust_exe(
        gen,
        out='stdareceiver',
        libs=['isr'],
        dir=None,
        ldscript='tilemux',
        varAddr=False
    )
