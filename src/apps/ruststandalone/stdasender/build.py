def build(gen, env):
    env.m3_rust_exe(
        gen,
        out='stdasender',
        libs=['isr'],
        dir=None,
        ldscript='tilemux',
        varAddr=False
    )
