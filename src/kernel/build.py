def build(gen, env):
    env.m3_rust_exe(
        gen, out='kernel', libs=['isr', 'thread'], dir=None, ldscript='isr', varAddr=False,
        features=["kernel/" + env['TGT']]
    )
