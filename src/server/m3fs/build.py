def build(gen, env):
    env.m3_rust_exe(gen, out='m3fs', libs=['thread'], dir='sbin')

    if env['ISA'].startswith('riscv'):
        env = env.clone()
        env['LINKFLAGS'] += ['-nostartfiles']
        env['LIBPATH'] += [env['RUSTLIBS']]
        env.m3_exe(
            gen,
            ins=[],
            out='m3fs-tee',
            libs=['c', 'gem5', 'gcc', 'gcc_eh',
                  'isr-nostackswitch', 'unimux', 'unimuxentry',
                  'm3fs', 'thread'],
            NoSup=True,
            varAddr=False,
            ldscript='isr'
        )
