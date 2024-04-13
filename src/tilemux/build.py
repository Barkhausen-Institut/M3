def build(gen, env):
    # tilemux has to use soft-float, because the applications might use the FPU and we have to make
    # sure to not overwrite the state (otherwise we would have to save&restore the complete state
    # on every entry and exit).
    env = env.new(env['ISA'], True)

    # use our own start file (Entry.S)
    env['LINKFLAGS'] += ['-nostartfiles']

    dir = env['ISA'] if not env['ISA'].startswith('riscv') else 'riscv'
    entry_file = 'src/arch/' + dir + '/Entry.S'
    entry = env.asm(gen, out=entry_file[:-2] + '.o', ins=[entry_file])

    # build tilemux outside of the workspace to use a different target spec that enables soft-float
    lib = env.m3_cargo(gen, out='libtilemux.a')
    env.install(gen, outdir=env['RUSTLIBS'], input=lib)

    # link it as usual
    env.m3_rust_exe(
        gen,
        out='tilemux',
        libs=['isr'],
        dir=None,
        ldscript='isr',
        startup=entry,
        varAddr=False,
        cargo_ws=False,
    )
