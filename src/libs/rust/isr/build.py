def build(gen, env):
    for isa in env['ALL_ISAS']:
        for sf in [True, False]:
            env = env.new(isa, sf)

            dir = isa if not isa.startswith('riscv') else 'riscv'
            files = ['src/' + dir + '/Entry.S']

            lib = env.static_lib(gen, out='isr-' + isa + '-' + str(sf), ins=files)
            env.install_as(gen, env['LIBDIR'] + '/libisr.a', lib)

    env.m3_rust_lib(gen, features=["isr/" + env['TGT']])
