def build(gen, env):
    for isa in env['ALL_ISAS']:
        for sf in [True, False]:
            env = env.new(isa, sf)
            dir = isa if not isa.startswith('riscv') else 'riscv'
            files = env.glob(gen, dir + '/*.*')

            lib = env.static_lib(gen, out='gem5-' + isa + '-' + str(sf), ins=files)
            env.install_as(gen, env['LIBDIR'] + '/libgem5.a', lib)
            if isa == 'riscv64' and not sf:
                env.install_as(gen, env['LXLIBDIR'] + '/libgem5.a', lib)
