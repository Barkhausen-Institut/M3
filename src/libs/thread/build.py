def build(gen, env):
    env = env.clone()
    env['CXXFLAGS'] += ['-fno-exceptions -fno-rtti']
    env['LINKFLAGS'] += ['-fno-exceptions -fno-rtti']

    files = ['Thread.cc', 'ThreadManager.cc']
    dir = env['ISA'] if not env['ISA'].startswith('riscv') else 'riscv'
    files += ['isa/' + dir + '/ThreadSwitch.S']
    files += ['isa/' + dir + '/Thread.cc']
    lib = env.static_lib(gen, out='thread', ins=files)
    env.install(gen, env['LIBDIR'], lib)
    env.install(gen, env['LXLIBDIR'], lib)
