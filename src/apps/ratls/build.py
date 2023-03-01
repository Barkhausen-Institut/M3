def build(gen, env):
    env = env.clone()

    env['CPPFLAGS'] += [
        '-D__linux__=1',
        '-D__m3__=1',
        '-D_GNU_SOURCE',
        '-D_TPMCPPLIB',
    ]

    env.m3_exe(gen, out = 'ratls-dashboard', ins = ['dashboard.cpp'])

    # disable LTO to reduce link times
    env.remove_flag('CXXFLAGS', '-flto')
    env.remove_flag('LINKFLAGS', '-flto')

    env['CPPPATH'] += [
        'src/libs/openssl/include',
        'src/libs/tss/TSS.CPP/include',
    ]

    env['CXXFLAGS'] += [
        '-Wno-sign-conversion',
        '-Wno-unused-parameter',
    ]

    objfiles = ['benchmark.cpp', 'demo.cpp', 'ratls-tpm2.cpp', 'ratls.cpp']
    objs     = env.objs(gen, ins = objfiles)

    env.m3_exe(gen, out = 'ratls', ins = ['client.cpp'] + objs, 
               libs = ['crypto', 'ssl', 'tss'])
    
    env.m3_exe(gen, out = 'ratls-demo', ins = ['demo-client.cpp'] + objs, 
               libs = ['crypto', 'ssl', 'tss', 'uart'])
