def build(gen, env):
    env = env.clone()

    env['CPPFLAGS'] += [
        '-D__linux__=1',
        '-D_GNU_SOURCE',
        '-D_TPMCPPLIB',
    ]

    env['CPPPATH'] += [
        'src/libs/openssl/include',
        'src/libs/tss/TSS.CPP/include',
    ]

    env['CXXFLAGS'] += [
        '-Wno-sign-conversion',
        '-Wno-unused-parameter',
    ]

    env.m3_exe(gen, out = 'ratls', ins = env.glob('*.cpp'), libs = ['crypto', 'ssl', 'tss'])
