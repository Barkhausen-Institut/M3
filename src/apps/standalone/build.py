def build(gen, env):
    env = env.clone()
    env['CXXFLAGS']  += ['-fno-exceptions']
    env['LINKFLAGS'] += ['-fno-exceptions', '-nodefaultlibs']

    libs = ['simplec', 'gem5', 'base', 'supc++', 'gcc']

    env_obj = env.cxx(gen, out = 'env.o', ins = ['env.cc'])
    env.m3_exe(
        gen,
        out = 'standalone',
        ins = [env_obj, 'standalone.cc'] + env.glob('tests/*.cc'),
        libs = libs,
        dir = None,
        ldscript = 'baremetal',
        varAddr = False,
        NoSup = True
    )

    for s in ['sender', 'receiver', 'mem', 'uarttest']:
        env.m3_exe(
            gen,
            out = 'standalone-' + s,
            ins = [env_obj, s + '/' + s + '.cc'],
            dir = None,
            NoSup = True,
            ldscript = 'baremetal',
            varAddr = False,
            libs = libs
        )
