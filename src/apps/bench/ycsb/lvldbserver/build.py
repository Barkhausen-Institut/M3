from ninjapie import BuildPath


def build(gen, env):
    env = env.clone()
    env['CPPPATH'] += ['src/libs/leveldb/include']
    # disable warning in leveldb, that is only produced at linktime
    env['LINKFLAGS'] += ['-Wno-alloc-size-larger-than']

    input = [
        'handler.cc', 'leveldb.cc', 'ops.cc', 'tcp_handler.cc', 'tcu_handler.cc',
        'udp_handler.cc'
    ]
    env.m3_exe(gen, out='lvldbserver', libs=['leveldb'], ins=input)

    # TEE version
    if env['ISA'].startswith('riscv'):
        env = env.clone()
        env['LINKFLAGS'] += ['-nostartfiles']
        crt0_obj = BuildPath(env['LIBDIR'] + '/crtbegin.o')
        crtn_obj = BuildPath(env['LIBDIR'] + '/crtend.o')
        ins = [crt0_obj] + input + [crtn_obj]
        libs = ['leveldb', 'isr-nostackswitch', 'unimux', 'unimuxentry']
        env.m3_exe(gen, ins=ins, out='lvldbserver-tee', libs=libs, varAddr=False, ldscript='isr')
