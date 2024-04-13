def build(gen, env):
    ldscript = 'ld.conf'

    types = [
        ["default", []],
        ["baremetal", ["baremetal"]],
        ["isr", ["baremetal", "isr"]],
    ]

    for isa in env['ALL_ISAS']:
        for ty in types:
            tenv = env.new(isa)
            for flag in ty[1]:
                tenv['CPPFLAGS'] += ['-D__' + flag + '__=1']
            ldconf = tenv.cpp(gen, out='ld-' + ty[0] + '-' + isa + '.conf', input=ldscript)
            tenv.install_as(gen, tenv['LDDIR'] + '/ld-' + ty[0] + '.conf', ldconf)
