def build(gen, env):
    ldscript = 'ld.conf'

    types = [
        ["default", []],
        ["baremetal", ["baremetal"]],
        ["isr", ["baremetal", "isr"]],
        ["tilemux", ["tilemux", "isr"]],
    ]

    for ty in types:
        tenv = env.clone()
        for flag in ty[1]:
            tenv['CPPFLAGS'] += ['-D__' + flag + '__=1']
        ldconf = tenv.cpp(gen, out='ld-' + ty[0] + '.conf', input=ldscript)
        tenv.install(gen, tenv['LDDIR'], ldconf)
