def build(gen, env):
    for d in ['ipcrecv', 'ipcsend']:
        env.sub_build(gen, d)
