def build(gen, env):
    for d in ['server', 'client']:
        env.sub_build(gen, d)
