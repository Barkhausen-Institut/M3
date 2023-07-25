dirs = ['isodemoctrl', 'isodemoattacker', 'isodemovictim']


def build(gen, env):
    for d in dirs:
        env.sub_build(gen, d)
