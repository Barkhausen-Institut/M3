dirs = ['priobomber', 'prioreceiver']


def build(gen, env):
    for d in dirs:
        env.sub_build(gen, d)
