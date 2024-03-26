dirs = [
    'accel',
    'base',
    'heap',
    'isr',
    'lang',
    'm3',
    'm3impl',
    'paging',
    'pci',
    'resmng',
    'thread',
]


def build(gen, env):
    for d in dirs:
        env.sub_build(gen, d)
