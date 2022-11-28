dirs = [
    'arith',
    'crypto',
    'disk',
    'm3fs',
    'net',
    'pager',
    'pipes',
    'root',
    'sig',
    'timer',
    'vterm',
]

def build(gen, env):
    for d in dirs:
        env.sub_build(gen, d)
