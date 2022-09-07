dirs = [
    'accelchain',
    'bench-apps',
    'cppbenchs',
    'cppnetbenchs',
    'disturber',
    'facever',
    'fs',
    'fstrace',
    'hashmuxbenchs',
    'imgproc',
    'ipc',
    'loadgen',
    'mem',
    'netlat',
    'noopbench',
    'pingpong',
    'rustbenchs',
    'rustnetbenchs',
    'scale',
    'scale-pipe',
    'tcusleep',
    'tlbmiss',
    'voiceassist',
    'ycsb',
]


def build(gen, env):
    for d in dirs:
        env.sub_build(gen, d)
