dirs = [
    'accelchain',
    'bench-apps',
    'cppbenchs',
    'cppnetbenchs',
    'disturber',
    'fs',
    'fstrace',
    'hashmuxbenchs',
    'imgproc',
    'ipc',
    'loadgen',
    'netlat',
    'pingpong',
    'rustbenchs',
    'rustnetbenchs',
    'scale',
    'scale-pipe',
    'tlbmiss',
    'voiceassist',
    'ycsb',
]

def build(gen, env):
    for d in dirs:
        env.sub_build(gen, d)
