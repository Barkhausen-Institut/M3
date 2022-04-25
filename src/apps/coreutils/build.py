dirs = [
    'hashsum',
    'man',
    'netcat',
    'rand',
    'readelf',
    'sink',
    'time',
]

def build(gen, env):
    for d in dirs:
        env.sub_build(gen, d)
