dirs = [
    'axieth',
    'base',
    'crypto',
    'dummy',
    'flac',
    'gem5',
    'heap',
    'host',
    'leveldb',
    'llvmprofile',
    'm3',
    'memory',
    'musl',
    'openssl',
    'pci',
    'rust',
    'support',
    'thread',
]

def build(gen, env):
    for d in dirs:
        env.sub_build(gen, d)
