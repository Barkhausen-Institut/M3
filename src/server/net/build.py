def build(gen, env):
    if env['TGT'] == 'hw' or env['TGT'] == 'hw22':
        return
        libs = ['axieth', 'base', 'supc++']
    else:
        libs = []
    env.m3_rust_exe(gen, out='net', libs=libs, dir='sbin', features=['net/' + env['TGT']])
