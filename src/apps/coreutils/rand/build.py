def build(gen, env):
    env = env.clone()
    env.remove_flag('CXXFLAGS', '-flto=auto')
    env.m3_exe(gen, out='rand', ins=['loop.cc', 'rand.cc'])
