def build(gen, env):
    env.m3_exe(gen, out = 'cpppipe1', ins = ['step1/step1.cc'])
    env.m3_exe(gen, out = 'cpppipe2', ins = ['step2/step2.cc'])
