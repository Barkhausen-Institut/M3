def build(gen, env):
    for d in ['stdapriorecv', 'stdapriosnd', 'stdasender', 'stdareceiver', 'vmtest']:
        env.sub_build(gen, d)
