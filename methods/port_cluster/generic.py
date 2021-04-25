def add_data(mod):
    pass


def train(mods):
    pass


def set_model(model):
    pass


def convert(port):
    data_len = port.get_property("data")
    ret = { "{}:{}".format(port.type, port.port): 1 if data_len == 0 else -1 }
    return ret
