def add_data(mod):
    pass


def train():
    pass


def set_model(model):
    pass


def convert(port):
    entropy = port.get_property("entropy")
    ret = {
        port.type + ":" + str(port.port) + ":entropy": 0 if not entropy else entropy,
    }

    return ret
