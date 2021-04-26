def add_data(mod):
    pass


def train():
    pass


def set_model(model):
    pass


def convert(tls_port):
    pfx = "tls:{}".format(tls_port.port)
    ret = {
        pfx + ":" + "si": int(tls_port.get_property("self_issued")),
        pfx + ":" + "ss": 1 if tls_port.get_property("self_signed") == "maybe" else 0,
    }
    return ret
