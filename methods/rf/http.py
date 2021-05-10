def set_model(model):
    pass


def add_data(http_port):
    pass


def train():
    pass


def convert(http_port):
    features = {}

    for rt in _request_types:
        header_keys = http_port.get_property(rt + ":header_keys")
        if header_keys:
            i = 0
            for header_key in _header_keys:
                if header_key in header_keys:
                    features["http:" + rt + ":" + _header_keys[i] + ":" + str(http_port.port)] = i+1
                    i += 1

    return features


_request_types = [
    "get_root",
    "head_root",
    "delete_root",
    "very_simple_get",
    "not_exist",
    "invalid_version",
    "invalid_protocol",
    "long_path",
    "get_favicon",
    "get_robots",
]


_vector_types = [
    "header_keys",
    "status_code",
]


_header_keys = [
    "server",
    "content-type",
    "date",
    "content-length",
    "connection",
    "Server",
    "Content-type",
    "Date",
    "Content-length",
    "Connection",
]
