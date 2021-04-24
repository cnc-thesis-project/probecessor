from methods.port_cluster.vectors import list_to_order_list, ListOrderVectorizer, construct_vector
from sklearn.cluster import KMeans


_NUM_CLUSTERS = 30

_training_data = []
_cls = None


class StatusCodeVectorizer():
    def get_default_vector(self):
        return [-1]


    # TODO: This is probably not a good method to vectorize the status code,
    # as there is no concept of distance intrinsic to the values used.
    # We should instead perhaps consider something that can encode a distance.
    def get_vector(self, status_code):
        return [status_code/100]


def set_model(model):
    global _cls
    _cls = model


def add_data(http_port):
    _training_data.append(construct_vector(_props_to_vectorizers, http_port))


def train():
    global _cls
    _cls = KMeans(n_clusters=_NUM_CLUSTERS)
    _cls.fit(_training_data)
    return _cls


def convert(http_port):
    if _cls:
        return {"http:{}".format(http_port.port): _cls.predict([construct_vector(_props_to_vectorizers, http_port)])[0]}
    print("WARNING: NO MODEL FOR HTTP")
    return {"http:{}".format(http_port.port): -1}


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


_props_to_vectorizers = {}


_vectorizers = {
    "header_keys": ListOrderVectorizer([
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
    ]),
    "status_code": StatusCodeVectorizer()
}


for request_type in _request_types:
    for vector_type in _vector_types:
        _props_to_vectorizers["{}:{}".format(request_type,  vector_type)] = _vectorizers[vector_type]
