from methods.cluster.vectors import list_to_order_list, ListOrderVectorizer, construct_vector
from methods.cluster.utils import cluster_module_data, match_module_clusters


class StatusCodeVectorizer():
    def get_default_vector(self):
        return [-1]


    def get_vector(self, status_code):
        return [status_code/100]


def get_data(http_port):
    data = {}

    data["vector"] = construct_vector(_props_to_vectorizers, http_port)

    return data


match = match_module_clusters


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
