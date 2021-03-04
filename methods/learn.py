from sklearn.cluster import DBSCAN
import numpy as np
from pprint import pprint


module_X = {
    "http": [],
    "ssh": []
}

module_clusterings = {}


def list_to_order_list(li, desc):
    res = [-1 for i in range(len(desc.values()))]
    for i in range(len(li)):
        if li[i] in desc.keys():
            res[desc[li[i]]] = i
    return res


def _normalize_response_code(code):
    return [code/100]


def _normalize_header_keys(headers):
    header_keys = {
        "Server": 0,
        "Content-Type": 1,
        "Date": 2,
        "Content-Length": 3,
        "Connection": 4,
    }

    return list_to_order_list(headers, header_keys)


vector_descs = {
    "http": [
        { "name": "get_root_header_keys", "norm": _normalize_header_keys },
        { "name": "get_root_response_code", "norm": _normalize_response_code },
        { "name": "head_root_header_keys", "norm": _normalize_header_keys },
        { "name": "head_root_response_code", "norm": _normalize_response_code },
        { "name": "delete_root_header_keys", "norm": _normalize_header_keys },
        { "name": "delete_root_response_code", "norm": _normalize_response_code },
        { "name": "very_simple_get_header_keys", "norm": _normalize_header_keys },
        { "name": "very_simple_get_response_code", "norm": _normalize_response_code },
        { "name": "not_exist_header_keys", "norm": _normalize_header_keys },
        { "name": "not_exist_response_code", "norm": _normalize_response_code },
        { "name": "invalid_version_header_keys", "norm": _normalize_header_keys },
        { "name": "invalid_version_response_code", "norm": _normalize_response_code },
        { "name": "invalid_protocol_header_keys", "norm": _normalize_header_keys },
        { "name": "invalid_protocol_response_code", "norm": _normalize_response_code },
        { "name": "long_path_header_keys", "norm": _normalize_header_keys },
        { "name": "long_path_response_code", "norm": _normalize_response_code },
        { "name": "get_favicon_header_keys", "norm": _normalize_header_keys },
        { "name": "get_favicon_response_code", "norm": _normalize_response_code },
        { "name": "get_robots_header_keys", "norm": _normalize_header_keys },
        { "name": "get_robots_response_code", "norm": _normalize_response_code },
    ],
    "ssh": {
    },
}


def get_vector(host_data):
    pass


# Add training data
def add(host_data):
    for data in host_data.values():
        # TODO: fix
        if data["module"] != "http":
            continue

        vec = []
        desc = vector_descs[data["module"]]
        for feat in desc:
            if feat["name"] in data["features"].keys():
                vec.extend(feat["norm"](data["features"][feat["name"]]))

        # TODO: fix
        if len(vec) != 60:
            continue

        print("added vector of len {}:".format(len(vec)), vec)
        module_X[data["module"]].append(vec)


def process():
    pprint(module_X, width=1000)

    for m, X in module_X.items():
        if len(X) == 0:
            continue
        # TODO: temporary
        if m != "http":
            continue
        X = np.array(X)
        module_clusterings[m] = DBSCAN(eps=3, min_samples=2).fit(X)
        print("labels for {}:".format(m), module_clusterings[m].labels_)


"""
data = {}
data["192.123.123.123"] = {
    80: {
        "module": "http",
        "features": {
            "delete_response_code": 200,
            "get_response_code": 200,
            "favicon_response_code": 404,
            "delete_root_header_keys": [
                "Server",
                "Content-Type",
                "Content-Length",
            ],
        }
    }
}
data["192.123.123.1"] = {
    80: {
        "module": "http",
        "features": {
            "delete_response_code": 200,
            "get_response_code": 200,
            "favicon_response_code": 404,
            "delete_root_header_keys": [
                "Content-Type",
                "Content-Length",
                "Server",
            ],
        }
    }
}
data["192.123.123.2"] = {
    80: {
        "module": "http",
        "features": {
            "delete_response_code": 200,
            "get_response_code": 200,
            "favicon_response_code": 200,
            "delete_root_header_keys": [
                "Server",
                "Content-Type",
                "Content-Length",
            ],
        }
    }
}

for d in data.values():
    add(d)

print("module X:", module_X)

train()
"""
