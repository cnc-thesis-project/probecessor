from sklearn.cluster import DBSCAN
import numpy as np


module_X = {
    "http": [],
    "ssh": []
}

module_clusterings = {}

vector_descs = {
    "http": {
        "lists": {
            "delete_root_header_keys": {
                "Server": 0,
                "Content-Type": 1,
                "Date": 2,
                "Content-Length": 3,
                "Connection": 4,
            },
            "get_root_header_keys": {
                "Server": 0,
                "Content-Type": 1,
                "Date": 2,
                "Content-Length": 3,
                "Connection": 4,
            },
        },
        "vector": [
            "delete_root_header_keys",
            "get_root_header_keys",
            "get_response_code",
            "delete_response_code",
            "favicon_response_code",
        ],
    },
    "ssh": {
        "lists": {},
        "vector": {},
    }
}


def get_vector(host_data):
    pass

# Add training data
def add(host_data):
    print("Adding data:")
    print(host_data)
    for data in host_data.values():
        if data["module"] != "http":
            continue
        vec = []
        desc = vector_descs[data["module"]]
        for el in desc["vector"]:
            if el in desc["lists"]:
                vec.extend(list_to_order_list(data["features"][el], desc["lists"][el]))
            else:
                vec.append(data["features"][el])
        print("added vector:", vec)
        module_X[data["module"]].append(vec)


def train():
    print("training with module_X:", module_X)
    for m, X in module_X.items():
        if m != "http":
            continue
        X = np.array(X)
        module_clusterings[m] = DBSCAN(eps=2, min_samples=2).fit(X)
        print("labels for {}:".format(m), module_clusterings[m].labels_)


def list_to_order_list(li, desc):
    res = [-1 for i in range(max(len(desc.values()), len(li)))]
    for i in range(max(len(res), len(li))):
        if i < len(li):
            if li[i] in desc.keys():
                res[desc[li[i]]] = i
    return res

"""
data = {}
data["192.123.123.123"] = {
    80: {
        "module": "http",
        "features": {
            "delete_response_code": 200,
            "get_response_code": 200,
            "favicon_response_code": 404,
            "header_keys": [
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
            "header_keys": [
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
            "header_keys": [
                "Server",
                "Content-Type",
                "Content-Length",
            ],
        }
    }
}

for d in data.values():
    add(d)

train()

print("module X:", module_X)
"""
