from sklearn.cluster import DBSCAN
import numpy as np
import joblib
from pprint import pprint


module_X = {
    "http": [],
    "ssh": []
}

module_models = {}


# Returns a list described by desc of the mutual orders of the elements in li.
def list_to_order_list(li, desc):
    res = [-1 for i in range(len(desc.values()))]
    j = 0
    for i in range(len(li)):
        if li[i] in desc.keys():
            res[desc[li[i]]] = j
            j+=1
    return res


def _normalize_status_code(code):
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


def _normalize_kex_algorithms(arr):
    algos = {
        "curve25519-sha256": 0,
        "curve25519-sha256@libssh.org": 1,
        "ecdh-sha2-nistp256": 2,
        "ecdh-sha2-nistp384": 3,
        "ecdh-sha2-nistp521": 4,
        "diffie-hellman-group-exchange-sha256": 5,
        "diffie-hellman-group16-sha512": 6,
        "diffie-hellman-group18-sha512": 7,
        "diffie-hellman-group14-sha256": 8,
        "diffie-hellman-group14-sha1": 9,
    }
    return list_to_order_list(arr, algos)


def _normalize_server_host_key_algorithms(arr):
    algos = {
        "rsa-sha2-512": 0,
        "rsa-sha2-256": 1,
        "ssh-rsa": 2,
        "ecdsa-sha2-nistp256": 3,
        "ssh-ed25519": 4,
    }
    return list_to_order_list(arr, algos)


def _normalize_encryption_algorithms(arr):
    algos = {
        "chacha20-poly1305@openssh.com": 0,
        "aes128-ctr": 1,
        "aes192-ctr": 2,
        "aes256-ctr": 3,
        "aes128-gcm@openssh.com": 4,
        "aes256-gcm@openssh.com": 5,
        "aes128-cbc": 6,
        "aes192-cbc": 7,
        "aes256-cbc": 8, 
    }
    return list_to_order_list(arr, algos)


def _normalize_mac_algorithms(arr):
    algos = {
        "umac-64-etm@openssh.com": 0,
        "umac-128-etm@openssh.com": 1,
        "hmac-sha2-256-etm@openssh.com": 2,
        "hmac-sha2-512-etm@openssh.com": 3,
        "hmac-sha1-etm@openssh.com": 4,
        "umac-64@openssh.com": 5,
        "umac-128@openssh.com": 6,
        "hmac-sha2-256": 7,
        "hmac-sha2-512": 8,
        "hmac-sha1": 9,
    }
    return list_to_order_list(arr, algos)


# TODO: don't use hard coded array lengths

# HTTP
_default_header_keys = [ -1 ] * 5
_default_status_code = [ -1 ]

# SSH
_default_kex_algorithms = [ -1 ] * 10
_default_server_host_key_algorithms = [ -1 ] * 5
_default_encryption_algorithms = [ -1 ] * 9
_default_mac_algorithms = [ -1 ] * 10

vector_descs = {
    "http": [
        { "name": "get_root:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "get_root:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "head_root:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "head_root:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "delete_root:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "delete_root:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "very_simple_get:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "very_simple_get:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "not_exist:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "not_exist:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "invalid_version:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "invalid_version:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "invalid_protocol:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "invalid_protocol:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "long_path:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "long_path:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "get_favicon:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "get_favicon:status_code", "norm": _normalize_status_code, "default": _default_status_code },
        { "name": "get_robots:header_keys", "norm": _normalize_header_keys, "default": _default_header_keys },
        { "name": "get_robots:status_code", "norm": _normalize_status_code, "default": _default_status_code },
    ],
    "ssh": [
        { "name": "ciphers:kex_algorithms", "norm": _normalize_kex_algorithms, "default": _default_kex_algorithms },
        { "name": "ciphers:server_host_key_algorithms", "norm": _normalize_server_host_key_algorithms, "default": _default_server_host_key_algorithms },
        { "name": "ciphers:encryption_algorithms_client_to_server", "norm": _normalize_encryption_algorithms, "default": _default_encryption_algorithms },
        { "name": "ciphers:encryption_algorithms_server_to_client", "norm": _normalize_encryption_algorithms, "default": _default_encryption_algorithms },
        { "name": "ciphers:mac_algorithms_client_to_server", "norm": _normalize_mac_algorithms, "default": _default_mac_algorithms},
        { "name": "ciphers:mac_algorithms_server_to_client", "norm": _normalize_mac_algorithms, "default": _default_mac_algorithms},
    ],
}


# Extracts a feature vector from the module data, e.g. port data.
def extract_vector(mod_data):
    if mod_data.get("name") in ["unknown", None]:
        return None

    data = mod_data[mod_data["name"]]

    vec = []
    desc = vector_descs[mod_data["name"]]
    for feat in desc:
        if feat["name"] in data.keys():
            vec.extend(feat["norm"](data[feat["name"]]))
        else:
            vec.extend(feat["default"])

    return vec


# Add training data
def add(host_data):
    for port_data in host_data["port"].values():
        if port_data.get("name") in ["unknown", None]:
            continue
        vec = extract_vector(port_data)
        """

        data = port_data[port_data["name"]]

        vec = []
        desc = vector_descs[port_data["name"]]
        for feat in desc:
            if feat["name"] in data.keys():
                vec.extend(feat["norm"](data[feat["name"]]))
            else:
                vec.extend(feat["default"])

        #print("added vector of len {}:".format(len(vec)), vec)
        """
        module_X[port_data["name"]].append(vec)


def process(out_path):
    for m, X in module_X.items():
        if len(X) == 0:
            continue
        X = np.array(X)
        module_models[m] = DBSCAN(eps=8, min_samples=2).fit(X)
        print("labels for {}:".format(m), module_models[m].labels_)

        joblib.dump(module_X, out_path)


# Returns the fingerprint match. If none match, return None.
def classify(in_path, data):
    module_X = joblib.load(in_path)

    for ip, host_data in data.items():
        print("matching host {} against known hosts".format(ip))
        for m, mod_data in host_data.items():
            if m == "port":
                for port, port_data in mod_data.items():
                    name = port_data.get("name")
                    print("classifying {} port {}:{}".format(name, ip, port))
                    if name == "unknown" or not name:
                        continue
                    vec = extract_vector(port_data)
                    db = DBSCAN(eps=8, min_samples=2)
                    X = np.array(module_X[name] + [vec])
                    db.fit(X)
                    print("{} port:".format(name), db.labels_[len(db.labels_) - 1])
