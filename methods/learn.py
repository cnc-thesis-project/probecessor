from sklearn.cluster import KMeans
import numpy as np
import math
import joblib
from pprint import pprint
import sys
from util.label import get_label_names

NUM_CLUSTERS = 50

module_X = {
    "http": [],
    "ssh": []
}

module_models = {}
host_fingerprints = []


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


def normalized_host(host_data):
    norm = {"ports":{}}
    for port, port_data in host_data["port"].items():
        if port_data.get("name") in ["unknown", None]:
            continue

        norm["ports"][port] = {}
        # Extract vector for this port to use for clustering.
        norm["ports"][port]["vector"] = extract_vector(port_data)
        norm["ports"][port]["name"] = port_data["name"]
    norm["labels"] = get_label_names(host_data)
    return norm


def store_fingerprints(out_path, data):
    fingerprints = {"hosts": []}
    norm_hosts = []

    for host_data in data.values():
        norm_host = normalized_host(host_data)
        norm_hosts.append(norm_host)
        for norm_port in norm_host["ports"].values():
            module_X[norm_port["name"]].append(norm_port["vector"])

    # Train models
    for m, X in module_X.items():
        if len(X) == 0:
            continue

        # TODO: temp
        if len(X) < NUM_CLUSTERS:
            continue

        clt = KMeans(n_clusters=NUM_CLUSTERS)
        X = np.array(X)
        clt.fit(X)

        module_models[m] = clt

    for norm_host in norm_hosts:
        for port, norm_port in norm_host["ports"].items():
            # TODO: Fix this inefficient code plz :o
            model = module_models.get(norm_port["name"])
            if not model:
                continue
            norm_host["ports"][port]["cluster"] = model.predict([norm_port["vector"]])[0]
        fingerprints["hosts"].append(fp)

    fingerprints["models"] = module_models
    joblib.dump(fingerprints, out_path)


def load_fingerprints(fp_path):
    global host_fingerprints
    global module_models
    fingerprints = joblib.load(fp_path)
    module_models = fingerprints["models"]
    host_fingerprints = fingerprints["hosts"]


def distance_host(norm_host):
    dist_host = {
        "ports": []
    }

    if len(norm_host["ports"]) < 1:
        return None

    for port, port_data in norm_host["ports"].items():
        model = module_models.get(port_data["name"])
        if model:
            dist_port = {}
            dist_port["name"] = port_data["name"]
            dist_port["cluster"] = model.predict([port_data["vector"]])[0]
            trns = model.transform([port_data["vector"]])
            dist_port["distance"] = min(trns[0])
            dist_port["port"] = port
            dist_host["ports"].append(dist_port)
    return dist_host


"""
def compare_hosts(clust_host1, clust_host2):
    print("COMPARING HOSTS:", clust_host1, clust_host2)
    if len(clust_host1["ports"]) > len(clust_host2["ports"]):
        host1 = clust_host1
        host2 = clust_host2
    else:
        host1 = clust_host2
        host2 = clust_host1

    ports1 = host1["ports"]
    if len(ports1) < 1:
        return False
    for port, port_clust1 in ports1.items():
        port_clust2 = host2["ports"].get(port)
        if port_clust2:
            print("CMP port {} with clust {} TO other port with clust {}".format(port, port_clust1, port_clust2))
            if port_clust1 != port_clust2:
                return False
        else:
            return False
    return True
"""


# Match the host against the fingerprints
def match(host_data):
    norm_host = normalized_host(host_data)

    print("distance host:", distance_host(norm_host))

    """
    clustered_host = {"ports":{}}

    for port, norm_port in norm_host["ports"].items():
        name = norm_port["name"]
        vec = norm_port["vector"]
        clt = module_models.get(name)
        if not clt:
            print("NO CLASSIFIER FOR {}".format(name))
            continue

    found_match = False
    for fp in host_fingerprints:
        if compare_hosts(fp, clustered_host):
            found_match = True
            break

    if found_match:
        print("Host MATCHED")
    else:
        print("Host did NOT match")
    """
