from sklearn.cluster import KMeans
import numpy as np
import math
import joblib
from pprint import pprint
import sys
import methods.cluster.http
import methods.cluster.ssh
import methods.cluster.generic


_modules = {
    "HttpPort": methods.cluster.http,
    "SshPort": methods.cluster.ssh,
}


_generic_module = methods.cluster.generic


def _get_module_handler(module):
    return _modules.get(module.__class__.__name__, _generic_module)


# TODO: Use number of clusters per mod instead of a global value.
NUM_CLUSTERS = 20

module_models = {}
host_fingerprints = []


# Convert the module to a data representation of the module
# as a dictionary.
def convert_module(module):
    mod_data = _get_module_handler(module).get_data(module)
    mod_data["module"] = module.__class__.__name__
    return mod_data


# Convert a Host instance to a data representation
# that can be used for fingerprinting and matching.
def convert_host(host):
    host_data = {"ports": {}, "ip": host.ip, "labels": host.labels }
    for port in host.ports.values():
        host_data["ports"][port.port] = convert_module(port)

    return host_data


# Returns a list described by desc of the mutual orders of the elements in li.
def list_to_order_list(li, desc):
    res = [-1 for i in range(len(desc.values()))]
    j = 0
    for i in range(len(li)):
        if li[i] in desc.keys():
            res[desc[li[i]]] = j
            j+=1
    return res


def store_fingerprints(out_path, data):
    fingerprints = {"hosts": []}
    conv_hosts = []
    module_X = {}

    for host in data.values():
        print("Handling host {} ...".format(host.ip))
        conv_host = convert_host(host)
        conv_hosts.append(conv_host)
        for port_data in conv_host["ports"].values():
            print("  Handling {}".format(port_data["module"]))
            port_module = port_data["module"]
            port_vector = port_data.get("vector")

            if port_vector:
                vectors = module_X.get(port_module)
                if vectors is None:
                    vectors = []
                    module_X[port_module] = vectors
                vectors.append(port_vector)

    print("Training:", module_X.keys())
    # Train models
    for m, X in module_X.items():
        print("Training model for {}".format(m))
        if len(X) == 0:
            print("error: len(X) == 0")
            continue

        if len(X) <= NUM_CLUSTERS:
            print("WARNING: Can't train model for '{}'. Too few samples.".format(m))
            continue

        clt = KMeans(n_clusters=NUM_CLUSTERS)
        X = np.array(X)
        clt.fit(X)

        module_models[m] = clt

    for conv_host in conv_hosts:
        # Pliz figz dis inefficient code :o
        fingerprint_host_data(conv_host)
        fingerprints["hosts"].append(conv_host)

    fingerprints["models"] = module_models
    joblib.dump(fingerprints, out_path)


def load_fingerprints(fp_path):
    global host_fingerprints
    global module_models
    fingerprints = joblib.load(fp_path)
    module_models = fingerprints["models"]
    host_fingerprints = fingerprints["hosts"]


def fingerprint_host_data(host_data):
    for port, port_data in host_data["ports"].items():
        model = module_models.get(port_data["module"])
        if not model:
            #print("WARNING: No model for port of type '{}'".format(port_data["module"]))
            continue
        port_data["cluster"] = model.predict([port_data["vector"]])[0]
        # Get the distance to the closest centroid.
        trns = model.transform([port_data["vector"]])
        port_data["distance"] = min(trns[0])


def match_host_data(host_data1, host_data2):
    if len(host_data2["ports"]) > len(host_data1["ports"]):
        tmp_host = host_data2
        host_data2 = host_data1
        host_data1 = tmp_host

    for port_num, port_data1 in host_data1["ports"].items():
        port_data2 = host_data2["ports"].get(port_num)
        if port_data2:
            if not match_mod_data(port_data1, port_data2):
                return False
        else:
            return False
    return True


def match_mod_data(mod_data1, mod_data2):
    if mod_data1["module"] != mod_data2["module"]:
        return False
    return _get_module_handler(mod_data1["module"]).match(mod_data1, mod_data2)


# Match the host against the fingerprints
def match(host, force=False):
    host_data = convert_host(host)

    if not host_data:
        return (host,[])

    for fp_host_data in host_fingerprints:
        if fp_host_data["ip"] == host_data["ip"] and not force:
            # ignoring same host
            print("Refusing to compare host {} with itself. Use the --force, Luke.".format(host.ip))
            continue

        if match_host_data(fp_host_data, host_data):
            return (host, fp_host_data["labels"])

    return (host, [])
