from sklearn.cluster import KMeans
from sklearn.feature_extraction import FeatureHasher
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

import numpy as np
import math
import joblib
from pprint import pprint
import sys
from methods.port_cluster.utils import cluster_module_data
import methods.port_cluster.models
import modules.label
from modules.port import Port

import methods.port_cluster.http
import methods.port_cluster.ssh
import methods.port_cluster.generic
import methods.port_cluster.tls


_module_handlers = {
    "HttpPort": methods.port_cluster.http,
    "SshPort": methods.port_cluster.ssh,
    "TlsPort": methods.port_cluster.tls,
}


_port_handlers = {
    "HttpPort": methods.port_cluster.http,
    "SshPort": methods.port_cluster.ssh,
}


_open_ports_hasher = FeatureHasher(n_features=1000, input_type="dict")

_generic_module = methods.port_cluster.generic


def _get_module_handler(module_name):
    return _module_handlers.get(module_name, _generic_module)


# TODO: Use number of clusters per mod instead of a global value.
NUM_CLUSTERS = 32

_fingerprints = {}


# Convert the module to a data representation of the module
# as a dictionary.
def _convert_module(module):
    mod_data = _get_module_handler(module.__class__.__name__).get_data(module)
    mod_data["module"] = module.__class__.__name__
    if isinstance(module, Port):
        mod_data["port"] = module.port
        if module.tls:
            mod_data["tls"] = _convert_module(module.tls)
    return mod_data


def get_default_config():
    return {}


def get_configs():
    return [{}]


def use_config(conf):
    pass


def is_binary_classifier():
    return False


def _get_open_ports_vectors(*args):
    open_ports_X = []
    for host in args:
        open_ports_x = {}
        for port in host.ports.values():
            open_ports_x[str(port.port)] = 1
        open_ports_X.append(open_ports_x)
    return _open_ports_hasher.transform(open_ports_X).toarray()


def get_fingerprints(data):
    fingerprints = {"ports": []}
    module_X_map = {}
    open_ports_X = _get_open_ports_vectors(*data.values())
    open_ports_y = []

    for host in data.values():
        open_ports_x = {}
        has_labeled_port = False
        for port in host.ports.values():
            port_data = _convert_module(port)
            port_data["ip"] = host.ip
            port_module = port_data["module"]
            port_vector = port_data.get("vector")

            if port_vector:
                vectors = module_X_map.get(port_module)
                if vectors is None:
                    vectors = []
                    module_X_map[port_module] = vectors
                vectors.append(port_vector)

            labels = host.get_port_label(port.port, False)
            if len(labels):
                port_data["labels"] = labels
                # Only add the port to the fingerprint list if it is labeled.
                fingerprints["ports"].append(port_data)

        # TODO: we need multi-labels, not just a binary classification.
        open_ports_y.append(host.label_str())

    # Train cluster models
    """
    for m, X in module_X_map.items():
        print("Training port model for {} ...".format(m))
        if len(X) == 0:
            print("error: len(X) == 0")
            continue

        X = np.array(X)
        clt = KMeans(n_clusters=NUM_CLUSTERS)
        clt.fit(X)

        methods.port_cluster.models.models[m] = clt
    """


    for port_data in fingerprints["ports"]:
        if port_data.get("vector"):
            cluster_module_data(port_data)


    # Train open ports model
    print("Training open ports classifier ...")
    rf = RandomForestClassifier()
    rf.fit(open_ports_X, open_ports_y)


    fingerprints["module_models"] = methods.port_cluster.models.models
    fingerprints["open_ports_model"] = rf

    return fingerprints


def use_fingerprints(fp):
    global _fingerprints
    _fingerprints = fp
    #print("Loaded {} port fingerprints".format(len(_fingerprints["ports"])))
    #print("Loaded models:", _fingerprints.get("module_models"))
    methods.port_cluster.models.models = _fingerprints["module_models"]


def _match_mod_data(mod_data1, mod_data2):
    if mod_data1["module"] != mod_data2["module"]:
        return False
    return _get_module_handler(mod_data1["module"]).match(mod_data1, mod_data2)


def _match_port_data(port_data1, port_data2):
    if port_data1["port"] != port_data2["port"]:
        return False
    if _match_mod_data(port_data1, port_data2):
        if port_data1.get("tls") and port_data2.get("tls"):
            return _match_mod_data(port_data1["tls"], port_data2["tls"])

        if port_data1.get("tls") != port_data2.get("tls"):
            return False

        return True
    return False


# Match the host against the fingerprints
def match(host, force=False, test=False):
    labels_matched = {}

    open_ports_x = _get_open_ports_vectors(host)
    if _fingerprints["open_ports_model"].predict(open_ports_x)[0] == host.label_str():
        return (host, host.labels)
    else:
        return (host, [])

    for port in host.ports.values():
        port_data = _convert_module(port)

        for fp_port_data in _fingerprints["ports"]:
            if fp_port_data["ip"] == host.ip and not force:
                # ignoring same host
                #print("Refusing to compare host {} with itself. Use the --force, Luke.".format(host.ip))
                continue
            if _match_port_data(fp_port_data, port_data):
                #print("* MATCH *")
                #print("    Port: {}".format(port_data["port"]))
                #print(fp_port_data["labels"][0].label)
                label_str = modules.label.Label.to_str(fp_port_data["labels"])
                if not labels_matched.get(label_str):
                    labels_matched[label_str] = {"count": 0, "labels":[]}
                labels_matched[label_str]["count"] += 1
                labels_matched[label_str]["labels"].extend(fp_port_data["labels"])

    max_count = 0
    labels = []
    for l in labels_matched.values():
        if max_count < l["count"]:
            max_count = l["count"]
            labels = l["labels"]

    return (host, labels)
