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
    open_ports_y = []
    for host in args:
        open_ports_x = {}
        for port in host.ports.values():
            open_ports_x[port.type + ":" + str(port.port)] = _get_module_handler(port.__class__.__name__).convert(port)
        open_ports_X.append(open_ports_x)
        open_ports_y.append(host.label_str())
    print("open_ports_X[0]:", open_ports_X[0])
    return _open_ports_hasher.transform(open_ports_X).toarray(), open_ports_y


def get_fingerprints(data):
    fingerprints = {}
    open_ports_y = []
    module_models = {}

    # Train modules
    for host in data.values():
        for port in host.ports.values():
            mod = _get_module_handler(port.__class__.__name__)
            mod.add_data(port)
    for mod_name, mod in _module_handlers.items():
        module_models[mod_name] = mod.train()

    open_ports_X, open_ports_y = _get_open_ports_vectors(*data.values())

    # Train ports model
    print("Training open ports classifier ...")
    cls = RandomForestClassifier()
    cls.fit(open_ports_X, open_ports_y)

    fingerprints["open_ports_model"] = cls
    fingerprints["module_models"] = module_models

    return fingerprints


def use_fingerprints(fp):
    global _fingerprints
    _fingerprints = fp
    for mod_name, mod in _module_handlers.items():
        model = fp["module_models"].get(mod_name)
        if model:
            mod.set_model(model)
        else:
            print("WARNING: NO MODEL IN FINGERPRINT FILE MATCHING MODULE '{}'".format(mod_name))
    #print("Loaded {} port fingerprints".format(len(_fingerprints["ports"])))
    #print("Loaded models:", _fingerprints.get("module_models"))


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

    open_ports_x,_ = _get_open_ports_vectors(host)
    if _fingerprints["open_ports_model"].predict(open_ports_x)[0] == host.label_str():
        return (host, host.labels)
    else:
        return (host, [])

    # TODO: the below is not currently used for anything. Should perhaps be removed in the future.
    """
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
    """
