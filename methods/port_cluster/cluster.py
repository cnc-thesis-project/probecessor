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


def _get_module_handler(module):
    return _module_handlers.get(module.__class__.__name__, _generic_module)


_fingerprints = {}


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
            if port.tls:
                open_ports_x[port.tls.type + ":" + str(port.port)] = _get_module_handler(port.tls).convert(port.tls)
            open_ports_x[port.type + ":" + str(port.port)] = _get_module_handler(port).convert(port)
        open_ports_X.append(open_ports_x)
        open_ports_y.append(host.label_str())
    return _open_ports_hasher.transform(open_ports_X).toarray(), open_ports_y


def get_fingerprints(data):
    fingerprints = {}
    open_ports_y = []
    module_models = {}

    # Train modules
    for host in data.values():
        for port in host.ports.values():
            mod = _get_module_handler(port)
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
    #print("Loaded {} port fingerprints".format(len(_fingerprints["ports"])))
    #print("Loaded models:", _fingerprints.get("module_models"))


# Match the host against the fingerprints
def match(host, force=False, test=False):
    labels_matched = {}

    open_ports_x,_ = _get_open_ports_vectors(host)
    if _fingerprints["open_ports_model"].predict(open_ports_x)[0] == host.label_str():
        return (host, host.labels)
    else:
        return (host, [])
