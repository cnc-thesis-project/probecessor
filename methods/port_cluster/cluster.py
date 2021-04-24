from sklearn.feature_extraction import FeatureHasher
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from modules.label import Label
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


_open_ports_hasher = FeatureHasher(n_features=2000, input_type="dict")

_generic_module = methods.port_cluster.generic

_fingerprints = {}


def _get_module_handler(module):
    return _module_handlers.get(module.__class__.__name__, _generic_module)


def get_default_config():
    return {}


def get_configs():
    return [{}]


def use_config(conf):
    pass


def is_binary_classifier():
    return False


def _get_open_ports_vectors(*args):
    X = []
    y = []
    for host in args:
        open_ports_x = {}
        for port in host.ports.values():
            if port.tls:
                open_ports_x.update(_get_module_handler(port.tls).convert(port.tls))
            open_ports_x.update(_get_module_handler(port).convert(port))
        X.append(open_ports_x)
        y.append(host.label_str())
    return _open_ports_hasher.transform(X).toarray(), y


def get_fingerprints(data):
    fingerprints = {}
    module_models = {}

    # Train modules
    for host in data.values():
        for port in host.ports.values():
            mod = _get_module_handler(port)
            mod.add_data(port)
    for mod_name, mod in _module_handlers.items():
        module_models[mod_name] = mod.train()

    X, y = _get_open_ports_vectors(*data.values())

    # Train ports model
    print("Training open ports classifier ...")
    cls = RandomForestClassifier()
    cls.fit(X, y)

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


# Match the host against the fingerprints
def match(host, force=False, test=False):
    labels_matched = {}

    open_ports_x,_ = _get_open_ports_vectors(host)
    return (host, [Label("", _fingerprints["open_ports_model"].predict(open_ports_x)[0], 0)])
