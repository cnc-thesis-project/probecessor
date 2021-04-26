from sklearn.feature_extraction import FeatureHasher
from sklearn.ensemble import RandomForestClassifier

from modules.label import Label
import numpy as np
import math
import joblib
from pprint import pprint
import sys
from methods.port_cluster.utils import cluster_module_data
import methods.port_cluster.models
import modules.label
import modules
from modules.port import Port
from modules.generic import GenericPort
from modules.protocol import is_default_port

import methods.port_cluster.http
import methods.port_cluster.ssh
import methods.port_cluster.generic
import methods.port_cluster.tls


# Whether to disregard all advanced features and only classify based on the list of open ports.
# Changing this requires retraining.
# TODO: make shit like this configurable >:(
_SIMPLE_CLASSIFY = False


_module_handlers = {
    "HttpPort": methods.port_cluster.http,
    "SshPort": methods.port_cluster.ssh,
    "TlsPort": methods.port_cluster.tls,
}


_open_ports_hasher = FeatureHasher(n_features=1000, input_type="dict")

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
    # List of dictionaries containing named features that will go into the hasher.
    X = []
    # List of lists of features that will be appended to the hashed vector.
    # These features will not be passed into the hasher, but will be appended to the hashers output vector.
    X_nohash = []
    # Ground truth for training.
    y = []
    for host in args:
        open_ports_x = {}

        non_default_port_counts = 0
        port_type_counts = {}
        for p in modules._ports:
            port_type_counts[p] = 0
        for port in host.ports.values():
            if not _SIMPLE_CLASSIFY:
                if not is_default_port(port):
                    non_default_port_counts += 1

                if port_type_counts.get(port.type):
                    port_type_counts[port.type] += 1
                else:
                    port_type_counts["unknown"] += 1
                if port.tls:
                    open_ports_x.update(_get_module_handler(port.tls).convert(port.tls))
                    port_type_counts[port.tls.type] += 1

                open_ports_x.update(_get_module_handler(port).convert(port))
                open_ports_x[port.type + ":" + str(port.port)] = 1
            open_ports_x["port:" + str(port.port)] = 1
        x_noh = [len(host.ports), non_default_port_counts/len(host.ports)]
        for p in sorted(port_type_counts):
            x_noh.append(port_type_counts[p]/len(host.ports))
        X_nohash.append(x_noh)
        X.append(open_ports_x)
        y.append(host.label_str())
    #print("X[0]:", X[0])
    hashed_X = _open_ports_hasher.fit_transform(X).toarray()
    ret_X = []
    for i in range(len(hashed_X)):
        l = hashed_X[i].tolist()
        l.extend(X_nohash[i])
        ret_X.append(l)

    #print("ret_X[0]:", ret_X[0])
    return ret_X, y


def get_fingerprints(data):
    fingerprints = {}
    module_models = {}

    # Train modules
    if not _SIMPLE_CLASSIFY:
        for host in data.values():
            for port in host.ports.values():
                mod = _get_module_handler(port)
                mod.add_data(port)
        for mod_name, mod in _module_handlers.items():
            module_models[mod_name] = mod.train()

    X, y = _get_open_ports_vectors(*data.values())

    # Train ports model
    print("Training open ports classifier ...")
    cls = RandomForestClassifier(max_features="sqrt", n_estimators=400, min_samples_leaf=1)
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
