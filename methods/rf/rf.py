from sklearn.feature_extraction import FeatureHasher
from sklearn.ensemble import RandomForestClassifier

from modules.label import Label
import numpy as np
import math
import joblib
from pprint import pprint
import sys
from methods.rf.utils import cluster_module_data
import methods.rf.models
import modules.label
import modules
from modules.port import Port
from modules.generic import GenericPort
from modules.protocol import is_default_port

import methods.rf.http
import methods.rf.ssh
import methods.rf.generic
import methods.rf.tls


# Whether to disregard all advanced features and only classify based on the list of open ports.
# Changing this requires retraining.
# TODO: make shit like this configurable >:(
_MODE_PROBE = 2
_CLASSIFY_MODE = 0


_module_handlers = {
    "HttpPort": methods.rf.http,
    "SshPort": methods.rf.ssh,
    "TlsPort": methods.rf.tls,
    "GenericPort": methods.rf.generic,
}


_open_ports_hasher = FeatureHasher(n_features=1000, input_type="dict")

_probe_hashers = {}
for mod_name in _module_handlers.keys():
    _probe_hashers[mod_name] = FeatureHasher(n_features=50, input_type="dict")

_generic_module = methods.rf.generic

_fingerprints = {}


def _new_module_features_map():
    features = {}
    for mod_name in _module_handlers.keys():
        features[mod_name] = []
    return features


def _hash_module_features_map(feat_map):
    hashed = {}
    for mod_name in sorted(feat_map.keys()):
        hashed[mod_name] = _probe_hashers[mod_name].fit_transform(feat_map[mod_name])

    ret = []
    for mod_name in sorted(hashed.keys()):
        ret.extend(hashed[mod_name])
    return ret


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
    open_ports_X = []
    probe_X = {}
    if _CLASSIFY_MODE & _MODE_PROBE:
        for mod_name in _module_handlers.keys():
            probe_X[mod_name] = []
    # Ground truth for training.
    y = []
    for host in args:
        open_ports_x = {}
        probe_x = {}
        for mod_name in _module_handlers.keys():
            probe_x[mod_name] = {}

        for port in host.ports.values():
            if _CLASSIFY_MODE & _MODE_PROBE:
                if port.tls:
                    probe_x[port.tls.__class__.__name__].update(_get_module_handler(port.tls).convert(port.tls))
                probe_x[port.__class__.__name__].update(_get_module_handler(port).convert(port))
            open_ports_x["port:" + str(port.port)] = 1
        open_ports_X.append(open_ports_x)

        if _CLASSIFY_MODE & _MODE_PROBE:
            for mod_name in probe_x.keys():
                probe_X[mod_name].append(probe_x[mod_name])
        y.append(host.label_str())
    # DEBUG PRINT
    #print("open_ports_X[0]:", open_ports_X[0])
    # END DEBUG PRINT

    # DEBUG PRINTS
    #for mod_name in _module_handlers.keys():
    #    print("probe_X[{}][0]:".format(mod_name), probe_X[mod_name][0])
    # END DEBUG PRINTS

    open_ports_h_X = _open_ports_hasher.fit_transform(open_ports_X).toarray()

    ret_X = []
    for i in range(len(open_ports_h_X)):
        l = open_ports_h_X[i].tolist()
        ret_X.append(l)

    if _CLASSIFY_MODE & _MODE_PROBE:
        for mod_name in sorted(probe_X.keys()):
            hashed = _probe_hashers[mod_name].fit_transform(probe_X[mod_name]).toarray()
            mod_X = []
            for i in range(len(hashed)):
                l = hashed[i].tolist()
                mod_X.append(l)
            for i in range(len(ret_X)):
                ret_X[i] = ret_X[i] + mod_X[i]

    # DEBUG PRINT
    #print("ret_X[0] ({}):".format(len(ret_X[0])), ret_X[0])
    # END DEBUG PRINT
    return ret_X, y


def get_fingerprints(data):
    fingerprints = {}
    module_models = {}

    # Train modules
    if _CLASSIFY_MODE & _MODE_PROBE:
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
