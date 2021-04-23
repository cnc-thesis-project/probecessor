import joblib
import modules.label

def is_binary_classifier():
    return True

def get_default_config():
    return {}

def get_configs():
    return [{}]

def use_config(config):
	pass


def use_fingerprints(fp):
    pass

def load_fingerprints(fp_path):
    pass

def get_fingerprints(fp_path):
    return True # doesn't matter what it returns as long as it's not empty

# Returns the fingerprint match. If none match, return None.
def match(host, force=False, test=False):
    for port in host.ports.values():
        if not port or not port.tls:
            continue

        self_issued = port.tls.get_property("self_issued")
        self_signed = port.tls.get_property("self_signed")
        if self_signed == "maybe" or self_issued:
            return (host, [modules.label.Label("", "self-signed", None)])

    return (host, [])
