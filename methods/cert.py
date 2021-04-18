import joblib
import modules.label

_hash_label = {}

def is_binary_classifier():
    return False

def get_default_config():
    return {}

def get_configs():
    return [{}]

def use_config(config):
    pass


def get_fingerprints(hosts):
    for host in hosts.values():
        checked_ports = set()
        for label in host.labels:
            if label.port in checked_ports:
                continue
            checked_ports.add(label.port)

            port = host.ports.get(label.port)
            if not port or not port.tls:
                continue

            hash = port.tls.get_property("key_sha256")
            _hash_label[hash] = label

    return _hash_label


def use_fingerprints(fps):
    global _hash_label
    _hash_label = fps


# Returns the fingerprint match. If none match, return None.
def match(host, force=False, test=False):
    for port in host.ports.values():
        if not port or not port.tls:
            continue

        hash = port.tls.get_property("key_sha256")
        if hash in _hash_label:
            return (host, [_hash_label[hash]])

    return (host, [])
