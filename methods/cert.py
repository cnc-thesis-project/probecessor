import joblib
import modules.label

_hash_label = {}
_issuer_label = {}
_subject_label = {}

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
            issuer = port.tls.get_property("issuer")
            subject = port.tls.get_property("subject")

            _hash_label[hash] = label
            _issuer_label[issuer] = label
            _subject_label[subject] = label

    return {"hash": _hash_label, "issuer": _issuer_label, "subject": _subject_label}


def use_fingerprints(fps):
    global _hash_label, _issuer_label
    _hash_label = fps["hash"]
    _issuer_label = fps["issuer"]


# Returns the fingerprint match. If none match, return None.
def match(host, force=False, test=False):
    for port in host.ports.values():
        if not port or not port.tls:
            continue

        hash = port.tls.get_property("key_sha256")
        if hash in _hash_label:
            return (host, [_hash_label[hash]])

        #issuer = port.tls.get_property("issuer")
        #if issuer in _issuer_label:
        #    return (host, [_issuer_label[issuer]])

        #subject = port.tls.get_property("subject")
        #if subject in _subject_label:
        #    return (host, [_subject_label[subject]])

    return (host, [])
