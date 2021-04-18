import joblib
import modules.label

_pubkey_label = {}

def is_binary_classifier():
    return False

def get_default_config():
    return {}

def get_configs():
    return [{}]

def use_config(config):
    pass


def use_fingerprints(fps):
    global _pubkey_label
    _pubkey_label = fps


def get_fingerprints(fps):
    _pubkey_label = {}
    for host in fps.values():
        for port in host.ports.values():
            if port.type != "ssh":
                continue

            for key in ["ssh-rsa:sha256", "ssh-ed25519:sha256", "ecdsa-sha2-nistp256:sha256",
                        "ecdsa-sha2-nistp384:sha256", "ecdsa-sha2-nistp521:sha256"]:
                hash = port.get_property(key)
                if not hash:
                    continue

                if not hash in _pubkey_label:
                    _pubkey_label[hash] = {}

                print(hash)

                label = host.label_str()
                if label in _pubkey_label[hash]:
                    _pubkey_label[hash][label] += 1
                else:
                    _pubkey_label[hash][label] = 1

    for hash in _pubkey_label:
        # get the most occuring label for each ssh key hash
        l = max(_pubkey_label[hash].items(), key = lambda k: k[1])[0]
        # convert to Label object since match function needs to return in that format
        _pubkey_label[hash] = modules.label.Label("", l, None)
    return _pubkey_label


# Returns the fingerprint match. If none match, return None.
def match(host, force=False, test=False):
    for port in host.ports.values():
        if not port or port.type != "ssh":
            continue
        hash = port.get_property("hash")
        if hash in _pubkey_label:
            return (host, [_pubkey_label[hash]])

    return (host, [])
