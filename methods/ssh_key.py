import joblib
import modules.label

pubkey_label = {}

def is_binary_classifier():
    return False

def get_default_config():
    return {}

def get_configs():
    return [{}]

def use_config(config):
	pass


def load_fingerprints(fp_path):
    global pubkey_label
    fp_hosts = joblib.load(fp_path)
    for fp_host in fp_hosts.values():
        for port in fp_host.ports.values():
            if port.type != "ssh":
                continue

            for key in ["ssh-rsa:sha256", "ssh-ed25519:sha256", "ecdsa-sha2-nistp256:sha256",
                        "ecdsa-sha2-nistp384:sha256", "ecdsa-sha2-nistp521:sha256"]:
                hash = port.get_property(key)
                if not hash:
                    continue

                if not hash in pubkey_label:
                    pubkey_label[hash] = {}

                print(hash)

                label = fp_host.label_str()
                if label in pubkey_label[hash]:
                    pubkey_label[hash][label] += 1
                else:
                    pubkey_label[hash][label] = 1

    for hash in pubkey_label:
        # get the most occuring label for each ssh key hash
        l = max(pubkey_label[hash].items(), key = lambda k: k[1])[0]
        # convert to Label object since match function needs to return in that format
        pubkey_label[hash] = modules.label.Label("", l, None)


# Returns the fingerprint match. If none match, return None.
def match(host, force=False, test=False):
    for port in host.ports.values():
        if not port or port.type != "ssh":
            continue
        hash = port.get_property("hash")
        if hash in pubkey_label:
            return (host, [pubkey_label[hash]])

    return (host, [])
