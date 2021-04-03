import joblib
import modules.label

hash_label = {}

def load_fingerprints(fp_path):
    global subject_label
    fp_hosts = joblib.load(fp_path)
    for fp_host in fp_hosts.values():
        checked_ports = set()
        for label in fp_host.labels:
            if label.port in checked_ports:
                continue
            checked_ports.add(label.port)

            port = fp_host.ports.get(label.port)
            if not port or not port.tls:
                continue

            hash = port.tls.get_property("key_sha256")
            hash_label[hash] = label

# Returns the fingerprint match. If none match, return None.
def match(host, force=False):
    for port in host.ports.values():
        if not port or not port.tls:
            continue

        hash = port.tls.get_property("key_sha256")
        if hash in hash_label:
            return (host, [hash_label[hash]])

    return (host, [])
