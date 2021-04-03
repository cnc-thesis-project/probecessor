import joblib
import modules.label

def load_fingerprints(fp_path):
    pass

# Returns the fingerprint match. If none match, return None.
def match(host, force=False):
    for port in host.ports.values():
        if not port or not port.tls:
            continue

        self_issued = port.tls.get_property("self_issued")
        self_signed = port.tls.get_property("self_signed")
        if self_signed == "maybe" or self_issued:
            return (host, [modules.label.Label("", "self-signed", None)])

    return (host, [])
