import joblib
import modules.label

jarm_label = {}

def load_fingerprints(fp_path):
    global jarm_label
    fp_hosts = joblib.load(fp_path)
    for fp_host in fp_hosts.values():
        for label in fp_host.labels:
            port = fp_host.ports.get(label.port)
            if not port or not port.tls:
                continue

            jarm = port.tls.get_property("jarm")
            if not jarm in jarm_label:
                jarm_label[jarm] = {}

            if label.label in jarm_label[jarm]:
                jarm_label[jarm][label.label] += 1
            else:
                jarm_label[jarm][label.label] = 1

    for jarm in jarm_label:
        # get the most occuring label in each jarm hash
        l = max(jarm_label[jarm].items(), key = lambda k: k[1])[0]
        # convert to Label object since match function needs to return in that format
        jarm_label[jarm] = modules.label.Label("", l, None)


# Returns the fingerprint match. If none match, return None.
def match(host, force=False):
    for port in host.ports.values():
        if not port or not port.tls:
            continue
        jarm = port.tls.get_property("jarm")
        if jarm in jarm_label:
            return (host, [jarm_label[jarm]])

    #for port in host.ports.values():
    #    if port.tls:

    #for port in host.ports.values():
    #    if port.tls:
    #        print(port.tls.get_property("jarm"))

    return (host, [])
