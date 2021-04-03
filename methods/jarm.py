import joblib
import modules.label

fp_hosts = {}

def load_fingerprints(fp_path):
    global fp_hosts
    fp_hosts = joblib.load(fp_path)

# TODO: 

# Returns the fingerprint match. If none match, return None.
def match(host, force=False):
    jarms = dict()
    for fp_host in fp_hosts.values():
        for label in fp_host.labels:
            port = fp_host.ports.get(label.port)
            if not port or not port.tls:
                continue

            jarm = port.tls.get_property("jarm")
            if not jarm in jarms:
                jarms[jarm] = {}

            if label.label in jarms[jarm]:
                jarms[jarm][label.label] += 1
            else:
                jarms[jarm][label.label] = 1

    for jarm in jarms:
        # get the most occuring label in each jarm hash
        l = max(jarms[jarm].items(), key = lambda k: k[1])[0]
        # convert to Label object since match function needs to return in that format
        jarms[jarm] = modules.label.Label("", l, None)

    for port in host.ports.values():
        if not port or not port.tls:
            continue
        jarm = port.tls.get_property("jarm")
        if jarm in jarms:
            return (host, [jarms[jarm]])

    #for port in host.ports.values():
    #    if port.tls:

    #for port in host.ports.values():
    #    if port.tls:
    #        print(port.tls.get_property("jarm"))

    return (host, [])
