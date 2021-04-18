import joblib
import modules.label


jarm_label = {}


def is_binary_classifier():
    return False


def get_default_config():
    return {}


def get_configs():
    return [{}]


def use_config(config):
    pass


def use_fingerprints(fp):
    global jarm_label
    jarm_label = fp


def get_fingerprints(hosts):
    global jarm_label
    for host in hosts.values():
        checked_ports = set()
        for label in host.labels:
            if label.port in checked_ports:
                continue
            checked_ports.add(label.port)

            port = host.ports.get(label.port)
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

    return jarm_label


def match(host, force=False, test=False):
    for port in host.ports.values():
        if not port or not port.tls:
            continue
        jarm = port.tls.get_property("jarm")
        if jarm in jarm_label:
            return (host, [jarm_label[jarm]])

    return (host, [])
