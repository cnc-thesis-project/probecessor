import joblib
import modules.label


_fp_hosts = None


def store_fingerprints(fp_out, hosts):
    joblib.dump(hosts, fp_out)


def load_fingerprints(fp_path):
    global _fp_hosts
    _fp_hosts = joblib.load(fp_path)


def match(host, force=False):
    labels_matched = {}
    for fp_host in _fp_hosts.values():
        if not force and fp_host.ip == host.ip:
            continue
        fp_match = True
        if len(fp_host.ports) > 0 and len(fp_host.ports) == len(host.ports):
            for port_num, fp_port in fp_host.ports.items():
                port = host.ports.get(port_num)
                if not port:
                    fp_match = False
                    break
        else:
            fp_match = False

        if fp_match:
            label_str = modules.label.Label.to_str(fp_host.labels)
            if not labels_matched.get(label_str):
                labels_matched[label_str] = {"count": 0, "labels":[]}
            labels_matched[label_str]["count"] += 1
            labels_matched[label_str]["labels"].extend(fp_host.labels)

    max_count = 0
    labels = []
    for l in labels_matched.values():
        if max_count < l["count"]:
            max_count = l["count"]
            labels = l["labels"]

    return (host, labels)
