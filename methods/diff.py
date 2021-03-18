import itertools
from pprint import pprint
import json
import html_similarity
from util.label import get_label_names

def get_module_weight(mod_keys):
    return sum(map(lambda x: x["weight"], mod_keys))

def _compare_equal(value1, value2):
    return 0 if value1 == value2 else 1

def _compare_entropy(value1, value2):
    # set the distance as entropy diff, but up to 1.0
    return min(abs(value1 - value2), 1)

def _compare_header_keys(value1, value2):
    #if value1 is None:
    #    value1 = []
    #if value2 is None:
    #    value2 = []
    if ".".join(value1) == ".".join(value2):
        return 0
    else:
        return 1

def _compare_dom_tree(value1, value2):
    #if value1 is None:
    #    value1 = ""
    #if value2 is None:
    #    value2 = ""
    if value1 == value2:
        return 0
    try:
        return 1 - html_similarity.structural_similarity(value1, value2)
    except AttributeError:
        return 1

diff_keys = {
    "http": [
        # populated at runtime using code
    ],
    "ssh": [
        { "name": "ciphers:kex_algorithms", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ciphers:server_host_key_algorithms", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ciphers:encryption_algorithms_client_to_server", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ciphers:encryption_algorithms_server_to_client", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ciphers:mac_algorithms_client_to_server", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ciphers:mac_algorithms_server_to_client", "cmp": _compare_equal, "weight": 1.0 },
    ],
    "tls": [
        { "name": "subject", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "issuer", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "sign_alg", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "hash_alg", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "key_size", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "key_sha1", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "not_before", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "not_after", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "valid_period", "cmp": _compare_equal, "weight": 1.0 },
#        { "name": "valid_domains", "cmp": _compare_equal, "weight": 1.0 },
#        { "name": "valid_ips", "cmp": _compare_equal, "weight": 1.0 },
#        { "name": "jarm", "cmp": _compare_equal, "weight": 1.0 },

    ],
    "unknown": [
        { "name": "response", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "entropy", "cmp": _compare_entropy, "weight": 1.0 },
    ]
}

http_request_types = ["get_root", "head_root", "delete_root", "very_simple_get", "not_exist",
                "invalid_version", "invalid_protocol", "long_path", "get_favicon", "get_robots"]
for request in http_request_types:
    diff_keys["http"].append({ "name": "{}:header:Server".format(request), "cmp": _compare_header_keys, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:header:Content-Type".format(request), "cmp": _compare_header_keys, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:header_keys".format(request), "cmp": _compare_header_keys, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:status_code".format(request), "cmp": _compare_equal, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:dom_tree".format(request), "cmp": _compare_dom_tree, "weight": 1.0 })


def port_diff(name, data1, data2):
    distance = 0
    data1 = data1.get(name, {})
    data2 = data2.get(name, {})
    # TODO: check for silent port
    for key_meta in diff_keys[name]:
        key = key_meta["name"]
        value1 = data1.get(key)
        value2 = data2.get(key)
        if value1 is None and value2 is None:
            # both doesn't have the key -> similar!
            key_dist = 0
        elif value1 is None or value2 is None:
            # either one lacks the key -> not similar!
            key_dist = 1
        else:
            # both have the key -> compare the values and get distance
            key_dist = key_meta["cmp"](value1, value2)
        distance += key_dist

    return distance / get_module_weight(diff_keys[name])

def connect_ports(distances):
    fp_ports = set(map(lambda x: x[1], distances))
    host_ports = set(map(lambda x: x[2], distances))
    candidates = []
    # if multiple ports have same distance, 'x[1] != x[2]' makes so it gets prioritized in case the port number matches
    distances = sorted(distances, key=lambda x: x[0] + (x[1] != x[2]) * 1e-128)
    while len(host_ports) > 0 and len(distances) > 0:
        distance, fp_port, host_port = distances[0]

        del distances[0]
        if not host_port in host_ports or not fp_port in fp_ports:
            continue
        fp_ports.remove(fp_port)
        host_ports.remove(host_port)

        candidates.append((distance, fp_port, host_port))

    return candidates

# Returns the fingerprint match. If none match, return None.
def classify(in_path, host_data):
    with open(in_path, "r") as f:
        data = json.load(f)

    #print(data)
    #print(host_data)

    ports = host_data["port"]

    host_ports = {}
    for port, port_data in host_data["port"].items():
        if len(port_data) == 0:
            # silent port
            continue
        mod_name = port_data["name"]
        if not mod_name in host_ports:
            host_ports[mod_name] = []
        host_ports[mod_name].append((port, port_data))

    ip_distances = []
    for ip, fp_data in data.items():
        fp_ports = {}
        for port, port_data in fp_data["port"].items():
            if len(port_data) == 0:
                # silent port
                continue
            mod_name = port_data["name"]
            if not mod_name in fp_ports:
                fp_ports[mod_name] = []
            fp_ports[mod_name].append((port, port_data))

        total_dist = 0
        max_dist = 0
        # list of tuple with port from both host that looks most identical, each port is only referenced once
        candidates = []
        for mod in set(fp_ports.keys()) & set(host_ports.keys()):
            distances = [] # list of tuple in format: (distance, fingerprint port, host port)
            for (fp_port, fp_port_data), (host_port, host_port_data) in itertools.product(fp_ports[mod], host_ports[mod]):
                # get distance between two ports and add the result to list distances
                dist = port_diff(mod, fp_port_data, host_port_data)
                if "tls" in fp_port_data or "tls" in host_port_data:
                    dist = (dist + port_diff("tls", fp_port_data, host_port_data)) / 2.0
                distances.append((dist, fp_port, host_port))

            c = connect_ports(distances)
            candidates.extend(c)
            total_dist += sum(map(lambda x: x[0], c))

        fp_port_used = list(map(lambda x: x[1], candidates))
        fp_port_left = list(filter(lambda x: x not in fp_port_used, fp_data["port"].keys()))

        host_port_used = list(map(lambda x: x[2], candidates))
        host_port_left = list(filter(lambda x: x not in host_port_used, host_data["port"].keys()))

        # calculate the maximum possible distance
        for _, fp_port, host_port in candidates:
            # calculation for ports that was in both
            fp_port_data = fp_data["port"][fp_port]
            host_port_data = host_data["port"][host_port]

            max_dist += 1
            #if "tls" in fp_port_data or "tls" in host_port_data:
            #    max_dist += 1

        # calculation for ports that was only available in either one
        for data, port_left in [(fp_data, fp_port_left), (host_data, host_port_left)]:
            for port in port_left:
                port_data = data["port"][port]
                mod = port_data.get("name")

                total_dist += 1
                max_dist += 1
                #if "tls" in port_data:
                #    total_dist += 1
                #    max_dist += 1

        #print("{}, candidates: {}".format(ip, candidates))
        #print(fp_port_used, fp_port_left)
        #print(host_port_used, host_port_left)
        #print("Total distance: {}/{}".format(total_dist, max_dist))

        # normalize total distance to value betweeon 0.0 - 1.0
        total_dist /= max_dist #* len(set(fp_ports.keys()) | set(host_ports.keys()))

        # get labels
        labels = get_label_names(fp_data)

        ip_distances.append((total_dist, ip, labels))
        #print("Distance {} to {} ({})".format(total_dist, ip, labels))

    if len(ip_distances) == 0:
        return

    ip_distances = sorted(ip_distances)

    label = ip_distances[0][2]
    lbl_dist = 0
    for c in ip_distances:
        if label != c[2]:
            break
        lbl_dist = c[0]

    print("IP distances (distance: {}-{}, label dist: {}, label: {})".format(ip_distances[0][0],ip_distances[-1][0], lbl_dist, label))
    for c in ip_distances:
        print("Distance {} to {} ({})".format(*c))

    return
