import itertools
from pprint import pprint
import json
import html_similarity
import joblib
import tlsh
from util.label import get_label_names
import textdistance

# maximum distance to a malicious host to alert being "similar"
dist_threshold = 0.4
# compare only the c2 port against other hosts port
# when it's set to true, the distance is based only on the c2 port distance
focus_c2_ports = False
# all ports in two hosts with same port number must be matched, the rest depends on `random_port_match`
force_same_port_num = True
# try all combination of ports from two hosts and bind the ports that gives lowest distance
random_port_match = True
# two ports are considered totally different if the existence of tls doesn't match
must_match_tls = True

verbose = True

fp_hosts = {}

def is_binary_classifier():
    return False

def get_default_config():
    return {"dist_threshold": dist_threshold, "focus_c2_ports": focus_c2_ports,
            "force_same_port_num": force_same_port_num, "random_port_match": random_port_match}

def get_configs():
    for threshold in range(20, 51, 1): # 0.20 - 0.50
        yield {"dist_threshold": threshold/100.0, "focus_c2_ports": False,
               "force_same_port_num": True, "random_port_match": False}
    for threshold in range(20, 51, 1): # 0.20 - 0.50
        yield {"dist_threshold": threshold/100.0, "focus_c2_ports": False,
               "force_same_port_num": True, "random_port_match": True}
    #for threshold in range(20, 51, 1): # 0.20 - 0.50
    #    yield {"dist_threshold": threshold/100.0, "focus_c2_ports": False,
    #           "force_same_port_num": False, "random_port_match": True}


def use_config(config):
    global dist_threshold, ip_distance_cache
    global focus_c2_ports, force_same_port_num, random_port_match

    if focus_c2_ports != config["focus_c2_ports"] or force_same_port_num != config["force_same_port_num"] or \
            random_port_match != config["random_port_match"]:
        ip_distance_cache.clear()

    dist_threshold = config["dist_threshold"]

    focus_c2_ports = config["focus_c2_ports"]
    force_same_port_num = config["force_same_port_num"]
    random_port_match = config["random_port_match"]

def _compare_equal(value1, value2):
    return 0 if value1 == value2 else 1

def _compare_entropy(value1, value2):
    # set the distance as entropy diff, but up to 1.0
    return min(abs(value1 - value2), 1)

def _compare_histogram(value1, value2):
    return sum(map(lambda v: abs(v[0] - v[1]), zip(value1, value2))) / 2

def _compare_keys(value1, value2):
    return 0 if value1 == value2 else 1
    # very very slower with very very few accuracy improvement
    return textdistance.levenshtein.distance(value1, value2) / textdistance.levenshtein.maximum(value1, value2)

def _compare_dom_tree(value1, value2):
    return 0 if value1 == value2 else 1
    # very very slower with very very few accuracy improvement
    if value1 == value2:
        return 0
    try:
        return 1 - html_similarity.structural_similarity(value1, value2)
    except AttributeError:
        return 1

def _compare_tlsh(value1, value2):
    if value1 == "TNULL" and value2 == "TNULL":
        return 0
    elif value1 == "TNULL" or value2 == "TNULL":
        return 1
    else:
        return min(tlsh.diff(value1, value2) / 100, 1)

def _compare_strings(value1, value2):
    union = len(value1 | value2)
    if union == 0:
        return 0
    return len(value1 & value2) / union


# note: weight is not implemented
diff_keys = {
    "http": [
        # populated at runtime using code
    ],
    "ssh": [
        { "name": "server", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ciphers:kex_algorithms", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:server_host_key_algorithms", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:encryption_algorithms_client_to_server", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:encryption_algorithms_server_to_client", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:mac_algorithms_client_to_server", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:mac_algorithms_server_to_client", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:compression_algorithms_client_to_server", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:compression_algorithms_server_to_client", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:languages_client_to_server", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ciphers:languages_server_to_client", "cmp": _compare_keys, "weight": 1.0 },
        { "name": "ssh-rsa:size", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ssh-ed25519:size", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ecdsa-sha2-nistp256:size", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ecdsa-sha2-nistp384:size", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "ecdsa-sha2-nistp521:size", "cmp": _compare_equal, "weight": 1.0 },
    ],
    "tls": [
        { "name": "subject", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "issuer", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "sign_alg", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "hash_alg", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "key_size", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "key_sha256", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "not_before", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "not_after", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "valid_period", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "is_valid", "cmp": _compare_equal, "weight": 1.0 },
        { "name": "jarm", "cmp": _compare_equal, "weight": 1.0 },
        #{ "name": "valid_domains", "cmp": _compare_equal, "weight": 1.0 },
        #{ "name": "valid_ips", "cmp": _compare_equal, "weight": 1.0 },
    ],
}

for generic in ["unknown", "smtp", "pop3", "ftp", "imap"]:
    diff_keys[generic] = \
        [
            { "name": "sha256", "cmp": _compare_equal, "weight": 1.0 },
            { "name": "entropy", "cmp": _compare_entropy, "weight": 1.0 },
            { "name": "histogram", "cmp": _compare_histogram, "weight": 1.0 },
            { "name": "strings", "cmp": _compare_strings, "weight": 1.0 },
            #{ "name": "tlsh", "cmp": _compare_tlsh, "weight": 1.0 },
        ]

http_request_types = ["get_root", "head_root", "delete_root", "very_simple_get", "not_exist",
                "invalid_version", "invalid_protocol", "long_path", "get_favicon", "get_robots"]
for request in http_request_types:
    diff_keys["http"].append({ "name": "{}:header:server".format(request), "cmp": _compare_equal, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:header:content-type".format(request), "cmp": _compare_equal, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:header_keys".format(request), "cmp": _compare_keys, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:status_code".format(request), "cmp": _compare_equal, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:status_text".format(request), "cmp": _compare_equal, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:header:connection".format(request), "cmp": _compare_equal, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:header:transfer-encoding".format(request), "cmp": _compare_equal, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:header:location".format(request), "cmp": _compare_equal, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:dom_tree".format(request), "cmp": _compare_dom_tree, "weight": 1.0 })
    diff_keys["http"].append({ "name": "{}:etag".format(request), "cmp": _compare_equal, "weight": 1.0 })


def port_diff(module_name, port1, port2):
    port1_data = {k.lower(): v for k, v in port1.get_properties()}
    port2_data = {k.lower(): v for k, v in port2.get_properties()}
    key_cmp = {d["name"]: {"cmp": d["cmp"], "weight": d["weight"]} for d in diff_keys[module_name]}

    checked_keys = set()

    distance = 0
    max_dist = 0

    for key, _ in port1.get_properties():
        low_key = key.lower()
        checked_keys.add(low_key)

        if module_name == "http":
            if key.endswith(":response_start") or key.endswith(":response_end"):
                # not interested in response time data
                continue
        elif low_key not in key_cmp:
            # for non-http, the key must exist in diff_keys
            # http is exception because it has to check http headers that isn't in diff_keys
            continue

        if low_key in key_cmp:
            # note that 'key' is used instead of low_key since it's case sensitive
            # the key-value cmp will be considered different even if both have the same header as long as the cases don't match
            if port2.has_property(key):
                value1 = port1.get_property(key)
                value2 = port2.get_property(key)

                if value1 is None and value2 is None:
                    max_dist += 1
                elif value1 is None or value2 is None:
                    # either one lacks the value -> not similar!
                    distance += 1
                    max_dist += 1
                else:
                    # both have the key -> compare the values and get distance
                    distance += key_cmp[low_key]["cmp"](value1, value2)
            else:
                distance += 1
            max_dist += 1
        else:
            # not in the list => should be header key that is not listed in diff_keys
            # for these, check only the existence match in both port
            if not port2.has_property(key):
                distance += 1
            max_dist += 1

    for key, _ in port2.get_properties():
        if key.lower() in checked_keys:
            # already compared in last for-loop
            continue
        if module_name == "http":
            if key.endswith(":response_start") or key.endswith(":response_end"):
                # not interested in response time data
                continue
        elif low_key not in key_cmp:
            # for non-http, the key must exist in diff_keys
            # http is exception because it has to check http headers that isn't in diff_keys
            continue

        # all these keys don't exist in port1
        distance += 1
        max_dist += 1

    if max_dist == 0:
        # means distance is 0 as well, so doesn't matter what max_dist is as long as it's not 0
        max_dist = 1
    port_dist = distance / max_dist

    return port_dist

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


def get_fingerprints(hosts):
    return hosts


def use_fingerprints(fps):
    global fp_hosts
    fp_hosts = fps


ip_distance_cache = {}
# Returns the fingerprint match. If none match, return None.
def match(host, force=False, test=False):
    global ip_distance_cache

    host_module_map = {} # module type -> list of Port classes
    for port in host.ports.values():
        if not port.type in host_module_map:
            host_module_map[port.type] = []
        host_module_map[port.type].append(port)

    ip_distances = []
    for ip, fp in fp_hosts.items():
        if ip == host.ip:
            # don't perform self comparison
            continue

        ip_sorted = list(sorted((host.ip, fp.ip)))
        if test and "{}:{}".format(*ip_sorted) in ip_distance_cache:
            # only relevant when doing performance test
            ip_dist = ip_distance_cache["{}:{}".format(*ip_sorted)]
            if ip_dist[0] <= dist_threshold:
                ip_distances.append(ip_dist)
            continue

        c2_ports = set() # port numbers that hosts C2 service
        if focus_c2_ports:
            for label in fp.labels:
                c2_ports.add(label.port)

        fp_module_map = {} # module type -> list of Port classes
        for port in fp.ports.values():
            if not port.type in fp_module_map:
                fp_module_map[port.type] = []
            if not focus_c2_ports or port.port in c2_ports:
                fp_module_map[port.type].append(port)

        total_dist = 0
        max_dist = 0
        # list of tuple with port from both host that looks most identical, each port is only referenced once
        candidates = []
        for mod in set(fp_module_map.keys()) & set(host_module_map.keys()):
            distances = [] # list of tuple in format: (distance, fingerprint port, host port)

            # TODO: JUST TESTING REMOVE THE WHOLE FOR LOOP
            matched_ports = set()
            if force_same_port_num:
                for fp_port, host_port in itertools.product(fp_module_map[mod], host_module_map[mod]):
                    if fp_port.port != host_port.port:
                        continue

                    # get distance between two ports and add the result to list distances
                    dist = port_diff(mod, fp_port, host_port)
                    if fp_port.tls or host_port.tls:
                        if must_match_tls and (fp_port.tls is None or host_port.tls is None):
                            # consider the ports as totally different and not comparable
                            continue
                        else:
                            if fp_port.tls and host_port.tls:
                                # both has tls, diff
                                dist = (dist + port_diff("tls", fp_port.tls, host_port.tls)) / 2.0
                            else:
                                # either one doesn't have tls, so tls part differs
                                dist = (dist + 1.0) / 2.0
                    distances.append((dist, fp_port.port, host_port.port))

                    matched_ports.add(fp_port.port)


            for fp_port, host_port in itertools.product(fp_module_map[mod], host_module_map[mod]):
                if not random_port_match and fp_port.port != host_port.port:
                    continue
                if fp_port.port in matched_ports or host_port.port in matched_ports:
                    # already found the distance for that port(s)
                    continue
                # get distance between two ports and add the result to list distances
                dist = port_diff(mod, fp_port, host_port)
                if fp_port.tls or host_port.tls:
                    if must_match_tls and (fp_port.tls is None or host_port.tls is None):
                        # consider the ports as totally different and not comparable
                        continue
                    else:
                        if fp_port.tls and host_port.tls:
                            # both has tls, diff
                            dist = (dist + port_diff("tls", fp_port.tls, host_port.tls)) / 2.0
                        else:
                            # either one doesn't have tls, so tls part differs
                            dist = (dist + 1.0) / 2.0
                distances.append((dist, fp_port.port, host_port.port))

            c = connect_ports(distances)
            candidates.extend(c)
            total_dist += sum(map(lambda x: x[0], c))


        fp_port_used = list(map(lambda x: x[1], candidates))
        host_port_used = list(map(lambda x: x[2], candidates))

        # all the ports that got left will make the distance between the hosts larger
        if focus_c2_ports:
            # when focusing on matching c2 port only, only check the c2 port that
            # couldn't be compared with other hosts
            host_port_left = []
            fp_port_left = list(filter(lambda x: x not in fp_port_used, c2_ports))
        else:
            host_port_left = list(filter(lambda x: x not in host_port_used, host.ports.keys()))
            fp_port_left = list(filter(lambda x: x not in fp_port_used, fp.ports.keys()))

        # calculate the maximum possible distance
        for _, fp_port, host_port in candidates:
            # calculation for ports that was in both
            max_dist += 1

        # calculation for ports that was only available in either one
        for data, port_left in [(fp, fp_port_left), (host, host_port_left)]:
            for port in port_left:
                total_dist += 1
                max_dist += 1

        #print("{}, candidates: {}".format(ip, candidates))
        #print(fp_port_used, fp_port_left)
        #print(host_port_used, host_port_left)
        #print("Total distance: {}/{}".format(total_dist, max_dist))

        # normalize total distance to value betweeon 0.0 - 1.0
        total_dist /= max_dist #* len(set(fp_module_map.keys()) | set(host_module_map.keys()))

        if total_dist <= dist_threshold:
            ip_distances.append((total_dist, fp))
        if test:
            # cache the distance to be able to reuse it
            ip_distance_cache["{}:{}".format(*sorted((host.ip, fp.ip)))] = (total_dist, fp)

    if len(ip_distances) == 0:
        return (host, [])

    ip_distances = sorted(ip_distances, key=lambda x: x[0])

    _, closest = ip_distances[0]
    if verbose:
        print("IP distances (distance: {}-{}, closest label: {}, label match: {})"
                .format(ip_distances[0][0],ip_distances[-1][0], closest.label_str(), closest.label_str() == host.label_str()))

        host_labels = host.label_str()
        for c in ip_distances:
            dist, fp_host = c
            print("Distance from {} ({}) to {} ({}): {}".format(host.ip, host_labels, fp_host.ip, fp_host.label_str(), dist))

    return (host, closest.labels)

# Analyze distance 
def post_match():
    pass
