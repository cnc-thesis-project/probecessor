from modules.http import HttpPort
from methods.cluster.http import get_data
from pprint import pprint
import joblib


fp_hosts = {}


def store_fingerprints(out_path, data):
    fp_hosts = {}
    for host in data.values():
        label_map = {}
        for label in host.labels:
            label_map[label.port] = label

        for port in host.ports.values():
            if not isinstance(port, HttpPort):
                continue
            label = label_map.get(port.port)
            if label:
                fp_host = {"ip": host.ip, "labels": host.labels, "port": port.port}
                fp_host["c2_http_data"] = get_data(port)
                fp_hosts[host.ip] = fp_host
                break
    print("HTTP host fingerprints:")
    pprint(fp_hosts)
    joblib.dump(fp_hosts, out_path)


def load_fingerprints(fp_path):
    global fp_hosts
    fp_hosts = joblib.load(fp_path)


def match(host, force=False):
    for port in host.ports.values():
        if not isinstance(port, HttpPort):
            continue

        http_data = get_data(port)
        for fp_host in fp_hosts.values():
            if fp_host["ip"] == host.ip and not force:
                print("REFUSING TO MATCH HOST WITH ITSELF. USE --force.")
                break
            #print("MATCHING {} and {}".format(fp_host["c2_http_data"]["vector"], http_data["vector"]))
            if fp_host["c2_http_data"]["vector"] == http_data["vector"]:
                print("{}:{}: Found matching host/port: {}:{}".format(host.ip, port.port, fp_host["ip"], fp_host["port"]))
                print(http_data["vector"])
                return (host, fp_host["labels"])

    return (host, [])
