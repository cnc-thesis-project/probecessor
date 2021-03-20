import sys
import sqlite3
import modules
import pprint
import json
import argparse
import methods
import re
from util.label import get_label_names
from scapy.all import PcapReader
import modules.host
import joblib


def populate_statistics(host):
    ip_data["stats"] = {}
    # nr of no response at all from server port
    ip_data["stats"]["no_response"] = 0
    # nr of (un)identifiable port service
    # note: port with no response is not counted in unknown
    ip_data["stats"]["known"] = 0
    ip_data["stats"]["unknown"] = 0
    # nr of open ports
    ip_data["stats"]["open_ports"] = len(ip_data["port"])
    # nr of ports with tls
    ip_data["stats"]["tls"] = 0
    # TODO: uses the expected port for the service
    expected_port = 0

    for port in ip_data["port"]:
        if "unknown" in ip_data["port"][port] and len(ip_data["port"][port]["unknown"]["response"]) == 0:
            ip_data["stats"]["no_response"] += 1
        elif ip_data["port"][port]["name"] == "unknown":
            ip_data["stats"]["unknown"] += 1
        else:
            ip_data["stats"]["known"] += 1

        if ip_data["port"][port].get("tls", False):
            ip_data["stats"]["tls"] += 1

def pcap_extract(pcap_path, data):
    # TODO: Examine if this is solved well
    return
    for p in PcapReader(pcap_path):
        # we are only interested in syn-ack packet
        if not "TCP" in p:
            continue
        if p["TCP"].flags != "SA":
            continue

        ip = p["IP"].src
        if not ip in data:
            continue

        ttl = p.ttl
        # round up ttl to closest one in the list
        for t in [32, 64, 128, 255]:
            if ttl <= t:
                ttl = t
                break

        mss = 0
        for o in p["TCP"].options:
            if o[0] == "MSS":
                mss = o[1]
                break

        data_pcap = {}
        data_pcap["ttl"] = max(data_pcap.get("ttl", 0), ttl)
        data_pcap["mss"] = max(data_pcap.get("mss", 0), mss)
        data_pcap["win"] = max(data_pcap.get("win", 0), p["TCP"].window)


def database_extract(output, database, label_path, pcap_path):
    print("Extract")
    data = {}

    for db_file in database:
        try:
            open(db_file, "r")
            dbh = sqlite3.connect(db_file)
        except:
            print("error: Failed opening database '{}'.".format(db_file))
            sys.exit(1)

        dbh.row_factory = sqlite3.Row

        c1 = dbh.cursor()

        c1.execute("SELECT DISTINCT ip FROM Probe;")
        while True:
            ip_row = c1.fetchone()
            if not ip_row:
                break

            ip = ip_row["ip"]

            c2 = dbh.cursor()
            c2.execute("SELECT * FROM Probe WHERE ip = ?;", (ip,))

            probe_map = {}
            while True:
                probe = c2.fetchone()
                if not probe:
                    break

                name = probe["name"]
                port = str(probe["port"]) # store as string since json cannot have integer key anyways

                if not port in probe_map:
                    probe_map[port] = {}
                if not name in probe_map[port]:
                    probe_map[port][name] = []
                probe_map[port][name].append(dict(probe))

            c2.close()

            for port in probe_map:
                if not data.get(ip):
                    data[ip] = modules.host.Host(ip)

                if port == "0":
                    # ip module stuff
                    # TODO: use ip module processor? (Yes /b)
                    # TODO: remove continue
                    continue
                    for m in probe_map[port]:
                        if m == "geoip":
                            country, asn, as_desc = probe_map[port][m][0]["data"].decode().split("\t")
                            data[ip][m] = {"country": country, "asn": int(asn), "as_desc": as_desc}
                        else:
                            data[ip][m] = probe_map[port][m][0]["data"].decode()
                else:
                    for m in probe_map[port]:
                        # module stuff
                        port_class = modules.modules.get(m)
                        if not port_class:
                            continue
                        if m == "tls":
                            continue
                        else:
                            port_obj = port_class(port)

                        port_obj.populate(probe_map[port][m])
                        data[ip].insert_port(port_obj)

        c1.close()

    remove_ip = []
    for ip in data:
        pprint.pprint(data[ip].ports)
        if len(data[ip].ports) == 0:
            # TODO: add a flag that decides whether to exclude this or not
            print("{}: No ports open, omitting".format(ip))
            remove_ip.append(ip)
            continue
        """
        if sum(map(len, data[ip].ports)) == 0:
            # TODO: add a flag that decides whether to exclude this or not
            print("{}: No ports responded, omitting".format(ip))
            remove_ip.append(ip)
            continue
        """

        # TODO:
        # data[ip].get_statistics()
        #populate_statistics(data[ip])

    for ip in remove_ip:
        del data[ip]

    if label_path:
        print("Adding labels...")
        with open(label_path, "r") as f:
            line = f.readline()
            while line != "":
                csv = line.strip().split(",")
                if len(csv) != 4:
                    continue

                mwdb_id, ip, port, label = csv
                if ip in data:
                    # TODO: add the rest of the label data
                    data[ip].add_label(label)

                line = f.readline()

    if pcap_path:
        print("Adding pcap data...")
        pcap_extract(pcap_path, data)


    # TODO: serialize host object

    joblib.dump(data, output)

    dbh.close()

def stringify_dict_keys(d, prefix="", separator="/", start_regex=re.compile("")):
    keys = set()

    for k in d:
        new_prefix = prefix + separator + k
        if isinstance(d[k], dict):
            keys.update(stringify_dict_keys(d[k], new_prefix, separator, start_regex))
        else:
            match = start_regex.match(new_prefix)
            if match is None:
                continue
            keys.add(new_prefix[match.span()[1]:])

    return keys

def print_statistics(input, detail):
    with open(input, "r") as f:
        data = json.load(f)

    # things to print: average port stats, % of hosts having "..." module, rdns, key stat
    ip_len = len(data)
    print("Hosts: {}".format(ip_len))
    for key in data[list(data.keys())[0]]["stats"]:
        value_sum = sum(map(lambda ip: data[ip]["stats"][key], data))
        print("{}: {}, average per host: {}".format(key, value_sum, (value_sum/ip_len)))

    port_stat = [{"port": i, "count": 0} for i in range(65536)]
    for ip in data:
        for port in data[ip]["port"]:
            port_stat[int(port)]["count"] += 1

    print("\nPort statistics - Top ~20")
    port_stat = sorted(port_stat, key=lambda k: k["count"], reverse=True)
    for p in port_stat[:20]:
        if p["count"] == 0:
            break

        print("Port {}: {} hosts".format(p["port"], p["count"]))

    if detail == "none":
        return

    module_keys = stringify_dict_keys(data, start_regex=re.compile("^/[0-9.]*/port/[0-9]*/"))
    data_stats = {}
    for keys in module_keys:
        data_stats[keys] = {"ports": 0, "hosts": 0, "value": {}}
        for ip in data:
            key_hosts = set()
            value_hosts = set()
            for port in data[ip]["port"]:
                # aggregate key
                d = data[ip]["port"][port]
                for k in keys.split("/"):
                    d = d.get(k)
                    if not d:
                        break
                if not d:
                    continue
                data_stats[keys]["ports"] += 1
                if not keys in key_hosts:
                    key_hosts.add(keys)
                    data_stats[keys]["hosts"] += 1

                if detail != "values":
                    continue
                # aggregate values
                values = [d]
                if isinstance(d, list):
                    values = d
                for value in values:
                    if not value in data_stats[keys]["value"]:
                        data_stats[keys]["value"][value] = {"ports": 0, "hosts": 0}
                    data_stats[keys]["value"][value]["ports"] += 1
                    if not (keys + "/" + str(value)) in value_hosts:
                        value_hosts.add(keys + "/" + str(value))
                        data_stats[keys]["value"][value]["hosts"] += 1

    for key in data_stats:
        key_stats = data_stats[key]
        print("Key: {}".format(key))
        print(" - Ports: {}, Hosts: {}".format(key_stats["ports"], key_stats["hosts"]))

        if detail != "values":
            continue
        for value in key_stats["value"]:
            value_stats = key_stats["value"][value]
            print("    - Value: {}".format(value))
            print("       - Ports: {}, Hosts: {}".format(value_stats["ports"], value_stats["hosts"]))

    return


def fingerprint(fp_out, data_in, method):
    data = joblib.load(data_in)

    method = methods.methods.get(method)
    if method:
        method.store_fingerprints(fp_out, data)


def match(data_in, fp_in, method):
    data = joblib.load(data_in)
    method = methods.methods[method]
    method.load_fingerprints(fp_in)
    for ip, host in data.items():
        #labels = get_label_names(host_data)
        print("Attempting to match host {} against fingerprinted hosts".format(ip))
        method.match(host)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeably data probecessor.")
    subparsers = parser.add_subparsers(help="Probecessor command to run.", dest="subcommand")
    # sub-command extract
    parser_extract = subparsers.add_parser("extract", help="Extract data from database file.")
    parser_extract.add_argument("--labels-in", help="Additional CSV file with host label data containing: id,ip,port,label", type=str)
    parser_extract.add_argument("--pcap-in", help="Additional pcap file.", type=str)
    parser_extract.add_argument("--db-in", help="A probeably database file.", type=str, nargs="+", required=True)
    parser_extract.add_argument("--data-out", help="Output file holding the processed host data.", type=str, required=True)
    # sub-command fingerprint
    parser_fingerprint = subparsers.add_parser("fingerprint", help="Generate fingerprint from host data file.")
    parser_fingerprint.add_argument("--data-in", help="Host data to use for constructing fingerprints.", type=str, required=True)
    parser_fingerprint.add_argument("--fp-out", help="Output file for storing the fingerprints.", type=str, required=True)
    parser_fingerprint.add_argument("--method", help="Method to use for .", type=str, default="learn", choices=["learn"])
    # sub-command stats
    parser_stats = subparsers.add_parser("stats", help="Print statistics from host data.")
    parser_stats.add_argument("--data-in", help="Data file to print statistics from.", type=str, required=True)
    parser_stats.add_argument("--detail", help="Aggregate keys.", choices=["none", "keys", "values"], default="none")
    # sub-command match
    parser_match = subparsers.add_parser("match", help="Match a host to fingerprinted hosts.")
    parser_match.add_argument("--fp-in", help="Fingerprints to use for matching.", type=str, required=True)
    parser_match.add_argument("--data-in", help="Data file to match with.", type=str, required=True)
    parser_match.add_argument("--method", help="Method to use for matching.", type=str, default="learn", choices=methods.methods.keys())

    args = parser.parse_args()

    if args.subcommand == "extract":
        database_extract(args.data_out, args.db_in, args.labels_in, args.pcap_in)
    elif args.subcommand == "stats":
        print_statistics(args.data_in, args.detail)
    elif args.subcommand == "fingerprint":
        fingerprint(args.fp_out, args.data_in, args.method)
    elif args.subcommand == "match":
        match(args.data_in, args.fp_in, args.method)
