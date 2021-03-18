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

def populate_statistics(ip_data):
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
    for p in PcapReader(pcap_path):
        # we are only interested in syn-ack packet
        if not "TCP" in p:
            continue
        if p["TCP"].flags != "SA":
            continue

        ip = p["IP"].src
        if not ip in data:
            continue

        if not "pcap" in data[ip]:
            data[ip]["pcap"] = {}
        data_pcap = data[ip]["pcap"]

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
                    data[ip] = {"port": {}}

                if port == "0":
                    # ip module stuff
                    # TODO: use ip module processor?
                    for m in probe_map[port]:
                        if m == "geoip":
                            country, asn, as_desc = probe_map[port][m][0]["data"].decode().split("\t")
                            data[ip][m] = {"country": country, "asn": int(asn), "as_desc": as_desc}
                        else:
                            data[ip][m] = probe_map[port][m][0]["data"].decode()
                    continue

                # TODO: handle name: port
                if port not in data[ip]["port"]:
                    data[ip]["port"][port] = {"name": "unknown"}
                for m in probe_map[port]:
                    # module stuff
                    mod = modules.modules.get(m)
                    if not mod:
                        continue

                    mod_data = mod.run(probe_map[port][m])
                    data[ip]["port"][port][m] = mod_data
                    # TODO: fix so it doesn't need this shitty check, all modules should be treated equally!!!
                    if m != "tls":
                        data[ip]["port"][port]["name"] = m
                if data[ip]["port"][port]["name"] == "unknown" and not "unknown" in data[ip]["port"][port]:
                    data[ip]["port"][port]["unknown"] = {"response": ""}

        c1.close()

    remove_ip = []
    for ip in data:
        if len(data[ip]["port"]) == 0:
            # TODO: add a flag that decides whether to exclude this or not
            print("{}: No ports open, omitting".format(ip))
            remove_ip.append(ip)
            continue
        if sum(map(len, data[ip]["port"].values())) == 0:
            # TODO: add a flag that decides whether to exclude this or not
            print("{}: No ports responded, omitting".format(ip))
            remove_ip.append(ip)
            continue
        populate_statistics(data[ip])

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
                    label_data = {"type": label, "port": port, "id": mwdb_id, "port_avail": str(port) in data[ip]["port"]}
                    if not "label" in data[ip]:
                        data[ip]["label"] = []
                    data[ip]["label"].append(label_data)

                line = f.readline()

    if pcap_path:
        print("Adding pcap data...")
        pcap_extract(pcap_path, data)

    with open(output, "w") as f:
        json.dump(data, f)

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeably data probecessor.")
    subparsers = parser.add_subparsers(help='sub-command help', dest="subcommand")
    # sub-command extract
    parser_extract = subparsers.add_parser("extract", help="Extract data from database file.")
    parser_extract.add_argument("--label", help="CSV file containing: id,ip,port,label", type=str)
    parser_extract.add_argument("--pcap", help="Masscan pcap file.", type=str)
    parser_extract.add_argument("database", help="A probeably database file.", type=str, nargs="+")
    parser_extract.add_argument("output", help="Processed output file.", type=str)
    # sub-command fingerprint
    parser_fingerprint = subparsers.add_parser("fingerprint", help="Generate fingerprint from processed file.")
    parser_fingerprint.add_argument("input", help="Processed output file.", type=str)
    parser_fingerprint.add_argument("output", help="Output file for storing the fingerprints.", type=str)
    parser_fingerprint.add_argument("--method", help="Method to use.", type=str, default="learn", choices=["learn"])
    # sub-command stats
    parser_stats = subparsers.add_parser("stats", help="Print statistics from extracted data.")
    parser_stats.add_argument("input", help="Processed output file.", type=str)
    parser_stats.add_argument("--detail", help="Aggregate keys.", choices=["none", "keys", "values"], default="none")
    # sub-command match
    # TODO: WIP
    parser_match = subparsers.add_parser("match", help="Match a host.")
    parser_match.add_argument("fingerprints", help="Fingerprints to use for matching.", type=str)
    parser_match.add_argument("--method", help="Method to use.", type=str, default="learn", choices=methods.methods.keys())
    parser_match.add_argument("input", help="Processed output file.", type=str)

    args = parser.parse_args()

    if args.subcommand == "extract":
        database_extract(args.output, args.database, args.label, args.pcap)
    elif args.subcommand == "stats":
        print_statistics(args.input, args.detail)
    elif args.subcommand == "fingerprint":
        data = {}
        with open(args.input, "r") as f:
            data = json.load(f)

        method = methods.methods[args.method]
        method.store_fingerprints(args.output, data)
    elif args.subcommand == "match":
        data = {}
        with open(args.input) as f:
            data = json.load(f)
        method = methods.methods[args.method]
        method.load_fingerprints(args.fingerprints)
        for ip, host_data in data.items():
            labels = get_label_names(host_data)
            print("Attempting to match host {} ({}) against fingerprinted hosts".format(ip, labels))
            method.match(host_data)
