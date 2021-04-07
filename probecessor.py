import sys
import sqlite3
import modules
import pprint
import json
import argparse
import methods
import re
from util.label import get_label_names
from util.progress import print_progress
from scapy.all import PcapReader, tcpdump
import modules.host
from modules.label import Label
import joblib
import math
import time
from sklearn.metrics import classification_report, confusion_matrix
import multiprocessing
import functools

def pcap_extract(pcap_path, hosts):
    with PcapReader(tcpdump(pcap_path, args=["-w", "-", "-n", "tcp"], getfd=True)) as pcreader:
        for p in pcreader:
            # we are only interested in syn-ack packet
            if not "TCP" in p:
                print("NOT TCP :OOOOO")
                continue
            if p["TCP"].flags != "SA":
                continue

            ip = p["IP"].src
            if not ip in hosts:
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

            if not hosts[ip].tcp:
                hosts[ip].tcp = {}

            tcp = hosts[ip].tcp

            tcp["ttl"] = max(tcp.get("ttl", 0), ttl)
            tcp["mss"] = max(tcp.get("mss", 0), mss)
            tcp["win"] = max(tcp.get("win", 0), p["TCP"].window)


def database_extract(output, database, label_path, pcap_path, keep):
    host_map = {}
    tls_map = {}

    for db_file in database:
        print("Extracting data from {} ...".format(db_file))
        try:
            open(db_file, "r")
            dbh = sqlite3.connect(db_file)
        except:
            print("error: Failed opening database '{}'.".format(db_file))
            sys.exit(1)

        dbh.row_factory = sqlite3.Row

        curse = dbh.cursor()
        curse.execute("SELECT COUNT(*) FROM Probe;")
        total_rows = curse.fetchone()[0]

        curse.execute("SELECT * FROM Probe;")

        processed_rows = 0

        while True:
            row = curse.fetchone()
            print_progress(processed_rows, total_rows)
            processed_rows += 1

            if not row:
                break

            ip = row["ip"]
            uuid = row["uuid"]

            if not host_map.get(ip):
                host_map[ip] = modules.host.Host(ip, uuid)

            if keep != "both" and host_map[ip].uuid != uuid:
                if keep == "old":
                    # don't use the probe data that comes from newer scan
                    continue
                elif keep == "new":
                    # keep the newer scan , trash the older probe data
                    host_map[ip] = modules.host.Host(ip, uuid)
                    if ip in tls_map:
                        del tls_map[ip]

            module_name = row["name"]
            port = row["port"]

            if port == 0:
                mod_obj = modules.get_module(module_name)
                if not mod_obj:
                    continue
                # ip module stuff
                mod_obj.add_data(row)

                if mod_obj.name == "geoip":
                    host_map[ip].geoip = mod_obj
                elif mod_obj.name == "rdns":
                    host_map[ip].rdns = mod_obj
            else:
                # module stuff
                if module_name == "tls":
                    if ip not in tls_map:
                        tls_map[ip] = {}
                    port_obj = tls_map[ip].get(port)
                    if not port_obj:
                        port_obj = modules.get_port("tls")
                        tls_map[ip][port] = port_obj
                else:
                    port_obj = host_map[ip].ports.get(port)
                    if not port_obj:
                        port_obj = modules.get_port(module_name, port)
                        host_map[ip].insert_port(port_obj)

                try:
                    port_obj.add_data(row)
                except Exception as e:
                    print("Error adding data for {}:{}".format(ip, port))
                    import traceback
                    traceback.print_exc()
                    sys.exit(1)

        curse.close()
        print("")

    # adding tls module to ports
    for ip, port_map in tls_map.items():
        for port, tls in port_map.items():
            port_obj = host_map[ip].ports.get(port)
            if not port_obj:
                port_obj = modules.get_port("generic", port)
                host_map[ip].insert_port(port_obj)
            port_obj.tls = tls

    # remove ip that doesn't have any ports open, or none gives any response
    print("Filtering hosts without any ports open")

    remove_ip = set()
    for ip in host_map:
        if len(host_map[ip].ports) == 0:
            # TODO: add a flag that decides whether to exclude this or not
            #print("{}: No ports open, omitting".format(ip))
            remove_ip.add(ip)
            continue

        """if len(host_map[ip].responsive_ports()) == 0:
            # TODO: add a flag that decides whether to exclude this or not
            print("{}: No ports responded, omitting".format(ip))
            remove_ip.append(ip)
            continue"""

    for ip in remove_ip:
        del host_map[ip]
    print("Filtered {} hosts".format(len(remove_ip)))

    # add labels to hosts
    if label_path:
        print("Adding labels to hosts")
        with open(label_path, "r") as f:
            line = f.readline()
            while line != "":
                csv = line.strip().split(",")
                line = f.readline()

                if len(csv) != 4:
                    continue

                mwdb_id, ip, port, family = csv
                if ip in host_map:
                    try:
                        port = int(port)
                    except:
                        # some c2 doesn't have port specified in label
                        port = None
                        pass

                    host_map[ip].add_label(mwdb_id, family, port)

        # remove labels where label port is not open
        # and remove the ip if it loses all label, since it means the relevant (C2 acting) port is closed
        print("Filtering hosts without any label ports open")

        remove_ip = set()
        for ip in host_map:
            if host_map[ip].filter_labels():
                remove_ip.add(ip)

        for ip in remove_ip:
            del host_map[ip]
        print("Filtered {} hosts".format(len(remove_ip)))

    if pcap_path:
        print("Adding pcap data...")
        pcap_extract(pcap_path, host_map)


    # TODO: serialize host object

    print("{} hosts processed".format(len(host_map)))
    print("Saving data to file {} ...".format(output))

    joblib.dump(host_map, output)

    dbh.close()

def fingerprint(fp_out, data_in, method):
    data = load_data(data_in)

    method_func = methods.methods.get(method)
    if method_func:
        method_func.store_fingerprints(fp_out, data)
    else:
        print("Error: method {} not found".format(method))
        sys.exit(1)


def print_hosts(data_in, method, ip=None):
    hosts = load_data(data_in)

    # TODO: Support using ip parameter with JARM print.

    if method == "data":
        if ip:
            host = hosts.get(ip)
            if not host:
                print("Error: No host {} exists in data file.".format(ip))
                sys.exit(1)

            host.print_data()
        else:
            for host in hosts.values():
                host.print_data()

    elif method == "jarm":
        # count jarm occurence
        jarm_map = {}
        # count jarm occurence of each label
        label_map = {}
        for host in hosts.values():
            for tls_port in [port for port in host.ports.values() if port.tls]:
                tls = tls_port.tls
                jarm = tls.get_property("jarm")

                # count jarm occurence
                if jarm not in jarm_map:
                    jarm_map[jarm] = 1
                else:
                    jarm_map[jarm] += 1

                # count jarm occurence in each label
                labels = set(map(lambda l: l.label + (" (no port)" if not l.port else ""), host.get_port_label(tls_port.port)))
                if len(labels) == 0:
                    labels = set(["unlabeled"])
                for label in labels:
                    if label not in label_map:
                        label_map[label] = {}
                    if jarm not in label_map[label]:
                        label_map[label][jarm] = 1
                    else:
                        label_map[label][jarm] += 1

        # print stats
        print("JARM occurences")
        for jarm, count in sorted(jarm_map.items(), key=lambda item: item[1], reverse=True):
            labels = []
            for label in label_map:
                if jarm in label_map[label]:
                    labels.append(label)
            print("{}: {} ({})".format(jarm, count, '/'.join(labels)))

        for label in label_map:
            print("JARM occurences in {}:".format(label))
            for jarm, count in sorted(label_map[label].items(), key=lambda item: item[1], reverse=True):
                print("  {}: {}".format(jarm, count))


def split_data(data_in, data_out1, data_out2, ratio):
    # set default name if output files are not specified
    if not data_out1:
        data_out1 = data_in + ".split1"
    if not data_out2:
        data_out2 = data_in + ".split2"

    # load data to split
    data = load_data([data_in])

    # categorize each host from label
    label_hosts = {}
    for host in data.values():
        label = host.label_str()
        if label not in label_hosts:
            label_hosts[label] = []
        label_hosts[label].append(host)

    # split dataset based so it gets same ratio for each label
    out1 = {}
    out2 = {}
    for label, hosts in label_hosts.items():
        split_len = math.ceil(len(hosts) * ratio)
        for host in hosts[:split_len]:
            out2[host.ip] = host
        for host in hosts[split_len:]:
            out1[host.ip] = host
        print("Label: {:16} ({:3} hosts) - dataset-1: {:3} hosts, dataset-2: {:3} hosts, ratio: {:04f}"
        		.format(label, len(hosts), len(hosts) - split_len, split_len, split_len / len(hosts)))

	# save splitted dataset
    joblib.dump(out1, data_out1)
    joblib.dump(out2, data_out2)


def match(data_in, fp_in, method, ip=None, force=False):
    start = time.time()

    data = load_data(data_in)
    method = methods.methods[method]
    method.load_fingerprints(fp_in)
    num_matched = 0

    if not ip:
        num_matched = 0
        y_true = []
        y_pred = []
        labels = []
        pool = multiprocessing.Pool(2)
        print_progress(0, len(data))
        count = 0
        for host, matches in pool.imap(functools.partial(method.match, force=force), data.values()):
            count += 1
            print_progress(count, len(data))
            #matches = method.match(host, force)

            host_labels = host.label_str()
            if host_labels not in labels:
                labels.append(host_labels)

            match_labels = Label.to_str(matches)
            if match_labels not in labels:
                labels.append(match_labels)

            y_true.append(labels.index(host_labels))
            y_pred.append(labels.index(match_labels))

        print("")
        print(classification_report(y_true, y_pred, target_names=labels, zero_division=0, digits=4))
        print("Confusion Matrix")
        print("Labels:", labels)
        print(confusion_matrix(y_true, y_pred))

    else:
        host = data.get(ip)

        if not host:
            print("Error: No host {} exists in data file.".format(ip))
            sys.exit(1)

    end = time.time()
    print("Match function took {} seconds to complete".format(end-start))

def load_data(data_path):
    data = {}
    for path in data_path:
        print("Loading data from {} ...".format(path))
        data.update(joblib.load(path))
    return data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeably data probecessor.")
    subparsers = parser.add_subparsers(help="Probecessor command to run.", dest="subcommand")
    # sub-command extract
    parser_extract = subparsers.add_parser("extract", help="Extract data from database file.")
    parser_extract.add_argument("--labels-in", help="Additional CSV file with host label data containing: id,ip,port,label", type=str)
    parser_extract.add_argument("--pcap-in", help="Additional pcap file.", type=str)
    parser_extract.add_argument("--db-in", help="A probeably database file.", type=str, nargs="+", required=True)
    parser_extract.add_argument("--data-out", help="Output file holding the processed host data.", type=str, required=True)
    parser_extract.add_argument("--keep", help="Which host data to keep when it finds probe data from newer scan session.", default="both", type=str, choices=["old", "new", "both"])
    # sub-command print
    parser_print = subparsers.add_parser("print", help="Print data in the processed host data.")
    parser_print.add_argument("--data-in", help="Extracted Host data.", type=str, nargs="+", required=True)
    parser_print.add_argument("--method", help="Information to print.", type=str, default="data", choices=["data", "jarm"])
    parser_print.add_argument("--host", help="The optional host to print from the data file.", type=str)
    # sub-command split
    parser_split = subparsers.add_parser("split", help="Split processed host data into two dataset")
    parser_split.add_argument("--data-in", help="Extracted host data.", type=str, required=True)
    parser_split.add_argument("--data-out1", help="First dataset output.", type=str, required=False)
    parser_split.add_argument("--data-out2", help="Second dataset output.", type=str, required=False)
    parser_split.add_argument("--ratio", help="The ratio of hosts in the second dataset.", type=float, default=0.5)
    # sub-command fingerprint
    parser_fingerprint = subparsers.add_parser("fingerprint", help="Generate fingerprint from host data file.")
    parser_fingerprint.add_argument("--data-in", help="Host data to use for constructing fingerprints.", type=str, nargs="+", required=True)
    parser_fingerprint.add_argument("--fp-out", help="Output file for storing the fingerprints.", type=str, required=True)
    parser_fingerprint.add_argument("--method", help="Method to use for .", type=str, default="cluster", choices=["cluster"])
    # sub-command match
    parser_match = subparsers.add_parser("match", help="Match a host to fingerprinted hosts.")
    parser_match.add_argument("--fp-in", help="Fingerprints to use for matching.", type=str, required=True)
    parser_match.add_argument("--data-in", help="Data file to match with.", type=str, nargs="+", required=True)
    parser_match.add_argument("--method", help="Method to use for matching.", type=str, default="cluster", choices=methods.methods.keys())
    parser_match.add_argument("--force", help="Force comparison of two hosts even if they share IP address.", action="store_true", default=False)
    parser_match.add_argument("--host", help="The specific host IP in the data file to match with.", type=str)

    args = parser.parse_args()

    if args.subcommand == "extract":
        database_extract(args.data_out, args.db_in, args.labels_in, args.pcap_in, args.keep)
    elif args.subcommand == "print":
        print_hosts(args.data_in, args.method, args.host)
    elif args.subcommand == "split":
        split_data(args.data_in, args.data_out1, args.data_out2, args.ratio)
    elif args.subcommand == "fingerprint":
        fingerprint(args.fp_out, args.data_in, args.method)
    elif args.subcommand == "match":
        match(args.data_in, args.fp_in, args.method, ip=args.host, force=args.force)
