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
from sklearn.metrics import classification_report, confusion_matrix, precision_score
from sklearn.ensemble import RandomForestClassifier
import multiprocessing
import functools


def report_to_latex_table(report):
    latex = ""
    metric_names = [
        "precision",
        "recall",
        "f1-score",
        "support",
    ]
    # Print header
    latex += " & " + " & ".join(metric_names) + " \\\\\n"

    summary_metric_names = [
        "weighted avg",
        "macro avg",
        "accuracy",
    ]

    summary_metrics = {}

    for summary_metric_name in summary_metric_names:
        summary_metrics[summary_metric_name] = report[summary_metric_name]

    for label in sorted(report.keys()):
        if label in summary_metric_names:
            continue
        metrics = report[label]
        latex += label
        for metric_name in metric_names:
            latex += " & " + str(metrics[metric_name])
        latex += " \\\\\n"

    latex += "accuracy & & &" + str(summary_metrics["accuracy"]) + " & \\\\\n"
    for summary_metric_name, summary_metric in summary_metrics.items():
        if summary_metric_name == "accuracy":
            continue
        latex += summary_metric_name
        for metric_name in metric_names:
            latex += " & " + str(summary_metric[metric_name])
        latex += " \\\\\n"

    return latex


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

def fingerprint(fp_out, data_in, method_names):
    data = load_data(data_in)

    print("Fingerprinting ...")

    method_fingerprints = {"method_fingerprints": {}}
    method_names = sorted(method_names)
    for method_name in method_names:
        method_func = methods.methods.get(method_name)
        if method_func:
            method_fingerprints["method_fingerprints"][method_name] = method_func.get_fingerprints(data)
            print("Saved {} fingerprints for {} method".format(len(data), method_name))
        else:
            print("Error: method {} not found".format(method_name))
            sys.exit(1)

    print("Training method model ...")
    rf = RandomForestClassifier(n_estimators=750)
    X = []
    y = []

    i = 0
    for host in data.values():
        print_progress(i, len(data))
        i += 1
        x = []
        for method_name in method_names:
            method_func = methods.methods.get(method_name)
            method_func.use_fingerprints(method_fingerprints["method_fingerprints"][method_name])
            _, labels = method_func.match(host)
            x.append(Label.to_str(labels))
        X.append(x)
        y.append(host.label_str())

    highest_lid = 0
    label_id_map = {}
    # convert labels to numbers
    for x in X:
        for i in range(len(x)):
            l = x[i]
            if l not in label_id_map:
                label_id_map[l] = highest_lid
                highest_lid += 1
            lid = label_id_map[l]
            x[i] = lid

    for i in range(len(y)):
        y[i] = label_id_map[y[i]]

    rf.fit(X, y)

    print("label_id_map", label_id_map)
    method_fingerprints["_method_model"] = rf
    method_fingerprints["_label_id_map"] = label_id_map

    joblib.dump(method_fingerprints, fp_out)


def print_hosts(data_in, method, ip=None, label=None):
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
                if label:
                    for l in host.labels:
                        if l.label == label:
                            host.print_data()
                else:
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


def split_data(data_in, data_out1, data_out2, ratio=None, exclude=None):
    # set default name if output files are not specified
    if not data_out1:
        data_out1 = data_in + ".split1"
    if not data_out2:
        data_out2 = data_in + ".split2"

    # load data to split
    data = load_data([data_in])
    label_hosts = {}
    for host in data.values():
        label = host.label_str()
        label_hosts.setdefault(label, []).append(host)

    out1 = {}
    out2 = {}
    if ratio:
        # split dataset based so it gets same ratio for each label
        for label, hosts in label_hosts.items():
            split_len = math.ceil(len(hosts) * ratio)
            for host in hosts[:split_len]:
                out2[host.ip] = host
            for host in hosts[split_len:]:
                out1[host.ip] = host
            print("Label: {:16} ({:3} hosts) - dataset-1: {:3} hosts, dataset-2: {:3} hosts, ratio: {:04f}"
                    .format(label, len(hosts), len(hosts) - split_len, split_len, split_len / len(hosts)))
    elif exclude:
        for label, hosts in label_hosts.items():
            for host in hosts:
                if exclude == label:
                    out2[host.ip] = host
                else:
                    out1[host.ip] = host
        print("({:3} hosts) - dataset-1: {:3} hosts, dataset-2: {:3} hosts".format(len(data), len(out1),  len(out2)))
    else:
        print("Error: One of '--exlude' or '--ratio' must be specified.")
        sys.exit(1)


    # save splitted dataset
    joblib.dump(out1, data_out1)
    joblib.dump(out2, data_out2)


def match2(data_in, fp_in, ip=None, force=False, binary=False, log_path=None, test=False, inception=True):
    data = load_data(data_in)
    fps = joblib.load(fp_in)

    if inception:
        method_names = list(fps["method_fingerprints"].keys())
    else:
        method_names = ["port-cluster"] # TODO: temporary hard coded list

    print("Matching ...")

    rf = fps["_method_model"]
    label_id_map = fps["_label_id_map"]
    id_label_map = {v: k for k, v in label_id_map.items()}
    id_label_list = [-1]*len(id_label_map)
    print("label_id_map", label_id_map)
    print("id_label_map", id_label_map)
    for k, v in id_label_map.items():
        id_label_list[k] = v
    print("id_label_list", id_label_list)

    y_pred = []
    y_true = []

    i = 0
    for host in data.values():
        print_progress(i, len(data))
        i += 1

        x = []
        for method_name in method_names:
            method = methods.methods.get(method_name)
            # TODO: only run use_fingerprints once for each method.
            if not method:
                print("Error: Invalid method '{}' in fingerprint file".format(method_name))
                sys.exit(1)
            method.use_fingerprints(fps["method_fingerprints"][method_name])

            _, labels = method.match(host, force=force, test=test)
            if inception:
                lstr = Label.to_str(labels)
                lid = label_id_map.get(lstr, -1)
                x.append(lid)
            else:
                # TODO: fix this!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                lstr = Label.to_str(labels)
                lid = label_id_map.get(lstr, -1)
                y_pred.append(lid)
                break

        if inception:
            y_pred.append(rf.predict([x])[0])
        else:
            pass
            #y_pred.append(lid)
        y_true.append(label_id_map.get(host.label_str(), -1))


    print("y pred:", y_pred)
    print("y true:", y_true)

    report = classification_report(y_true, y_pred, labels=list(sorted(id_label_map.keys())), target_names=id_label_list, zero_division=0, digits=5)

    print("Predicted:", y_pred)

    print(report)



def match(data_in, fp_in, ip=None, force=False, binary=False, log_path=None, test=False, latex=False):
    data = load_data(data_in)
    fps = joblib.load(fp_in)

    method_names = list(fps.keys())

    print("Matching ...")

    if log_path:
        log_file = open(log_path, "w")

    results = []

    if not ip:
        for method_name in method_names:
            if not methods.methods.get(method_name):
                print("Warning: no such method '{}'".format(method_name))
                continue
            if not fps.get(method_name):
                print("Warning: the fingerprint file does not contain a fingerprint for method '{}'".format(method_name))
                continue
            method = methods.methods[method_name]
            method.use_fingerprints(fps[method_name])
            if test:
                configs = method.get_configs()
            else:
                configs = [method.get_default_config()]

            num_matched = 0

            for conf in configs:
                method.use_config(conf)

                start = time.time()

                num_matched = 0
                y_true = []
                y_pred = []
                labels = []
                print_progress(0, len(data))
                count = 0

                if test:
                    # cannot use pool in test because diff method needs to cache results
                    # which won't work with multiprocessing
                    match_map = map(functools.partial(method.match, force=force, test=test), data.values())
                else:
                    pool = multiprocessing.Pool(1)
                    match_map = pool.imap_unordered(functools.partial(method.match, force=force, test=test), data.values())

                for host, matches in match_map:
                    count += 1
                    print_progress(count, len(data))

                    host_labels = host.label_str()
                    if (method.is_binary_classifier() or binary) and host_labels != "unlabeled":
                        host_labels = "malicious"
                    if host_labels not in labels:
                        labels.append(host_labels)

                    match_labels = Label.to_str(matches)
                    if (method.is_binary_classifier() or binary) and match_labels != "unlabeled":
                        match_labels = "malicious"
                    if match_labels not in labels:
                        labels.append(match_labels)

                    y_true.append(labels.index(host_labels))
                    y_pred.append(labels.index(match_labels))

                if not test:
                    pool.close()

                end = time.time()

                report = classification_report(y_true, y_pred, target_names=labels, zero_division=0, digits=5, output_dict=True if latex else False)
                if latex:
                    report = report_to_latex_table(report)

                perf_text = " ----- Performance result -----\n"
                perf_text += "Method: {}\n".format(method_name)
                perf_text += "Config: " + ", ".join("{} = {}".format(k, v) for k, v in conf.items()) + "\n"
                perf_text += "Classification report:\n"
                perf_text += str(report) + "\n"
                perf_text += "Confusion Matrix (x-axis: guess, y-axis: true):\n"
                perf_text += "Labels: {}\n".format(labels)
                perf_text += str(confusion_matrix(y_true, y_pred)) + "\n"
                perf_text += "Took {} seconds to perform".format(end-start)
                perf_text += "\n\n"

                precision = precision_score(y_true, y_pred, average="micro")
                results.append({"method": method_name, "config": conf, "precision": precision})

                if log_path:
                    log_file.write(perf_text)
                    log_file.flush()

                print("")
                print(perf_text)

        # if two or more methods were used, print precision ranking
        if len(results) > 1:
            result_text = " ----- Best performing method/config -----\n"
            for i, result in enumerate(sorted(results, key=lambda k: k["precision"], reverse=True)):
                result_text += "{}.\n".format(i+1)
                result_text += "Method: {}\n".format(result["method"])
                result_text += "Config: " + ", ".join("{} = {}".format(k, v) for k, v in result["config"].items()) + "\n"
                result_text += "Precision: {}\n\n".format(result["precision"])

            if log_path:
                log_file.write(result_text)

            print(result_text)

    else:
        host = data.get(ip)

        if not host:
            print("Error: No host {} exists in data file.".format(ip))
            sys.exit(1)

    if log_path:
        log_file.close()


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
    parser_print.add_argument("--label", help="Only print hosts matching the specified label.", type=str)
    # sub-command split
    parser_split = subparsers.add_parser("split", help="Split processed host data into two dataset")
    parser_split.add_argument("--data-in", help="Extracted host data.", type=str, required=True)
    parser_split.add_argument("--data-out1", help="First dataset output.", type=str, required=False)
    parser_split.add_argument("--data-out2", help="Second dataset output.", type=str, required=False)
    parser_split.add_argument("--ratio", help="The ratio of hosts in the second dataset.", type=float)
    parser_split.add_argument("--exclude", help="Exclude this label from the first dataset. The second dataset will only contain this label.", type=str)
    # sub-command fingerprint
    parser_fingerprint = subparsers.add_parser("fingerprint", help="Generate fingerprint from host data file.")
    parser_fingerprint.add_argument("--data-in", help="Host data to use for constructing fingerprints.", type=str, nargs="+", required=True)
    parser_fingerprint.add_argument("--fp-out", help="Output file for storing the fingerprints.", type=str, required=True)
    parser_fingerprint.add_argument("--method", help="Method to use for .", type=str, nargs="+", required=True, choices=methods.methods.keys())
    # sub-command match
    parser_match = subparsers.add_parser("match", help="Match a host to fingerprinted hosts.")
    parser_match.add_argument("--fp-in", help="Fingerprints to use for matching.", type=str, required=True)
    parser_match.add_argument("--data-in", help="Data file to match with.", type=str, nargs="+", required=True)
    parser_match.add_argument("--method", help="Method(s) to use for matching.", type=str, nargs="+", choices=methods.methods.keys())
    parser_match.add_argument("--force", help="Force comparison of two hosts even if they share IP address.", action="store_true", default=False)
    parser_match.add_argument("--host", help="The specific host IP in the data file to match with.", type=str)
    parser_match.add_argument("--binary", help="Perform binary (benign/malicious) classification .", action="store_true", default=False)
    parser_match.add_argument("--log", help="The path to log the performance results.", type=str)
    parser_match.add_argument("--test", help="Test performance of the specified methods using different configs.", action="store_true", default=False)
    parser_match.add_argument("--latex", help="We are lazy.", action="store_true", default=False)

    args = parser.parse_args()

    if args.subcommand == "extract":
        database_extract(args.data_out, args.db_in, args.labels_in, args.pcap_in, args.keep)
    elif args.subcommand == "print":
        print_hosts(args.data_in, args.method, args.host, args.label)
    elif args.subcommand == "split":
            split_data(args.data_in, args.data_out1, args.data_out2, ratio=args.ratio, exclude=args.exclude)
    elif args.subcommand == "fingerprint":
        fingerprint(args.fp_out, args.data_in, args.method)
    elif args.subcommand == "match":
        #match(args.data_in, args.fp_in, args.method, ip=args.host, force=args.force,
        #      binary=args.binary, log_path=args.log, test=args.test, latex=args.latex)
        #TODO: fix match instead of using match2
        match2(args.data_in, args.fp_in, ip=args.host, force=args.force,
              binary=args.binary, log_path=args.log, test=args.test)
>>>>>>> 5ef1469 (Inception)
