import sys
import sqlite3
import modules
import pprint
import json
import tlsh
import argparse
import fingerprint

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
        if len(ip_data["port"][port]) == 0:
            ip_data["stats"]["no_response"] += 1
        elif ip_data["port"][port]["name"] == "unknown":
            ip_data["stats"]["unknown"] += 1
        else:
            ip_data["stats"]["known"] += 1

        if ip_data["port"][port].get("tls", False):
            ip_data["stats"]["tls"] += 1

    print(ip_data["stats"])

def database_extract(output, database):
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
                    data[ip]["port"][port] = {}
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
                    else:
                        data[ip]["port"][port]["name"] = data[ip]["port"][port].get("name", "unknown")

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
        print(ip)
        populate_statistics(data[ip])

    for ip in remove_ip:
        del data[ip]

    with open(output, "w") as f:
        json.dump(data, f)

    #pprint.pprint(data)

    """fingerprints = {}
    for ip in data.keys():
        if not fingerprints.get(ip):
            fingerprints[ip] = {}
        for port in data[ip].keys():
            if args.method == "tlsh":
                fingerprints[ip][port] = fingerprint.tlsh.fp(data[ip][port])
            else:
                fingerprints[ip][port] = fingerprint.minhash.fp(data[ip][port])"""

    dbh.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeably data probecessor.")
    parser.add_argument("--method", help="The fingerprinting method to use.", choices=["tlsh", "minhash"], default="tlsh")
    subparsers = parser.add_subparsers(help='sub-command help', dest="subcommand")
    # sub-command extract
    parser_extract = subparsers.add_parser("extract", help="Extract data from database file.")
    parser_extract.add_argument("database", help="A probeably database file.", type=str, nargs="+")
    parser_extract.add_argument("output", help="Processed output file.", type=str)
    # sub-command fingerprint
    parser_fingerprint = subparsers.add_parser("fingerprint", help="Generate fingerprint from processed file.")
    parser_fingerprint.add_argument("input", help="Processed output file.", type=str, nargs="+")
    # sub-command classify
    # TODO: WIP
    parser_fingerprint = subparsers.add_parser("classify", help="Classify a host.")
    parser_fingerprint.add_argument("input", help="Processed output file.", type=str, nargs="+")

    args = parser.parse_args()

    if args.subcommand == "extract":
        database_extract(args.output, args.database)
    elif args.subcommand == "fingerprint":
        # TODO: this code is no longer relevant, nuke it
        data = {}
        for db_file in args.database:
            try:
                open(db_file, "r")
                dbh = sqlite3.connect(db_file)
            except:
                print("error: Failed opening database '{}'.".format(sys.argv[1]))
                sys.exit(1)

            dbh.row_factory = sqlite3.Row

            c1 = dbh.cursor()

            c1.execute("SELECT DISTINCT ip, port FROM Probe;")

            while(True):
                ip_row = c1.fetchone()
                if not ip_row:
                    break
                ip = ip_row[0]
                port = ip_row[1]

                for m in modules.modules.keys():
                    c2 = dbh.cursor()
                    c2.execute("SELECT * FROM Probe WHERE ip = ? AND port = ? AND name = ?", (ip,port,m,))
                    rows = c2.fetchall()

                    if not rows or len(rows) == 0:
                        continue

                    mod = modules.modules.get(m)
                    if not mod:
                        continue

                    mod_data = mod.run(rows)

                    if not data.get(ip):
                        data[ip] = {}

                    data[ip][port] = mod_data


        fingerprints = {}
        for ip in data.keys():
            if not fingerprints.get(ip):
                fingerprints[ip] = {}
            for port in data[ip].keys():
                if args.method == "tlsh":
                    fingerprints[ip][port] = fingerprint.tlsh.fp(data[ip][port])
                else:
                    fingerprints[ip][port] = fingerprint.minhash.fp(data[ip][port])

        dbh.close()

        print("+ Fingerprints for host {}".format(ip))
        pprint.pprint(fingerprints)

