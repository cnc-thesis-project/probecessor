import sys
import sqlite3
import modules
import pprint
import json
import tlsh
import argparse
import fingerprint

def database_extract(output, database):
    print("Extract")
    data = {}
    for db_file in database:
        try:
            open(db_file, "r")
            dbh = sqlite3.connect(db_file)
        except:
            print("error: Failed opening database '{}'.".format(sys.argv[1]))
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
                port = probe["port"]

                if not port in probe_map:
                    probe_map[port] = {}
                if not name in probe_map[port]:
                    probe_map[port][name] = []
                probe_map[port][name].append(dict(probe))

            c2.close()

            for port in probe_map:
                if not data.get(ip):
                    data[ip] = {}

                if port == 0:
                    # ip module stuff
                    # TODO: use ip module processor?
                    for m in probe_map[port]:
                        if m == "geoip":
                            country, asn, as_desc = probe_map[port][m][0]["data"].decode().split("\t")
                            data[ip][m] = {"country": country, "asn": int(asn), "as_desc": as_desc}
                        else:
                            data[ip][m] = probe_map[port][m][0]["data"].decode()
                    continue
                # TODO: handle name: port, unknown
                for m in probe_map[port]:
                    # module stuff
                    mod = modules.modules.get(m)
                    if not mod:
                        continue

                    data[ip][port] = mod.run(probe_map[port][m])

        c1.close()

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
    parser_extract.add_argument("output", help="Processed output file.", type=str)
    parser_extract.add_argument("database", help="A probeably database file.", type=str, nargs="+")
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

