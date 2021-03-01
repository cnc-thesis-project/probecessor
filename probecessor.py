import sys
import sqlite3
import modules
import pprint
import tlsh
import argparse
import fingerprint


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeably data probecessor.")
    parser.add_argument("--method", help="The fingerprinting method to use.", choices=["tlsh", "minhash"], default="tlsh")
    parser.add_argument("database", help="A probeably database file.", type=str, nargs="+")

    args = parser.parse_args()

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

            c2 = dbh.cursor()
            c2.execute("SELECT data FROM Probe WHERE name = 'port' AND type = 'open' AND ip = ? AND port = ?", (ip, port))
            rows = c2.fetchall()
            if len(rows) < 1 or rows is None:
                continue
            row = rows[0]
            m = row["data"].decode("utf-8")
            if m == "unknown":
                continue
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
