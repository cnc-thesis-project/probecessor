import sys
import sqlite3
import modules
import pprint
import tlsh
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeably data probecessor.")
    parser.add_argument("databases", type=str, nargs="+")

    args = parser.parse_args()

    for db_file in args.databases:
        try:
            open(db_file, "r")
            dbh = sqlite3.connect(db_file)
        except:
            print("error: Failed opening database '{}'.".format(sys.argv[1]))
            sys.exit(1)

        dbh.row_factory = sqlite3.Row

        c1 = dbh.cursor()

        c1.execute("SELECT DISTINCT ip, port FROM Probe;")

        fingerprints = {}

        while(True):
            ip_row = c1.fetchone()
            if not ip_row:
                print("no ip row")
                break
            ip = ip_row[0]
            port = ip_row[1]
            print("Handling host {}:{}".format(ip, port))

            c2 = dbh.cursor()
            c2.execute("SELECT data FROM Probe WHERE name = 'port' AND type = 'open' AND ip = ? AND port = ?", (ip, port))
            rows = c2.fetchall()
            if len(rows) < 1 or rows is None:
                print("No rows")
                continue
            row = rows[0]
            m = row["data"].decode("utf-8")
            if m == "unknown":
                print("Unknown protocol")
                continue
            print("Examining {}".format(m))
            c2 = dbh.cursor()
            c2.execute("SELECT * FROM Probe WHERE ip = ? AND port = ? AND name = ?", (ip,port,m,))
            rows = c2.fetchall()

            if not rows or len(rows) == 0:
                print("No rows 2")
                continue

            mod = modules.modules.get(m)
            if not mod:
                print("Processor module '{}' does not exist".format(m))
                continue

            print("Mod:", mod)
            mod_data = mod.run(rows)

            host_fps = fingerprints.get(ip)
            if not host_fps:
                host_fps = {}
                fingerprints[ip] = host_fps
            fingerprints[ip][port] = tlsh.hash(mod_data)

        dbh.close()

        print("+ FINGERPRINTS")
        pprint.pprint(fingerprints)
