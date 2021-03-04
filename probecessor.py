import sys
import sqlite3
import pprint
import tlsh
import argparse

import methods
import modules


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The probeably data probecessor.")
    parser.add_argument("--method", help="The fingerprinting method to use.", choices=["rules", "learn"], default="learn")
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

    method = methods.methods[args.method]

    for ip in data.keys():
        method.add(data[ip])

    dbh.close()

    method.process()
