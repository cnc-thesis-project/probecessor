import sys
import sqlite3
import modules

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: probecessor [database file]")
        sys.exit(1)

    try:
        dbh = sqlite3.connect(sys.argv[1])
    except:
        print("error: Failed opening database '{}'.".format(sys.argv[1]))
        sys.exit(1)

    c1 = dbh.cursor()

    c1.execute("SELECT DISTINCT ip, port FROM Probe;")

    while(True):
        ip_row = c1.fetchone()
        if not ip_row:
            break
        ip = ip_row[0]
        port = ip_row[1]
        print("Handling host {}:{}".format(ip, port))

        for m in modules.modules.keys():
            print("Examining {}".format(m))
            c2 = dbh.cursor()
            c2.execute("SELECT * FROM Probe WHERE ip = ? AND port = ? AND name = ?", (ip,port,m,))

            rows = c2.fetchall()
            if not rows:
                break

            mod = modules.modules.get(m)
            if not mod:
                print("Processor module '{}' does not exist".format(m))
                break
            mod.run(rows)

    dbh.close()
