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

    c1.execute("SELECT DISTINCT ip FROM Probe")

    while(True):
        ip_row = c1.fetchone()
        if not ip_row:
            break
        ip = ip_row[0]
        print("Handling host {}".format(ip))

        c2 = dbh.cursor()
        c2.execute("SELECT * FROM Probe WHERE ip = ?", (ip,))

        while(True):
            row = c2.fetchone()
            if not row:
                break

            mod = modules.modules.get(row[0])
            if not mod:
                print("Processor module '{}' does not exist".format(row[0]))
                break
            mod.run(row)

    dbh.close()
