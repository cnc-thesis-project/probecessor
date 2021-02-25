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
    dbh.row_factory = sqlite3.Row

    c1 = dbh.cursor()

    c1.execute("SELECT DISTINCT ip, port FROM Probe;")

    while(True):
        ip_row = c1.fetchone()
        if not ip_row:
            break
        ip = ip_row[0]
        port = ip_row[1]
        print("Handling host {}:{}".format(ip, port))


        c2 = dbh.cursor()
        c2.execute("SELECT data FROM Probe WHERE name = 'port' AND type = 'open' AND ip = ? AND port = ?", (ip, port))
        rows = c2.fetchall()
        if len(rows) < 1:
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
            continue

        mod = modules.modules.get(m)
        if not mod:
            print("Processor module '{}' does not exist".format(m))
            continue
        mod.run(rows)

    dbh.close()
