import sys
import sqlite3

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: probecessor [database file]")
        sys.exit(1)

    try:
        dbh = sqlite3.connect(sys.argv[1])
    except:
        print("error: Failed opening database '{}'.".format(sys.argv[1]))
        sys.exit(1)

    c = dbh.cursor()

    c.execute("SELECT DISTINCT ip FROM Probe")

    while(True):
        ip = c.fetchone()
        if not ip:
            break
        print(ip)

    dbh.close()
