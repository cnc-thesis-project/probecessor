import sys
import json


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: port_stats.py [masscan json file]")
        sys.exit(1)

    try:
        f = open(sys.argv[1])
    except:
        print("failed to open file '{}'".format(sys.argv[1]))
        sys.exit(1)

    try:
        data = json.load(f)
    except:
        print("failed to load json")
        sys.exit(1)


    ports_present = set()
    for o in data:
        for port in o["ports"]:
            if port["status"] == "open":
                ports_present.add(port["port"])

    print("{} different ports open in the scan file".format(len(ports_present)))

