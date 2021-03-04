from pprint import pprint

rules = []

def add(host_data):
    print("Running rule based fingerprinter")
    for data in host_data.values():
        # TODO: fix
        if data["module"] != "http":
            continue

        rule = ":".join(data["features"])
        rules.append(rule)


def process():
    print("rules:")
    pprint(rules)
