import joblib
fp_hosts = {}

def store_fingerprints(fp_out, data):
    print(len(data))
    for host in data.values():
        print(host)
    print("you suck")


def load_fingerprints(fp_path):
    global fp_hosts
    fp_hosts = joblib.load(fp_path)


# Returns the fingerprint match. If none match, return None.
def match(host):
    return
