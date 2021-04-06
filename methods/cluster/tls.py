def get_data(tls_port):
    print("TLS GET DATA")
    data = {}
    data["issuer"] = tls_port.get_property("issuer")

    return data


def match(tls_data1, tls_data2):
    print("TLS MATCH")
    return tls_data1["issuer"] == tls_data2["issuer"]
