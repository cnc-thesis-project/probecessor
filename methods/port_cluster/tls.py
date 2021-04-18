def get_data(tls_port):
    data = {}
    data["jarm"] = tls_port.get_property("jarm")
    #data["issuer"] = tls_port.get_property("issuer")

    return data


def match(tls_data1, tls_data2):
    return tls_data1["jarm"] == tls_data2["jarm"] #and tls_data1["issuer"] == tls_data2["issuer"]
