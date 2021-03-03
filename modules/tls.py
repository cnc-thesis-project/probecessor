from asn1crypto import x509

def run(rows):
    data = {}
    for row in rows:
        if row["type"] == "certificate":
            cert_der = row["data"]
            cert = x509.Certificate.load(cert_der)
            #print("Issuer:", cert.issuer.human_friendly)
            data["cn"] = cert.subject.human_friendly
            data["issuer"] = cert.issuer.human_friendly
            data["sign_alg"] = cert.signature_algo
            data["hash_alg"] = cert.hash_algo
            data["key_size"] = cert.public_key.bit_size
            #data["issued"] = 1; print(dir(cert))
            data["self_issued"] = cert.self_issued
            data["self_signed"] = cert.self_signed
            print(type(cert.self_signed))
            #print("Common name:", cn)
            #print("Date issued:", cert.not_valid_before)
        elif row["type"] == "jarm":
            data["jarm"] = row["data"].decode().strip("\x00")
            #print("JARM:", jarm)
    return data
