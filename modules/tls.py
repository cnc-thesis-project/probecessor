from asn1crypto import x509

def run(rows, index_map):
    for row in rows:
        if row[index_map["type"]] == "certificate":
            cert_der = row[index_map["data"]]
            cert = x509.Certificate.load(cert_der)
            print("Issuer:", cert.issuer.human_friendly)
            print("Common name:", cert.subject.human_friendly)
            print("Date issued:", cert.not_valid_before)
        elif row[index_map["type"]] == "jarm":
            jarm = row[index_map["data"]]
            print("JARM:", jarm)
