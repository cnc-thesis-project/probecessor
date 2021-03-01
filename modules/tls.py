from asn1crypto import x509

def run(rows):
    for row in rows:
        if row["type"] == "certificate":
            cert_der = row["data"]
            cert = x509.Certificate.load(cert_der)
            print("Issuer:", cert.issuer.human_friendly)
            cn = cert.subject.human_friendly
            print("Common name:", cn)
            print("Date issued:", cert.not_valid_before)
        elif row["type"] == "jarm":
            jarm = row["data"]
            print("JARM:", jarm)
    return (jarm + cn).encode()
