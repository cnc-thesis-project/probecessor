import codecs
from datetime import timezone
from asn1crypto import x509
import modules.port


class TlsPort(modules.port.Port):
    def __init__(self, port_num, app_port):
        super().__init__("tls", port_num)
        self.app_port = app_port


    def populate(rows):
        data = {}
        for row in rows:
            if row["type"] == "certificate":
                cert_der = row["data"]
                cert = x509.Certificate.load(cert_der)
                #print("Issuer:", cert.issuer.human_friendly)
                data["subject"] = cert.subject.human_friendly
                data["issuer"] = cert.issuer.human_friendly
                data["sign_alg"] = cert.signature_algo
                data["hash_alg"] = cert.hash_algo
                data["key_size"] = cert.public_key.bit_size
                data["key_sha1"] = codecs.encode(cert.public_key.sha1, "hex").decode()
                #data["issued"] = 1; print(dir(cert))
                data["self_issued"] = cert.self_issued
                data["self_signed"] = cert.self_signed
                #print(cert.is_valid_domain_ip())
                data["valid_domains"] = cert.valid_domains
                data["valid_ips"] = cert.valid_ips
                data["not_before"] = int(cert.not_valid_before.replace(tzinfo=timezone.utc).timestamp())
                data["not_after"] = int(cert.not_valid_after.replace(tzinfo=timezone.utc).timestamp())
                data["valid_period"] = data["not_after"] - data["not_before"]
                #print("Common name:", cn)
                #print("Date issued:", cert.not_valid_before)
            elif row["type"] == "jarm":
                data["jarm"] = row["data"].decode().strip("\x00")
                #print("JARM:", jarm)
        self.data = data


    def to_dict(self):
        return self.data
