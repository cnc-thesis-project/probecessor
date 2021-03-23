import codecs
from datetime import timezone
from asn1crypto import x509
import modules.module


class TlsPort(modules.module.Module):
    def __init__(self):
        super().__init__("tls")
        self.data = {}


    def add_data(self, row):
        if row["type"] == "certificate":
            cert_der = row["data"]
            cert = x509.Certificate.load(cert_der)
            #print("Issuer:", cert.issuer.human_friendly)
            self.data["subject"] = cert.subject.human_friendly
            self.data["issuer"] = cert.issuer.human_friendly
            self.data["sign_alg"] = cert.signature_algo
            self.data["hash_alg"] = cert.hash_algo
            self.data["key_size"] = cert.public_key.bit_size
            self.data["key_sha1"] = codecs.encode(cert.public_key.sha1, "hex").decode()
            #self.data["issued"] = 1; print(dir(cert))
            self.data["self_issued"] = cert.self_issued
            self.data["self_signed"] = cert.self_signed
            #print(cert.is_valid_domain_ip())
            self.data["valid_domains"] = cert.valid_domains
            self.data["valid_ips"] = cert.valid_ips
            self.data["not_before"] = int(cert.not_valid_before.replace(tzinfo=timezone.utc).timestamp())
            self.data["not_after"] = int(cert.not_valid_after.replace(tzinfo=timezone.utc).timestamp())
            self.data["valid_period"] = self.data["not_after"] - self.data["not_before"]
            #print("Common name:", cn)
            #print("Date issued:", cert.not_valid_before)
        elif row["type"] == "jarm":
            self.data["jarm"] = row["data"].decode()
            #print("JARM:", jarm)


    def get_property(self, name):
        return self.data.get(name)


    def has_property(self, name):
        return name in self.data

    def print_data(self, indent=0):
        keys = ["subject", "issuer", "sign_alg", "hash_alg", "key_size", "key_sha1", "self_issued", "self_signed", "valid_domains", "valid_ips", "not_before", "not_after", "valid_period", "jarm"]
        for key in keys:
            print(indent*" {}: {}".format(key, self.data[key]))
