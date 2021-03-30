import codecs
from datetime import datetime
from datetime import timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import modules.module


class TlsPort(modules.module.Module):
    def __init__(self):
        super().__init__("tls")
        self.data = {}

    def add_data(self, row):
        if row["type"] == "certificate":
            cert_der = row["data"]
            cert = x509.load_der_x509_certificate(cert_der)
            #print("Issuer:", cert.issuer.human_friendly)
            self.data["subject"] = cert.subject.rfc4514_string()
            self.data["issuer"] = cert.issuer.rfc4514_string()
            self.data["sign_alg"] = cert.signature_algorithm_oid._name
            self.data["hash_alg"] = cert.signature_hash_algorithm.name
            self.data["key_size"] = cert.public_key().key_size
            self.data["key_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
            #self.data["issued"] = 1; print(dir(cert))
            self.data["self_issued"] = cert.subject == cert.issuer
            try:
                authority_key_identifier = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
                if authority_key_identifier:
                    authority_key_identifier = authority_key_identifier.key_identifier
                key_identifier = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
                self_signed = "no"
                if self.data["self_issued"]:
                    if key_identifier:
                        if not authority_key_identifier or authority_key_identifier == key_identifier:
                            self_signed = "maybe"
                    else:
                        self_signed = "maybe"
                self.data["self_signed"] = self_signed
            except x509.extensions.ExtensionNotFound:
                pass
            #print(cert.is_valid_domain_ip())
            try:
                alternative = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                self.data["valid_domains"] = alternative.value.get_values_for_type(x509.DNSName)
                self.data["valid_ips"] = alternative.value.get_values_for_type(x509.IPAddress)
            except x509.extensions.ExtensionNotFound:
                pass
            self.data["not_before"] = int(cert.not_valid_before.replace(tzinfo=timezone.utc).timestamp())
            self.data["not_after"] = int(cert.not_valid_after.replace(tzinfo=timezone.utc).timestamp())
            self.data["valid_period"] = self.data["not_after"] - self.data["not_before"]
            self.data["is_valid"] = self.data["not_before"] <= datetime.utcnow().replace(tzinfo=timezone.utc).timestamp() <= self.data["not_after"]
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
        print(indent*" " + "TLS:")
        for key, value in self.data.items():
            print((indent+2)*" " + "{}: {}".format(key, value))
