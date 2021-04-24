import codecs
from datetime import datetime
from datetime import timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from OpenSSL import crypto
import modules.module


class TlsPort(modules.port.Port):
    def __init__(self, port):
        super().__init__("tls", port)
        self.data = {}


    def add_data(self, row):
        if row["type"] == "certificate":
            cert_der = row["data"]
            cert = x509.load_der_x509_certificate(cert_der)
            # use openssl to parse subject/issuer since cryptography lib may throw unavoidable exceptions
            openssl_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
            subject = openssl_cert.get_subject().get_components()
            issuer = openssl_cert.get_issuer().get_components()
            self.data["subject"] = b"".join(b"/" + name + b"=" + value for name, value in subject)
            self.data["issuer"] = b"".join(b"/" + name + b"=" + value for name, value in issuer)
            if cert.signature_algorithm_oid:
                self.data["sign_alg"] = cert.signature_algorithm_oid._name
            if cert.signature_hash_algorithm:
                self.data["hash_alg"] = cert.signature_hash_algorithm.name
            if cert.public_key().__class__.__name__ == "_Ed25519PublicKey":
                self.data["key_size"] = 256
            else:
                self.data["key_size"] = cert.public_key().key_size
            self.data["key_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
            self.data["self_issued"] = self.data["subject"] == self.data["issuer"]
            try:
                authority_key_identifier = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
                if authority_key_identifier:
                    authority_key_identifier = authority_key_identifier.key_identifier
                key_identifier = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
                if key_identifier:
                    key_identifier = key_identifier.digest
                self_signed = "no"
                if self.data["self_issued"]:
                    if key_identifier:
                        if not authority_key_identifier or authority_key_identifier == key_identifier:
                            self_signed = "maybe"
                    else:
                        self_signed = "maybe"
                self.data["self_signed"] = self_signed
            except x509.extensions.ExtensionNotFound:
                self.data["self_signed"] = "no"
                pass
            #print(cert.is_valid_domain_ip())
            try:
                alternative = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                self.data["valid_domains"] = alternative.value.get_values_for_type(x509.DNSName)
                self.data["valid_ips"] = list(map(str, alternative.value.get_values_for_type(x509.IPAddress)))
            except x509.extensions.ExtensionNotFound:
                pass
            self.data["not_before"] = int(cert.not_valid_before.replace(tzinfo=timezone.utc).timestamp())
            self.data["not_after"] = int(cert.not_valid_after.replace(tzinfo=timezone.utc).timestamp())
            self.data["valid_period"] = self.data["not_after"] - self.data["not_before"]
            self.data["is_valid"] = self.data["not_before"] <= row["probe_time"] <= self.data["not_after"]
            #print("Common name:", cn)
            #print("Date issued:", cert.not_valid_before)
        elif row["type"] == "jarm":
            self.data["jarm"] = row["data"].decode()
            #print("JARM:", jarm)


    def get_property(self, name):
        return self.data.get(name)

    def get_properties(self):
        return self.data.items()

    def has_property(self, name):
        return name in self.data

    def print_data(self, indent=0):
        print(indent*" " + "TLS:")
        for key, value in self.data.items():
            print((indent+2)*" " + "{}: {}".format(key, value))
