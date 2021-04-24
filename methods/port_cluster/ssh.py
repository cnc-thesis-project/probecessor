from methods.port_cluster.vectors import list_to_order_list, ListOrderVectorizer, construct_vector
from sklearn.cluster import KMeans


_NUM_CLUSTERS = 30

_training_data = []
_cls = None


def add_data(ssh_port):
    _training_data.append(construct_vector(_props_to_vectorizers, ssh_port))


def train():
    global _cls
    _cls = KMeans(n_clusters=_NUM_CLUSTERS)
    _cls.fit(_training_data)
    return _cls


def set_model(model):
    global _cls
    _cls = model


def convert(ssh_port):
    if _cls:
        return {"ssh:{}".format(ssh_port.port): _cls.predict([construct_vector(_props_to_vectorizers, ssh_port)])[0]}
    print("WARNING: NO MODEL FOR SSH")
    return {"ssh:{}".format(ssh_port.port): -1}


_encryption_algorithms = [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
]

_mac_algorithms = [
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
]

_compression_algorithms = [
    "zlib@openssh.com",
    "zlib",
    "none",
]

_props_to_vectorizers = {
    "ciphers:kex_algorithms": ListOrderVectorizer([
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
    ]),
    "ciphers:server_host_key_algorithms": ListOrderVectorizer([
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ssh-ed25519",
    ]),
    "ciphers:encryption_algorithms_client_to_server": ListOrderVectorizer(_encryption_algorithms),
    "ciphers:encryption_algorithms_server_to_client": ListOrderVectorizer(_encryption_algorithms),
    "ciphers:mac_algorithms_client_to_server": ListOrderVectorizer(_mac_algorithms),
    "ciphers:mac_algorithms_server_to_client": ListOrderVectorizer(_mac_algorithms),
    "ciphers:compression_algorithms_client_to_server": ListOrderVectorizer(_compression_algorithms),
    "ciphers:compression_algorithms_server_to_client": ListOrderVectorizer(_compression_algorithms),
}
