from methods.cluster.vectors import list_to_order_list, ListOrderVectorizer, construct_vector
from methods.cluster.utils import cluster_module_data, match_module_clusters


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


def get_data(ssh_port):
    data = {}

    data["vector"] = construct_vector(_props_to_vectorizers, ssh_port)

    return data


match = match_module_clusters
