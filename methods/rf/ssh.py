def add_data(ssh_port):
    pass


def train():
    pass


def set_model(model):
    pass


def convert(ssh_port):
    features = {}

    for at in _algo_map.keys():
        algos = ssh_port.get_property("ciphers:" + at)
        if algos:
            i = 0
            for algo in _algo_map.get(at, []):
                if algo in algos:
                    features["ssh:" + at + ":" + algo + ":" + str(ssh_port.port)] = i + 1
                    i += 1

    return features


_kex_algorithms = [
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
]


_server_host_key_algorithms = [
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ssh-ed25519",
]


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


_algo_map = {
    "kex_algorithms": _kex_algorithms,
    "server_host_key_algorithms": _server_host_key_algorithms,
    "encryption_algorithms_client_to_server": _encryption_algorithms,
    "encryption_algorithms_server_to_client": _encryption_algorithms,
    "mac_algorithms_client_to_server": _mac_algorithms,
    "mac_algorithms_server_to_client": _mac_algorithms,
    "compression_algorithms_client_to_server": _compression_algorithms,
    "compression_algorithms_server_to_client": _compression_algorithms,
}
