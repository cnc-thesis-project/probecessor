
# TODO: fix
_labels_to_jarm_hashes = {
    
}


def add_data(mod):
    pass


def train():
    pass


def set_model(model):
    pass


_sign_algs = [
    "ecdsa-with-SHA1",
    "ecdsa-with-SHA256",
    "ecdsa-with-SHA384",
    "md5WithRSAEncryption",
    "sha1WithRSAEncryption",
    "sha256WithRSAEncryption",
    "sha384WithRSAEncryption",
    "sha512WithRSAEncryption",
]


_hash_algs = [
    "md5",
    "sha1",
    "sha256",
    "sha384",
    "sha512",
]


def convert(tls_port):
    ss = -1 if tls_port.get_property("self_signed") == "no" else 1
    ks = tls_port.get_property("key_size")
    try:
        sa = _sign_algs.index(tls_port.get_property("sign_alg")) + 1
    except ValueError:
        sa = -1
    try:
        ha = _hash_algs.index(tls_port.get_property("hash_alg")) + 1
    except ValueError:
        ha = -1

    si = tls_port.get_property("self_issued")
    si = 1 if si else -1

    key_pfx = "tls:{}:".format(tls_port.port)
    ret = {
        key_pfx + "ss": ss,
        key_pfx + "ks": ks,
        key_pfx + "sa": sa,
        key_pfx + "ha": ha,
        key_pfx + "si": si,
    }

    return ret
