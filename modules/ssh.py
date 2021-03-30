import struct
from base64 import b64encode
from sshpubkeys import SSHKey
import modules.port


NAME_LIST_LEN_LEN = 4
PACKET_LEN_LEN = 4
PADDING_LEN_LEN = 1
MSG_KEXINIT_LEN = 1
COOKIE_LEN = 16


class SshPort(modules.port.Port):
    def __init__(self, port):
        super().__init__("ssh", port)
        self.data = {}


    def add_data(self, row):
        # TODO: more proper error handling
        if row["type"] == "string":
            self.data["server"] = parse_string(row["data"])
        elif row["type"] == "ciphers":
            algorithms = parse_algo_negotiation(row["data"])
            for key in algorithms:
                self.data["ciphers:{}".format(key)] = algorithms[key]
        elif row["type"] in ["ssh-rsa", "ssh-ecdsa", "ssh-ed25519"]:
            self.data.update(parse_key(row["data"]))


    def get_property(self, name):
        return self.data.get(name)


    def get_properties(self):
        return self.data.items()


    def has_property(self, name):
        return name in self.data


# Parses an SSH name-list as specified in RFC 4251
def parse_name_list(nl):
    nl_len = struct.unpack(">i", nl[0:NAME_LIST_LEN_LEN])[0]
    #print("Have name-list of {} size".format(nl_len))
    return (nl_len, nl[NAME_LIST_LEN_LEN:NAME_LIST_LEN_LEN + nl_len].split(b","))


def parse_string(data):
    #print("Server string:", data[0:-2])
    return data.rstrip(b"\r\n").decode()


def parse_algo_negotiation(data):
    algo_lists_names = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ]

    algo_lists_map = {}

    algo_lists_start = (
        PACKET_LEN_LEN +
        PADDING_LEN_LEN +
        MSG_KEXINIT_LEN +
        COOKIE_LEN
    )

    packet_len = struct.unpack(">i", data[0:4])
    #print("Have SSH packet of length {}".format(packet_len))

    current_list_start = algo_lists_start
    for algo_name in algo_lists_names:
        #print("Handling algo list {}".format(algo_name))
        (algo_list_len, algo_list) = parse_name_list(data[current_list_start:])
        current_list_start += NAME_LIST_LEN_LEN + algo_list_len
        algo_lists_map[algo_name] = list(map(lambda s: s.decode(), algo_list))


    #print("Server algorithms:", algo_lists_map)
    return algo_lists_map

def parse_key(data):
    key = {}

    ssh_key = SSHKey(data.decode())
    if ssh_key.bits is not None:
        name = ssh_key.key_type.decode()
        key[name + ":size"] = ssh_key.bits
        key[name + ":sha256"] = ssh_key.hash_sha256()

    return key
