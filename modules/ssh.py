import struct

NAME_LIST_LEN_LEN = 4
PACKET_LEN_LEN = 4
PADDING_LEN_LEN = 1
MSG_KEXINIT_LEN = 1
COOKIE_LEN = 16

# Parses an SSH name-list as specified in RFC 4251
def parse_name_list(nl):
    nl_len = struct.unpack(">i", nl[0:NAME_LIST_LEN_LEN])[0]
    return (nl_len, nl[NAME_LIST_LEN_LEN:NAME_LIST_LEN_LEN + nl_len].split(b","))


def parse_string(data):
    print("Server string:", data[0:-2])


def parse_algo_negotiation(data):
    algo_lists = {
        "kex_algorithms": [],
        "server_host_key_algorithms": [],
        "encryption_algorithms_client_to_server": [],
        "encryption_algorithms_server_to_client": [],
        "mac_algorithms_client_to_server": [],
        "mac_algorithms_server_to_client": [],
        "compression_algorithms_client_to_server": [],
        "compression_algorithms_server_to_client": [],
        "languages_client_to_server": [],
        "languages_server_to_client": [],
    }

    algo_lists_start = (
        PACKET_LEN_LEN +
        PADDING_LEN_LEN +
        MSG_KEXINIT_LEN +
        COOKIE_LEN
    )

    current_list_start = algo_lists_start
    for algo_name in algo_lists.keys():
        (algo_list_len, algo_list) = parse_name_list(data[current_list_start:])
        current_list_start += NAME_LIST_LEN_LEN + algo_list_len
        algo_lists[algo_name] = algo_list


    print("Server algorithms:", algo_lists)


def run(rows, index_map):
    for row in rows:
        if row[index_map["type"]] == "string":
            parse_string(row[index_map["data"]])
        elif row[index_map["type"]] == "ciphers":
            parse_algo_negotiation(row[index_map["data"]])
