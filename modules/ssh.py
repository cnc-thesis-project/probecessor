import struct

def handle_string(data):
    print(data[0:-2])

def handle_ciphers(data):
    print(data)
    print("\n")
    # "constants"
    packet_len_len = 4
    padding_len_len = 1
    kex_kexinit_len = 1
    kex_cookie_len = 16
    name_list_len_len = 4

    kex_list_start = (
        packet_len_len +
        padding_len_len +
        kex_kexinit_len +
        kex_cookie_len
    )

    kex_list_len = struct.unpack(">i", data[kex_list_start:kex_list_start + name_list_len_len])[0]

    kex_list = data[kex_list_start + name_list_len_len:kex_list_start + name_list_len_len + kex_list_len].split(b",")
    print("KEX list:", kex_list)

    cipher_list_start = kex_list_start + name_list_len_len + kex_list_len
    cipher_list_len = struct.unpack(">i", data[cipher_list_start:cipher_list_start + name_list_len_len])[0]
    cipher_list = data[cipher_list_start + name_list_len_len:cipher_list_start + name_list_len_len + cipher_list_len].split(b",")
    print("Cipher list:", cipher_list)

def run(rows, index_map):
    for row in rows:
        if row[index_map["type"]] == "string":
            handle_string(row[index_map["data"]])
        elif row[index_map["type"]] == "ciphers":
            handle_ciphers(row[index_map["data"]])
        else:
            print("UNKNOWN TYPE")
