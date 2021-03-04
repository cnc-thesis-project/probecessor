import methods.rules
import methods.learn


methods = {
    "rules": methods.rules,
    "learn": methods.learn,
}


vector_descs = {
    "http": {
        "lists": {
            "get_root_header_keys": {
                "Server": 0,
                "Content-Type": 1,
                "Date": 2,
                "Content-Length": 3,
                "Connection": 4,
            },
            "delete_root_header_keys": {
                "Server": 0,
                "Content-Type": 1,
                "Date": 2,
                "Content-Length": 3,
                "Connection": 4,
            },
        },
        "vector": [
            "get_root_header_keys",
            "delete_root_header_keys",
            "get_root_response_code",
            "delete_root_response_code",
        ],
    },
    "ssh": {
        "lists": {},
        "vector": {},
    }
}


def list_to_order_list(li, desc):
    res = [-1 for i in range(len(desc.values()))]
    for i in range(len(li)):
        if li[i] in desc.keys():
            res[desc[li[i]]] = i
    return res
