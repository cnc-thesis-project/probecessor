def run(rows, index_map):
    for row in rows:
        parts = row[index_map["data"]].split(b".")
        tld = parts[len(parts)-1]
        print("TLD:", tld)
