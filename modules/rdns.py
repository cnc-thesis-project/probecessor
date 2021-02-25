def run(rows):
    for row in rows:
        parts = row["data"].split(b".")
        tld = parts[len(parts)-1]
        print("TLD:", tld)
