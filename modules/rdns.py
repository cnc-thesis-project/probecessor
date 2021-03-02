def run(rows):
    if len(rows) < 1:
        return b""

    row = rows[0]
    parts = row["data"].split(b".")
    tld = parts[len(parts)-1]

    return tld
