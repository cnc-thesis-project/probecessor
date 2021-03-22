import modules.module


class RdnsModule(modules.module.Module):
    def __init__(self):
        super().__init__("rdns")
        self.data = {}


    def add_data(row):
        row = rows[0]
        parts = row["data"].split(b".")
        tld = parts[len(parts)-1]

        data["tld"] = tld
