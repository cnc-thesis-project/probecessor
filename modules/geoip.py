import modules.module


class GeoipModule(modules.module.Module):
    def __init__(self):
        super().__init__("geoip")


    def add_data(row):
        if row["type"] != "info":
            return
        self.country, self.asn, self.as_desc = probe_map[port][m][0]["data"].decode().split("\t")
