import modules.module


class GeoipModule(modules.module.Module):
    def __init__(self):
        super().__init__("geoip")
        self.data = {}


    def add_data(self, row):
        if row["type"] != "info":
            return
        self.data["country"], self.data["asn"], self.data["as_desc"] = row["data"].decode().split("\t")


    def print_data(self, indent=0):
        print(indent*" " + "Country: {}, ASN: {} ({})".format(self.data["country"], self.data["asn"], self.data["as_desc"]))


    def get_property(self, name):
        return self.data.get(name)


    # Should return an iterable of tuples with key-value
    def get_properties(self):
        return self.data.items()


    def has_property(self, name):
        return name in self.data
