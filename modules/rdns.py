import modules.module


class RdnsModule(modules.module.Module):
    def __init__(self):
        super().__init__("rdns")
        self.rdns = None


    def add_data(self, row):
        self.rdns = row["data"].decode()


    def print_data(self, indent=0):
        print(indent*" " + "Reverse DNS: ", self.rdns)


    def get_property(self, name):
        if name == "rdns":
            return self.rdns
        return None


    # Should return an iterable of tuples with key-value
    def get_properties(self):
        return [self.rdns]


    def has_property(self, name):
        return name == "rdns"
