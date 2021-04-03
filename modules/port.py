import modules.module

# Represents a port on a network host.
class Port(modules.module.Module):
    tls = None

    def __init__(self, port_type, port_num):
        super().__init__("port")
        # The type of port, e.g. "http".
        self.type = port_type
        self.port = port_num


    def print_data(self, indent=0):
        print("{}Port: {} ({})".format(" " * indent, self.port, self.type))
        if self.tls:
            self.tls.print_data(indent=indent + 2)
        for key, value in self.get_properties():
            print("{}Key: {}, Value: {}".format(" " * (indent + 2), key, value))
