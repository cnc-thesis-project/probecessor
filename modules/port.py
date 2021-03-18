import modules.module

# Represents a port on a network host.
class Port(modules.module.Module):
    def __init__(self, port_type, port_num):
        super().__init__("port")
        # The type of port, e.g. "http".
        self.type = port_type
        self.port = port_num
