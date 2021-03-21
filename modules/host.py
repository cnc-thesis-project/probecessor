import modules.port

# Represents a network host.
class Host():
    def __init__(self, ip):
        self.ip = ip
        self.ports = {}
        self.labels = set()


    def insert_port(self, port):
        if not isinstance(port, modules.port.Port):
            raise Exception

        self.ports[port.port] = port


    def is_open(self, port_num):
        return port_num in self.ports


    def add_label(self, label):
        self.labels.add(label)

    def label_str(self, delimiter="/"):
        return '/'.join(sorted(self.labels))

    def print_data(self):
        print("Host: {} (labels: {}, open ports: {})".format(self.ip, self.label_str(), len(self.ports)))
        for port in self.ports.values():
            port.print_data(indent=2)
