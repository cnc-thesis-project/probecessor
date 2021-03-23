import modules.port
import modules.label

# Represents a network host.
class Host():
    def __init__(self, ip):
        self.ip = ip
        self.ports = {}
        self.labels = []
        self.geoip = None
        self.rdns = None


    def insert_port(self, port):
        if not isinstance(port, modules.port.Port):
            raise Exception

        self.ports[port.port] = port


    def is_open(self, port_num):
        return port_num in self.ports


    def add_label(self, mwdb_id, host_type, host_port):
        self.labels.append(modules.label.Label(mwdb_id, host_type, host_port))


    def filter_labels(self):
        # remove labels where the host port is not open
        count = len(self.labels)
        self.labels[:] = [label for label in self.labels if label.port in self.ports or label.port is None]
        # return true if all labels got removed
        # if there were no labels from beginning, always return false
        return len(self.labels) == 0 and count != len(self.labels)


    def label_str(self, delimiter="/"):
        # convert labels into a string like: mirai/Dridex/QakBot
        label_set = set(map(lambda l: l.label, self.labels))
        if len(label_set) == 0:
            label_set.add("unlabeled")
        return delimiter.join(sorted(label_set))


    def print_data(self):
        print("Host: {} (labels: {}, open ports: {})".format(self.ip, self.label_str(), len(self.ports)))
        if self.geoip:
            self.geoip.print_data(indent=2)
        if self.rdns:
            self.rdns.print_data(indent=2)
        for port in self.ports.values():
            port.print_data(indent=2)
        print("  Labels:")
        for label in self.labels:
            print("    Label: {}, port: {}, Mwdb id: {}".format(label.label, label.port, label.mwdb_id))


    def responsive_ports(self):
        # ports that gave any kind of response
        # TODO: include tls ports, even if the application layer didn't respond tls gives some information
        ports = []
        for port in self.ports.values():
            if port.type == "unknown" and len(port.data.get("response", "")) == 0:
                continue
            ports.append(port)
        return ports
