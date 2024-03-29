import modules.port
import modules.label

# Represents a network host.
class Host():
    def __init__(self, ip, uuid):
        self.ip = ip
        self.ports = {}
        self.labels = []
        self.geoip = None
        self.rdns = None
        self.tcp = None
        self.uuid = uuid


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
        return modules.label.Label.to_str(self.labels, delimiter)


    def get_port_label(self, port, include_unspecified_port=True):
        # return all labels assosiated with the port
        # if include_unspecified_port is true, it will include labels that has port number set to None
        port_labels = []
        for label in self.labels:
            if label.port == port or (include_unspecified_port and not label.port):
                port_labels.append(label)
        return port_labels


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
