import base64
import numpy
import modules.port
import hashlib

class UnknownPort(modules.port.Port):
    def __init__(self, port):
        super().__init__("unknown", port)
        self.data = {}


    def add_data(self, row):
        if row["type"] == "response":
            self.data["response"] = row["data"]
            self.data["sha256"] = hashlib.sha256(row["data"]).hexdigest()
            self.data["entropy"] = entropy(row["data"])

    def get_property(self, name):
        return self.data.get(name)

    def has_property(self, name):
        return name in self.data


def entropy(data):
    value, counts = numpy.unique(bytearray(data), return_counts=True)
    norm_counts = counts / counts.sum()
    return -(norm_counts * numpy.log(norm_counts) / numpy.log(2)).sum()

