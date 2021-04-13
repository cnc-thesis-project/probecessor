import base64
import numpy
import modules.port
import hashlib
import tlsh
import re
from modules.protocol import identify_protocol

word_reg = re.compile(b"[a-zA-Z0-9-_]{4,}")

class GenericPort(modules.port.Port):
    def __init__(self, port):
        super().__init__("unknown", port)
        self.data_map = {}


    def add_data(self, row):
        data = row["data"]
        if data is None:
            print("NONE DATA FROM", row["type"], row["name"])
        self.type = row["name"]
        if self.type == "unknown":
            self.type = identify_protocol(data)
            self.type = self.type if self.type else "unknown"
        t = row["type"]
        if not self.data_map.get(t):
            self.data_map[t] = []
        self.data_map[t].append(data)


    def _concat_data(self):
        data = b""
        for t in sorted(self.data_map.keys()):
            for d in self.data_map[t]:
                data += d
        return data


    def get_property(self, name):
        data = self._concat_data()
        if name == "data":
            return data
        elif name == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif name == "entropy":
            return entropy(data)
        elif name == "histogram":
            return histogram(data)
        elif name == "tlsh":
            return tlsh.hash(data)
        elif name == "strings":
            return set(word_reg.findall(data))
        return None


    def get_properties(self):
        data = self._concat_data()
        ret = {
            "data": data,
            "sha256": hashlib.sha256(data).hexdigest(),
            "entropy": entropy(data),
            "histogram": histogram(data),
            "tlsh": tlsh.hash(data),
            "strings": set(word_reg.findall(data)),
        }
        return ret.items()


    def has_property(self, name):
        return name in ["data", "sha256", "entropy", "histogram", "tlsh", "strings"]


def entropy(data):
    values, counts = numpy.unique(bytearray(data), return_counts=True)
    norm_counts = counts / counts.sum()
    return -(norm_counts * numpy.log(norm_counts) / numpy.log(2)).sum()


def histogram(data):
    if len(data) == 0:
        return None
    values, counts = numpy.unique(bytearray(data), return_counts=True)
    histogram = [0] * 256
    for i, value in enumerate(values):
        histogram[value] = counts[i] / len(data)
    return histogram
