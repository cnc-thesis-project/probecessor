import base64
import numpy

def entropy(data):
    value, counts = numpy.unique(bytearray(data), return_counts=True)
    norm_counts = counts / counts.sum()
    return -(norm_counts * numpy.log(norm_counts) / numpy.log(2)).sum()

def run(rows):
    data = {}

    data["response"] = base64.b64encode(rows[0]["data"]).decode()
    data["entropy"] = entropy(rows[0]["data"])

    return data
