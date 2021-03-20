from email.parser import BytesParser
from lxml import html
from lxml.etree import ParserError, Comment
import modules.port


class HttpPort(modules.port.Port):
    def __init__(self, port):
        super().__init__("http", port)
        self.data = {}


    def add_data(self, row):
        if row["type"] not in probe_types:
            return

        self.data.update(process_probe(row))

        # timing related
        # TODO: yuki, pliz figz :O
        """
        response_time = get_type(rows, probe_type + "_time")["data"].split(b" ")
        self.data["{}:response_start".format(probe_type)] = float(response_time[0])
        self.data["{}:response_end".format(probe_type)] = float(response_time[0])
        """


    def get_property(self, name):
        return self.data.get(name)


    def has_property(self, name):
        return name in self.data


class HttpResponse():
    def __init__(self, name):
        self.name = name


probe_types = [
    "get_root",
    "head_root",
    "very_simple_get",
    "not_exist",
    "invalid_version",
    "invalid_protocol",
    "long_path",
    "get_favicon",
    "get_robots",
    "delete_root"
]

def merge_chunks(chunks):
    content = b""

    while len(chunks) > 0:
        try:
            chunk_size, chunk = chunks.split(b"\r\n", 1)
            chunk_size = int(chunk_size, 16)
        except ValueError:
            # HTTP is fucked up
            chunk_size = len(chunks)
            chunk = chunks

        chunk = chunk[0:chunk_size]
        content += chunk

        chunks = chunk[chunk_size:]
        if chunks.startswith(b"\r\n"):
            chunks = chunks[2:]

    return content

def tag_recursive(element, depth=-1):
    tag = element.tag
    if tag is Comment:
        tag = "!----"

    tag_str = "<%s>" % tag

    for child in element:
        tag_str += tag_recursive(child)

    if tag is not Comment:
        tag_str += "</%s>" % tag

    return tag_str

def get_type(rows, probe_type):
    for row in rows:
        if row["type"] == probe_type:
            return row
    return None

def process_probe(row):
    if not row["data"].startswith(b"HTTP/"):
        return {} # TODO: do some kind of content analysis

    #print(row["data"], "\n")
    response = row["data"].replace(b"\r\n\r\n", b"\n\n", 1)

    try:
        # split in headers and content
        raw_headers, content = response.split(b"\n\n", 1)
        request_line, headers_alone = raw_headers.split(b"\r\n", 1)
    except ValueError as e:
        return {}

    # parse first line
    try:
        protocol, status_code, status_text, version = None, None, None, None
        protocol, status_code, status_text = request_line.split(b" ", 2)
        protocol, version = protocol.split(b"/", 1)
    except ValueError as e:
        pass

    # get headers
    headers = BytesParser().parsebytes(headers_alone)

    server = headers.get("Server", "")
    date = headers.get("Date", "")
    content_type = headers.get("Content-Type", "")
    transfer_encoding = list(map(lambda s: s.strip(), headers.get("Transfer-Encoding", "").split(",")))

    if "chunked" in transfer_encoding:
        # the content is chunked and needs to be merged
        content = merge_chunks(content)

    # parse html
    tag_tree = ""
    try:
        tree = html.fromstring(content)
        tag_tree = tag_recursive(tree)
    except ParserError as e:
        pass

    data = {}

    probe_type = row["type"]

    try:
		# TODO: IIS server is dick and may return decimals in status_code :shrug:
        data["{}:status_code".format(probe_type)] = float(status_code)
    except TypeError:
        data["{}:status_code".format(probe_type)] = None
    try:
        data["{}:status_text".format(probe_type)] = status_text.decode()
    except AttributeError:
        data["{}:status_text".format(probe_type)] = None
    try:
        data["{}:header_keys".format(probe_type)] = headers.keys()
    except TypeError:
        data["{}:header_keys".format(probe_type)] = None

    for header in headers:
        data["{}:header:{}".format(probe_type, header)] = headers[header]
    data["{}:dom_tree".format(probe_type)] = tag_tree

    return data

def run(rows):
    data = {}

    for probe_type in probe_types:
        row = get_type(rows, probe_type)
        if row is not None:
            data.update(process_probe(row))

            # timing related
            response_time = get_type(rows, probe_type + "_time")["data"].split(b" ")
            data["{}:response_start".format(probe_type)] = float(response_time[0])
            data["{}:response_end".format(probe_type)] = float(response_time[0])

    return data
