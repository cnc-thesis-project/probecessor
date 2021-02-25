from email.parser import BytesParser
from lxml import html
from lxml.etree import ParserError, Comment

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
        chunk_size, chunk = chunks.split(b"\r\n", 1)
        chunk_size = int(chunk_size, 16)

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
    print("Request:", row["type"])

    if row is None:
        return

    if not row["data"].startswith(b"HTTP/"):
        print("error: Not a HTTP response")
        return

    try:
        # split in headers and content
        raw_headers, content = row["data"].split(b"\r\n\r\n", 1)
        request_line, headers_alone = raw_headers.split(b"\r\n", 1)
    except ValueError as e:
        print("error:", e)
        return

    # parse first line
    protocol, status_code, status_text = request_line.split(b" ", 2)
    protocol, version = protocol.split(b"/", 1)

    # get headers
    headers = BytesParser().parsebytes(headers_alone)

    server = headers.get("Server", None)
    date = headers.get("Date", None)
    content_type = headers.get("Content-Type", None)
    transfer_encoding = list(map(lambda s: s.strip(), headers.get("Transfer-Encoding", "").split(",")))

    if "chunked" in transfer_encoding:
        # the content is chunked and needs to be merged
        content = merge_chunks(content)

    # parse html
    tag_tree = None
    try:
        tree = html.fromstring(content)
        tag_tree = tag_recursive(tree)
    except ParserError as e:
        print("error:", e)

    print(protocol, version, status_code, status_text)
    print("Headers:", ", ".join(headers.keys()))
    print("Server:", server)
    print("Date:", date)
    print("Content-Type:", content_type)
    print("Transfer-Encoding:", transfer_encoding)
    print("Content-Length (in db):", len(content))
    print("DOM tree:", tag_tree)

    return

def run(rows):
    print("HTTP module handling probe")

    for row in rows:
        print(row["type"])

    for probe_type in probe_types:
        row = get_type(rows, probe_type)
        if row is not None:
            process_probe(row)
        else:
            print("HTTP Probe type not found:", probe_type)
