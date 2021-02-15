from email.parser import BytesParser
from lxml import html
from lxml.etree import ParserError


def tag_recursive(element, depth=-1):
    tag_str = "<%s>" % element.tag

    for child in element:
        tag_str += tag_recursive(child)

    tag_str += "</%s>" % element.tag

    return tag_str


def run(row):
    print("HTTP module handling probe")

    if not row[4].startswith(b"HTTP/"):
        print("error: Not a HTTP response")
        return

    try:
        # split in headers and content
        raw_headers, raw_html = row[4].split(b"\r\n\r\n", 1)
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

    # parse html
    try:
        tree = html.fromstring(raw_html)
    except ParserError as e:
        print("error:", e)
        return

    tag_tree = tag_recursive(tree)

    print(protocol, version, status_code, status_text)
    print("Headers:", ", ".join(headers.keys()))
    print("Server:", server)
    print("Date:", date)
    print("DOM tree:", tag_tree)

    #for element in tree.iter():
    #    print(depth(element))

    print()
