import re


_default_ports = {
    "ftp": [21],
    "pop3": [110, 995],
    "imap": [143, 993],
    "smtp": [25, 587, 465],
    "http": [80, 443],
    "ssh": [22],
    "xmpp": [5222],
}


def is_default_port(port):
    if port.type == "unknown":
        return True
    ret = port.port not in _default_ports[port.type]
    return ret


def _handle_ftp(response):
    p = re.compile(b"^(5[30]0[ -].+|220[ -])")
    if p.match(response):
        lrep = response.lower()
        if b"ftp" in lrep:
            return True
        if b"filezilla" in lrep:
            return True


def _handle_pop3(response):
    return response.startswith(b"-ERR") or response.startswith(b"+OK")


def _handle_imap(response):
    return response.startswith(b"* OK")


def _handle_xmpp(response):
    ret = b"<stream:stream" in response and b"jabber" in response
    if ret:
        print("xmpp ^_^")
    return ret


_handlers = {
    "ftp": _handle_ftp,
    "pop3": _handle_pop3,
    "imap": _handle_imap,
    "xmpp": _handle_xmpp,
}


def identify_protocol(response):
    for proto, handler in _handlers.items():
        if handler(response):
            return proto

    return None
