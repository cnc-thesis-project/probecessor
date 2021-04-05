import re


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


_handlers = {
    "ftp": _handle_ftp,
    "pop3": _handle_pop3,
    "imap": _handle_imap,
}


def identify_protocol(response):
    for proto, handler in _handlers.items():
        if handler(response):
            return proto

    return None
