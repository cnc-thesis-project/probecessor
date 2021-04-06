import modules.http
import modules.ssh
import modules.rdns
import modules.geoip
import modules.generic
import modules.tls


_ip_modules = {
    "rdns": modules.rdns.RdnsModule,
    "geoip": modules.geoip.GeoipModule,
}

_ports = {
    "http": modules.http.HttpPort,
    "ssh": modules.ssh.SshPort,
    "tls": modules.tls.TlsPort,
    "unknown": modules.generic.GenericPort,
}


def get_module(name, *args, **kwargs):
    mod_class = _ip_modules.get(name)
    if not mod_class:
        print("no mod for name {}".format(name))
        return None
    return mod_class(*args, **kwargs)


def get_port(port_type, *args, **kwargs):
    port_class = _ports.get(port_type, modules.generic.GenericPort)
    return port_class(*args, **kwargs)
